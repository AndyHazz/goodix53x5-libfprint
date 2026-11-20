/*
 * Goodix 53x5 driver for libfprint — Scan flow (FDT finger detection and capture)
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/transport.h"
#include "device/commands.h"
#include "device/calibration.h"
#include "device/image.h"
#include "device/base.h"
#include "device/scan.h"
#include "device/session.h"

#include <string.h>

typedef enum {
  GOODIX_SCAN_COORD_ENSURE_REFERENCE = 0,
  GOODIX_SCAN_COORD_ENSURE_REFERENCE_DONE,
  GOODIX_SCAN_COORD_POWER_ON,
  GOODIX_SCAN_COORD_ARM_DOWN,
  GOODIX_SCAN_COORD_WAIT_EVENT,
  GOODIX_SCAN_COORD_DISPATCH_EVENT,
  GOODIX_SCAN_COORD_DOWN_MANUAL,
  GOODIX_SCAN_COORD_DOWN_VALIDATE,
  GOODIX_SCAN_COORD_CAPTURE,
  GOODIX_SCAN_COORD_ARM_UP,
  GOODIX_SCAN_COORD_ARM_UP_DONE,
  GOODIX_SCAN_COORD_RECOVERY_ARM_UP,
  GOODIX_SCAN_COORD_RECOVERY_ARM_UP_DONE,
  GOODIX_SCAN_COORD_REFRESH,
  GOODIX_SCAN_COORD_REFRESH_DONE,
  GOODIX_SCAN_COORD_UP_HEALTH,
  GOODIX_SCAN_COORD_REARM_DOWN,
  GOODIX_SCAN_COORD_REARM_DOWN_DONE,
  GOODIX_SCAN_COORD_RESTORE_CONFIG,
  GOODIX_SCAN_COORD_ESD,
  GOODIX_SCAN_COORD_ESD_DONE,
  GOODIX_SCAN_COORD_DEACTIVATE_EC,
  GOODIX_SCAN_COORD_DEACTIVATE_EC_DONE,
  GOODIX_SCAN_COORD_WAIT_CPU,
  GOODIX_SCAN_COORD_CYCLE_SETTLED,
  GOODIX_SCAN_COORD_CLEANUP_JOIN,
  GOODIX_SCAN_COORD_CLEANUP_HEALTH,
  GOODIX_SCAN_COORD_CLEANUP_SLEEP,
  GOODIX_SCAN_COORD_CLEANUP_DONE,
  GOODIX_SCAN_COORD_NUM_STATES,
} GoodixScanCoordinatorState;

typedef struct
{
  FpiSsm                        *parent_ssm;
  FpiSsm                        *ssm;
  GoodixScanCaptureReadyCallback capture_ready;
  GoodixScanCycleSettledCallback cycle_settled;
  gpointer                       user_data;
  GCancellable                  *action_cancel;
  gulong                         action_cancel_id;
  GoodixFdtEventType             event_type;
  GoodixProfile9FdtRefreshReason refresh_reason;
  GoodixScanDisposition          disposition;
  GError                        *stop_error;
  guint16                        prior_down[GOODIX_PROFILE9_FDT_AREA_COUNT];
  gboolean                       waiting_event;
  gboolean                       dispatching;
  gboolean                       stop_requested;
  gboolean                       cpu_done;
  gboolean                       cpu_outstanding;
  gboolean                       refresh_deferred;
  gboolean                       cycle_active;
  gboolean                       recovering_generation;
  gboolean                       release_settled;
  gboolean                       idle;
  /* The action already received its outcome; the rest is maintenance. */
  gboolean                       detached;
  FpiSsm                        *health_parent;
  GSource                       *health_timer;
  FpDevice                      *service_device;
} GoodixScanCoordinatorData;

static void goodix_scan_coordinator_handler (FpiSsm   *ssm,
                                             FpDevice *dev);
static void goodix_scan_start_capture_subsm (FpiSsm   *parent_ssm,
                                             FpDevice *dev);
static void goodix_scan_start_health_wait (FpiSsm   *parent,
                                           FpDevice *dev);
static void goodix_scan_detach_action (FpiSsm   *ssm,
                                       FpDevice *dev);

/* usbinterface!0115a4 owns four module-static history words. HAL sensor
 * checking reseeds current/default only; neither close nor reset clears them.
 * Serialize the shared words if different device main contexts run in parallel. */
static GMutex goodix_dac_history_lock;
static GoodixDynamicDacState goodix_dac_history;

static void
goodix_scan_coordinator_data_free (GoodixScanCoordinatorData *data)
{
  if (!data)
    return;

  if (data->action_cancel && data->action_cancel_id)
    g_cancellable_disconnect (data->action_cancel, data->action_cancel_id);
  g_clear_object (&data->action_cancel);
  g_clear_error (&data->stop_error);
  g_clear_pointer (&data->health_timer, g_source_destroy);
  g_clear_object (&data->service_device);
  g_free (data);
}

static void
goodix_scan_normalize_event (const GoodixProfile9FdtEvent *event,
                             guint16                       values[GOODIX_PROFILE9_FDT_AREA_COUNT])
{
  for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
    {
      guint16 raw = event->raw[i * 2] |
                    ((guint16) event->raw[i * 2 + 1] << 8);

      values[i] = raw >> 1;
    }
}

static gboolean
goodix_scan_majority_changed (const guint16 first[GOODIX_PROFILE9_FDT_AREA_COUNT],
                              const guint16 second[GOODIX_PROFILE9_FDT_AREA_COUNT],
                              guint16       threshold)
{
  guint changed = 0;

  for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
    changed += ABS ((gint) first[i] - (gint) second[i]) > threshold;

  return changed > GOODIX_PROFILE9_FDT_AREA_COUNT / 2;
}

static gboolean
goodix_scan_all_strictly_close (const guint16 first[GOODIX_PROFILE9_FDT_AREA_COUNT],
                                const guint16 second[GOODIX_PROFILE9_FDT_AREA_COUNT],
                                guint16       threshold)
{
  for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
    if (ABS ((gint) first[i] - (gint) second[i]) >= threshold)
      return FALSE;

  return TRUE;
}

static gboolean
goodix_scan_apply_anchor (FpiDeviceGoodix53x5 *self,
                          const guint16        current[GOODIX_PROFILE9_FDT_AREA_COUNT],
                          gboolean             seed_if_empty)
{
  GoodixProfile9FdtState *fdt = &self->profile9_fdt;

  if (fdt->drift_anchor_empty)
    {
      if (seed_if_empty)
        {
          memcpy (fdt->drift_anchor, current, sizeof (fdt->drift_anchor));
          fdt->drift_anchor_empty = FALSE;
        }
      return FALSE;
    }

  if (goodix_scan_majority_changed (fdt->drift_anchor, current,
                                    self->calib.delta_down))
    return TRUE;

  if (goodix_scan_all_strictly_close (fdt->drift_anchor, current,
                                      self->calib.delta_down / 3))
    {
      memset (fdt->drift_anchor, 0, sizeof (fdt->drift_anchor));
      fdt->drift_anchor_empty = TRUE;
    }

  return FALSE;
}

static gboolean
goodix_scan_disposition_waits_for_up (GoodixScanDisposition disposition)
{
  return disposition == GOODIX_SCAN_DISPOSITION_AUTH_RETRY_AFTER_UP ||
         disposition == GOODIX_SCAN_DISPOSITION_ENROLL_CONTINUE_AFTER_UP ||
         disposition == GOODIX_SCAN_DISPOSITION_ENROLL_FINAL_AFTER_UP;
}

static void
goodix_scan_finish_requested (GoodixScanCoordinatorData *data)
{
  if (data->stop_error)
    fpi_ssm_mark_failed (data->ssm, g_steal_pointer (&data->stop_error));
  else
    fpi_ssm_mark_completed (data->ssm);
}

static void
goodix_scan_maybe_finish_requested (GoodixScanCoordinatorData *data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (
    fpi_ssm_get_device (data->ssm));

  if (self->profile9_fdt.owner != data->ssm ||
      data->dispatching || data->waiting_event || self->transport)
    return;
  if (data->cpu_outstanding)
    {
      if (fpi_ssm_get_cur_state (data->ssm) <
          GOODIX_SCAN_COORD_CLEANUP_JOIN &&
          fpi_ssm_get_cur_state (data->ssm) != GOODIX_SCAN_COORD_WAIT_CPU)
        fpi_ssm_jump_to_state (data->ssm, GOODIX_SCAN_COORD_WAIT_CPU);
      return;
    }
  if (data->refresh_deferred)
    {
      data->refresh_deferred = FALSE;
      data->dispatching = TRUE;
      fpi_ssm_jump_to_state (data->ssm, GOODIX_SCAN_COORD_REFRESH);
      return;
    }
  goodix_scan_finish_requested (data);
}

static void
goodix_scan_request_stop (GoodixScanCoordinatorData *data,
                          GError                    *error)
{
  FpDevice *dev = fpi_ssm_get_device (data->ssm);

  if (data->stop_requested)
    {
      if (error && !data->stop_error)
        data->stop_error = error;
      else
        g_clear_error (&error);
      goodix_scan_maybe_finish_requested (data);
      return;
    }

  data->stop_requested = TRUE;
  data->stop_error = error;

  if (data->waiting_event && !data->dispatching)
    {
      goodix_transport_cancel_event (dev);
      return;
    }

  goodix_scan_maybe_finish_requested (data);
}

static void
goodix_scan_action_cancelled (GCancellable *cancellable,
                              gpointer      user_data)
{
  GoodixScanCoordinatorData *data = user_data;

  (void) cancellable;
  goodix_scan_request_stop (
    data, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                               "Profile-9 scan action cancelled"));
}

static void
goodix_scan_gtls_restarted (FpDevice *dev, GError *error, gpointer user_data)
{
  GoodixScanCoordinatorData *data = user_data;

  data->dispatching = FALSE;
  if (error)
    {
      goodix_scan_request_stop (data, error);
      return;
    }
  fpi_ssm_jump_to_state (data->ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
}

static void
goodix_scan_event_done (FpDevice *dev, const GoodixTransportResult *result,
                        GError *error, gpointer user_data)
{
  GoodixScanCoordinatorData *data = user_data;
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  data->waiting_event = FALSE;
  if (!error && result->restart_gtls)
    {
      /* Keep the coordinator alive through asynchronous recovery and cancellation.
       * One transport owner serializes GTLS with capture and arm commands. */
      data->dispatching = TRUE;
      goodix_start_gtls_restart (dev, goodix_scan_gtls_restarted, data);
      return;
    }
  if (!error)
    {
      /* Selected work must still dispatch if its packet won cancellation. */
      data->dispatching = TRUE;
      fpi_ssm_next_state (data->ssm);
      return;
    }
  if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
      !g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED))
    {
      if (error->domain == G_USB_DEVICE_ERROR || error->domain == G_IO_ERROR)
        self->needs_reinit = TRUE;
      fpi_ssm_mark_failed (data->ssm, error);
      return;
    }
  g_clear_error (&error);

  if (!data->stop_requested)
    {
      data->stop_requested = TRUE;
      data->stop_error = fpi_device_error_new_msg (
        FP_DEVICE_ERROR_GENERAL,
        "Profile-9 event receive was cancelled unexpectedly");
    }
  goodix_scan_maybe_finish_requested (data);
}

static void
goodix_scan_prepare_refresh (FpiSsm                        *ssm,
                             FpiDeviceGoodix53x5           *self,
                             GoodixScanCoordinatorData     *data,
                             GoodixProfile9FdtRefreshReason reason)
{
  data->refresh_reason = reason;
  self->profile9_fdt.base_valid = FALSE;
  if (data->cpu_outstanding)
    {
      data->refresh_deferred = TRUE;
      data->dispatching = FALSE;
      /* Serialize replacement with the previous immutable CPU input. The
       * retained native wait state changes only on arm/deactivation. */
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_CPU);
    }
  else
    {
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_REFRESH);
    }
}

static void
goodix_scan_config_restored (FpiSsm *ssm, FpDevice *dev, guint8 status,
                             gboolean native_zero, GError *error)
{
  /* usbinterface!180015710 discards mode-4 failure before down-arm. Keep
   * terminal host errors on the existing joined cleanup path. */
  if (error && !native_zero)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  g_clear_error (&error);
  fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_REARM_DOWN);
}

static void
goodix_scan_manual_done (FpiSsm *ssm, FpDevice *dev, guint8 status,
                         gboolean native_zero, GError *error)
{
  GoodixScanCoordinatorData *data = fpi_ssm_get_data (ssm);

  if (error && native_zero)
    {
      /* A failed manual read returns from Down_procedure without an arm. */
      g_clear_error (&error);
      data->dispatching = FALSE;
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
    }
  else if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
    }
  else
    {
      fpi_ssm_next_state (ssm);
    }
}

static void
goodix_scan_health_done (FpDevice *dev,
                         const GoodixHealthMeasurement *measurement,
                         GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

static void
goodix_scan_coordinator_handler (FpiSsm   *ssm,
                                 FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixProfile9FdtState *fdt = &self->profile9_fdt;
  GoodixScanCoordinatorData *data = fpi_ssm_get_data (ssm);

  if (fpi_ssm_get_cur_state (ssm) < GOODIX_SCAN_COORD_CLEANUP_JOIN &&
      fpi_ssm_get_cur_state (ssm) != GOODIX_SCAN_COORD_WAIT_EVENT &&
      data->stop_requested && !data->dispatching && !data->waiting_event)
    {
      goodix_scan_maybe_finish_requested (data);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_SCAN_COORD_ENSURE_REFERENCE:
      if (data->idle)
        {
          fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
          break;
        }
      if (self->milan_generation || fdt->initial_recovery_pending)
        fpi_ssm_next_state (ssm);
      else
        goodix_milan_base_start_ensure_subsm (ssm, dev, TRUE);
      break;

    case GOODIX_SCAN_COORD_ENSURE_REFERENCE_DONE:
      if (self->milan_generation)
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      if (!fdt->initial_recovery_pending)
        {
          fpi_ssm_mark_failed (
            ssm, fpi_device_error_new_msg (
              FP_DEVICE_ERROR_GENERAL,
              "Milan reference acquisition produced no generation or recovery state"));
          return;
        }

      data->recovering_generation = TRUE;
      if (fdt->event.pending)
        {
          if ((fdt->event.touch_flag & 0x0fff) != 0)
            fpi_device_report_finger_status_changes (
              dev, FP_FINGER_STATUS_PRESENT, FP_FINGER_STATUS_NEEDED);
          else
            fpi_device_report_finger_status_changes (
              dev, FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_PRESENT);
        }
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_SCAN_COORD_POWER_ON:
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_PRESENT);
      goodix_cmd_ec_control (ssm, dev, TRUE);
      break;

    case GOODIX_SCAN_COORD_ARM_DOWN:
      fdt->wait_mode = GOODIX_PROFILE9_FDT_WAIT_DOWN;
      goodix_cmd_fdt_down_setup (ssm, dev, fdt->base_down);
      break;

    case GOODIX_SCAN_COORD_WAIT_EVENT:
      {
        if (data->health_parent && goodix_health_is_complete (&self->health))
          data->stop_requested = TRUE;
        if (data->idle && data->stop_requested)
          {
            /* Join the selected handler, leaving any newer coalesced event
             * to the next owner rather than extending handoff indefinitely. */
            data->dispatching = FALSE;
            goodix_scan_maybe_finish_requested (data);
            return;
          }
        /* A pending notification can complete synchronously and free data.
         * Preserve the arm/stop receive-and-cancel window without borrowing it
         * after submission. cancel_event affects only a still-pending wait. */
        gboolean stop = data->stop_requested;
        data->waiting_event = TRUE;
        goodix_transport_wait_event (dev, fdt->wait_mode, goodix_scan_event_done, data);
        if (stop)
          goodix_transport_cancel_event (dev);
      }
      break;

    case GOODIX_SCAN_COORD_DISPATCH_EVENT:
      {
        g_autoptr(GError) error = NULL;

        if (!goodix_recv_select_fdt (dev, &data->event_type, &fdt->event,
                                     data->prior_down, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        data->dispatching = TRUE;

        if (data->event_type == GOODIX_FDT_EVENT_ESD)
          {
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_ESD);
            return;
          }
        if (data->event_type == GOODIX_FDT_EVENT_WAKE)
          {
            /* Ordinary screen-on 00dc84 has no requested-mode gate. */
            fpi_ssm_jump_to_state (ssm, fdt->wait_mode == GOODIX_PROFILE9_FDT_WAIT_UP ?
                                   GOODIX_SCAN_COORD_RECOVERY_ARM_UP :
                                   GOODIX_SCAN_COORD_REARM_DOWN);
            return;
          }
        if (data->event_type == GOODIX_FDT_EVENT_DEACTIVATE)
          {
            /* Delay belongs to selected work, not to a replaceable timer. */
            fpi_ssm_jump_to_state_delayed (ssm, GOODIX_SCAN_COORD_DEACTIVATE_EC, 500);
            return;
          }

        if (data->event_type == GOODIX_FDT_EVENT_CONFIG)
          {
            /* Native worker 00e00d tests the persistent requested mode at
             * selection, not when the parser publishes the notification. */
            if (self->requested_mode == GOODIX_REQUESTED_MODE_SLEEP)
              {
                data->dispatching = FALSE;
                fdt->event.pending = FALSE;
                fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
                return;
              }
            /* No sample or release was published. Preserve the selected raw
             * vector, drift/reference state and outstanding CPU ownership. */
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_RESTORE_CONFIG);
            return;
          }

        if (data->event_type == GOODIX_FDT_EVENT_DOWN)
          {
            goodix_health_note_down (&self->health);
            fpi_ssm_next_state (ssm);
            return;
          }

        {
          guint16 current[GOODIX_PROFILE9_FDT_AREA_COUNT];
          gboolean refresh = FALSE;

          goodix_scan_normalize_event (&fdt->event, current);
          data->release_settled = data->cycle_active;

          if (data->event_type == GOODIX_FDT_EVENT_REVERSE)
            {
              if (!fdt->base_valid)
                {
                  data->refresh_reason = GOODIX_PROFILE9_FDT_REFRESH_INVALID_BASE;
                  refresh = TRUE;
                }
              else if (goodix_scan_majority_changed (
                         data->prior_down, current, self->calib.delta_down) ||
                       goodix_scan_apply_anchor (self, current, TRUE))
                {
                  refresh = TRUE;
                }
            }
          else
            {
              if (goodix_scan_apply_anchor (self, current, FALSE))
                {
                  refresh = TRUE;
                }
              else if (!fdt->base_valid)
                {
                  data->refresh_reason = GOODIX_PROFILE9_FDT_REFRESH_UP_INVALID_BASE;
                  refresh = TRUE;
                }
            }

          if (data->recovering_generation)
            {
              data->refresh_reason = GOODIX_PROFILE9_FDT_REFRESH_INVALID_BASE;
              refresh = TRUE;
            }

          if (refresh)
            {
              GoodixProfile9FdtRefreshReason reason = data->refresh_reason;

              if (reason == GOODIX_PROFILE9_FDT_REFRESH_NONE)
                reason = data->event_type == GOODIX_FDT_EVENT_REVERSE ?
                         GOODIX_PROFILE9_FDT_REFRESH_REVERSE :
                         GOODIX_PROFILE9_FDT_REFRESH_UP;
              goodix_scan_prepare_refresh (
                ssm, self, data, reason);
              return;
            }
          data->refresh_reason = GOODIX_PROFILE9_FDT_REFRESH_NONE;
          fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_UP_HEALTH);
        }
      }
      break;

    case GOODIX_SCAN_COORD_DOWN_MANUAL:
      goodix_cmd_fdt_manual_result (ssm, dev, FALSE, fdt->base_manual,
                                    goodix_scan_manual_done);
      break;

    case GOODIX_SCAN_COORD_DOWN_VALIDATE:
      {
        g_autoptr(GError) error = NULL;
        const guint8 *payload;
        gsize payload_len;

        if (!goodix_cmd_parse_fdt_manual_reply (dev, &payload, &payload_len,
                                                &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        if (goodix_device_is_fdt_base_valid (fdt->event.raw, payload + 4,
                                             GOODIX_FDT_BASE_LEN,
                                             self->calib.delta_fdt))
          {
            goodix_scan_prepare_refresh (
              ssm, self, data, GOODIX_PROFILE9_FDT_REFRESH_FALSE_DOWN);
            return;
          }

        if (self->requested_mode != GOODIX_REQUESTED_MODE_CAPTURE ||
            !self->capture_callback_pending || data->cycle_active)
          {
            /* Native manual validation precedes the live-request gate. A
            * genuine inactive down still arms up, but never captures. */
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_RECOVERY_ARM_UP);
            return;
          }
        fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT,
                                                 FP_FINGER_STATUS_NEEDED);
        if (!self->hardware_reference)
          {
            data->recovering_generation = TRUE;
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_RECOVERY_ARM_UP);
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_SCAN_COORD_CAPTURE:
      goodix_scan_start_capture_subsm (ssm, dev);
      break;

    case GOODIX_SCAN_COORD_ARM_UP:
      self->capture_callback_pending = FALSE;
      data->cycle_active = TRUE;
      data->release_settled = FALSE;
      data->cpu_done = FALSE;
      if (!data->stop_requested && !data->idle)
        {
          if (!self->milan_generation || !self->captured_raw_image)
            {
              data->recovering_generation = TRUE;
            }
          else
            {
              /* Deliver the completed frame before up-arm. Dispatch ownership
               * holds the coordinator until the command finishes; cleanup joins
               * any worker even if that command fails. */
              data->cpu_outstanding = TRUE;
              goodix_milan_generation_prepare_setup (dev, self->milan_generation);
              GOODIX53X5_DEBUG_ONLY (
                guint64 use = goodix_milan_generation_note_use (self->milan_generation);

                fp_info ("Using Milan generation id=%" G_GUINT64_FORMAT
                         " use=%" G_GUINT64_FORMAT,
                         self->milan_generation->generation_id, use);
                                    )
              data->capture_ready (dev, data->user_data);
            }
        }
      /* Hardware callback invocation consumes the marker even if cancellation
       * suppressed engine/CPU delivery. No setup is initialized for that case. */
      self->hardware_refresh_pending = FALSE;
      fdt->wait_mode = GOODIX_PROFILE9_FDT_WAIT_UP;
      goodix_cmd_fdt_up_setup (ssm, dev, fdt->base_up);
      break;

    case GOODIX_SCAN_COORD_ARM_UP_DONE:
    case GOODIX_SCAN_COORD_RECOVERY_ARM_UP_DONE:
      data->dispatching = FALSE;
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
      break;

    case GOODIX_SCAN_COORD_RECOVERY_ARM_UP:
      data->dispatching = TRUE;
      fdt->wait_mode = GOODIX_PROFILE9_FDT_WAIT_UP;
      goodix_cmd_fdt_up_setup (ssm, dev, fdt->base_up);
      break;

    case GOODIX_SCAN_COORD_REFRESH:
      goodix_milan_base_start_forced_refresh_subsm (ssm, dev,
                                                    data->refresh_reason);
      break;

    case GOODIX_SCAN_COORD_REFRESH_DONE:
      /* Rejected reverse drift restores only the down base from the selected
      * event. Newer notifications remain separately owned by pending_fdt. */
      if (data->refresh_reason == GOODIX_PROFILE9_FDT_REFRESH_REVERSE &&
          !fdt->base_valid)
        goodix_device_generate_fdt_base (fdt->event.raw, GOODIX_FDT_BASE_LEN,
                                         fdt->base_down);
      data->refresh_reason = GOODIX_PROFILE9_FDT_REFRESH_NONE;
      if (self->milan_generation)
        data->recovering_generation = FALSE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_SCAN_COORD_REARM_DOWN:
      fdt->wait_mode = GOODIX_PROFILE9_FDT_WAIT_DOWN;
      goodix_cmd_fdt_down_setup (ssm, dev, fdt->base_down);
      break;

    case GOODIX_SCAN_COORD_UP_HEALTH:
      /* Health runs for event_type == UP with a retained hardware_reference,
       * after reference handling (including rejection/failure), before down
       * arm. Neither base_valid nor an active user request gates eligibility;
       * DOWN/REVERSE continuations passing this state do not run UP health. */
      if (data->event_type == GOODIX_FDT_EVENT_UP && self->hardware_reference)
        goodix_health_start_pair (dev, GOODIX_HEALTH_PAIR_UP,
                                  goodix_scan_health_done, ssm);
      else
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_SCAN_COORD_REARM_DOWN_DONE:
      data->dispatching = FALSE;
      fdt->event.pending = FALSE;

      if (self->pending_fdt.event.pending || data->stop_requested)
        {
          /* An event already received during rearm precedes CPU settlement.
           * Otherwise resolve the outstanding arm before shutdown as usual. */
          fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
          return;
        }
      if (data->release_settled)
        {
          fpi_device_report_finger_status_changes (
            dev, FP_FINGER_STATUS_NONE,
            FP_FINGER_STATUS_PRESENT | FP_FINGER_STATUS_NEEDED);
          if (data->cpu_done)
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_CYCLE_SETTLED);
          else
            /* The down arm is one-shot: wait for CPU before posting the
             * next receive instead of posting one only to cancel it. */
            fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_CPU);
          return;
        }
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
      break;

    case GOODIX_SCAN_COORD_WAIT_CPU:
      break;

    case GOODIX_SCAN_COORD_RESTORE_CONFIG:
      goodix_cmd_restore_config (ssm, dev, goodix_scan_config_restored);
      break;

    case GOODIX_SCAN_COORD_ESD:
      goodix_cmd_repair_esd (ssm, dev);
      break;

    case GOODIX_SCAN_COORD_DEACTIVATE_EC:
      goodix_cmd_ec_control (ssm, dev, FALSE);
      break;

    case GOODIX_SCAN_COORD_ESD_DONE:
    case GOODIX_SCAN_COORD_DEACTIVATE_EC_DONE:
      data->dispatching = FALSE;
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
      break;

    case GOODIX_SCAN_COORD_CYCLE_SETTLED:
      if (data->cycle_settled)
        data->cycle_settled (dev, data->disposition, data->user_data);
      if (data->stop_requested)
        return;

      if (data->disposition == GOODIX_SCAN_DISPOSITION_ENROLL_CONTINUE_AFTER_UP)
        {
          data->cycle_active = FALSE;
          data->release_settled = FALSE;
          data->cpu_done = FALSE;
          self->capture_unread = 2;
          goodix_health_note_capture (&self->health, TRUE);
          self->capture_callback_pending = TRUE;
          fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_WAIT_EVENT);
        }
      else
        {
          fpi_ssm_mark_completed (ssm);
        }
      break;

    case GOODIX_SCAN_COORD_CLEANUP_JOIN:
      fdt->lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPING;
      if (data->idle)
        {
          /* Handoff is not native deactivation. Keep arm state and pending
          * notification; terminal power policy is owned by the session. */
          fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_NUM_STATES);
          break;
        }
      if (data->cpu_outstanding)
        {
          if (data->action_cancel &&
              !g_cancellable_is_cancelled (data->action_cancel))
            g_cancellable_cancel (data->action_cancel);
          break;
        }
      goodix_scan_detach_action (ssm, dev);
      break;

    case GOODIX_SCAN_COORD_CLEANUP_HEALTH:
      /* Native deactivation publishes 0x15 once, replacing only unselected
       * work. A newer FDT/notice during sleep replaces it in turn. The service
       * selects surviving work after the foreground joins. */
      fdt->wait_mode = GOODIX_PROFILE9_FDT_WAIT_NONE;
      self->pending_fdt.type = GOODIX_FDT_EVENT_DEACTIVATE;
      self->pending_fdt.event.pending = TRUE;
      self->capture_callback_pending = FALSE;
      if (goodix_health_is_complete (&self->health))
        fpi_ssm_next_state (ssm);
      else
        goodix_scan_start_health_wait (ssm, dev);
      break;

    case GOODIX_SCAN_COORD_CLEANUP_SLEEP:
      {
        gboolean study_allowed = goodix_health_finish_deactivation (&self->health);

        fp_dbg ("Deactivation retained study permission: %d", study_allowed);
        goodix_cmd_set_sleep_mode (ssm, dev);
      }
      break;

    case GOODIX_SCAN_COORD_CLEANUP_DONE:
      if (data->stop_error)
        fpi_ssm_mark_failed (ssm, g_steal_pointer (&data->stop_error));
      else
        fpi_ssm_mark_completed (ssm);
      break;

    case GOODIX_SCAN_COORD_NUM_STATES:
      g_assert_not_reached ();
    }
}

/* The action's outcome is final once its CPU work has joined. Hand it back
 * now and finish the native deactivation tail (health wait, sleep) as the
 * session's background owner, so a completed match reports immediately.
 * Like the native adapter, a hardware failure after the comparison does not
 * invalidate a positive result; it only marks the session for reconstruction. */
static void
goodix_scan_detach_action (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data = fpi_ssm_get_data (ssm);
  FpiSsm *parent = g_steal_pointer (&data->parent_ssm);
  GError *outcome = g_steal_pointer (&data->stop_error);

  if (!outcome && fpi_ssm_get_error (ssm))
    outcome = g_error_copy (fpi_ssm_get_error (ssm));
  if (outcome && !g_error_matches (outcome, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    {
      self->needs_reinit = TRUE;
      if (data->cpu_done &&
          data->disposition == GOODIX_SCAN_DISPOSITION_AUTH_SUCCESS)
        g_clear_error (&outcome);
    }

  data->detached = TRUE;
  goodix_session_detach_action (dev);
  /* Advance before completing the action: its callback may admit the next
   * action, which joins this owner through the ordinary stop request. */
  fpi_ssm_mark_completed (ssm);
  if (outcome)
    fpi_ssm_mark_failed (parent, outcome);
  else
    fpi_ssm_next_state (parent);
}

static void
goodix_scan_coordinator_done (FpiSsm   *ssm,
                              FpDevice *dev,
                              GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data = fpi_ssm_get_data (ssm);

  g_assert (self->profile9_fdt.owner == ssm);
  self->profile9_fdt.owner = NULL;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED;
  if (data->health_parent)
    {
      GoodixScanCoordinatorData *parent = fpi_ssm_get_data (data->health_parent);

      g_clear_pointer (&parent->health_timer, g_source_destroy);
      self->profile9_fdt.owner = data->health_parent;
      self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPING;
      if (error)
        fpi_ssm_mark_failed (data->health_parent, error);
      else
        fpi_ssm_next_state (data->health_parent);
      return;
    }
  if (data->detached)
    {
      /* Reconstruction already owns known failures. Let the session classify
       * any remaining tail error without changing the delivered result. */
      if (self->needs_reinit)
        g_clear_error (&error);
      goodix_session_service_done (dev, error);
      return;
    }
  /* Every action-owned coordinator passes through CLEANUP_JOIN and detaches. */
  g_assert (data->idle);
  goodix_session_service_done (dev, error);
}

static void
goodix_scan_health_wait_expired (FpDevice *dev, gpointer user_data)
{
  GoodixScanCoordinatorData *parent = user_data;
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  parent->health_timer = NULL;
  /* Stop selection, but join a selected pair/refresh/500-ms EC handler. */
  goodix_scan_request_stop (fpi_ssm_get_data (self->profile9_fdt.owner), NULL);
}

static void
goodix_scan_start_health_wait (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *parent = fpi_ssm_get_data (parent_ssm);
  GoodixScanCoordinatorData *data = g_new0 (GoodixScanCoordinatorData, 1);
  FpiSsm *ssm;

  /* Native deactivation waits while the independent event worker continues.
   * Lend hardware ownership to a maintenance-only child for that bounded wait.
   * The single coalescing slot also owns 0x15; no extra EC timer is introduced. */
  data->idle = TRUE;
  data->health_parent = parent_ssm;
  ssm = fpi_ssm_new_full (dev, goodix_scan_coordinator_handler,
                          GOODIX_SCAN_COORD_NUM_STATES,
                          GOODIX_SCAN_COORD_CLEANUP_JOIN,
                          "goodix-profile9-health-wait");
  data->ssm = ssm;
  fpi_ssm_set_data (ssm, data,
                    (GDestroyNotify) goodix_scan_coordinator_data_free);
  parent->health_timer = fpi_device_add_timeout (
    dev, GOODIX_HEALTH_DEACTIVATE_TIMEOUT_MS,
    goodix_scan_health_wait_expired, parent, NULL);
  self->profile9_fdt.owner = ssm;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
  fpi_ssm_start (ssm, goodix_scan_coordinator_done);
}

void
goodix_scan_start_service (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data = g_new0 (GoodixScanCoordinatorData, 1);
  FpiSsm *ssm;

  g_assert (!self->profile9_fdt.owner && !self->transport);
  data->idle = TRUE;
  data->service_device = g_object_ref (dev);
  ssm = fpi_ssm_new_full (dev, goodix_scan_coordinator_handler,
                          GOODIX_SCAN_COORD_NUM_STATES,
                          GOODIX_SCAN_COORD_CLEANUP_JOIN,
                          "goodix-profile9-service");
  data->ssm = ssm;
  fpi_ssm_set_data (ssm, data,
                    (GDestroyNotify) goodix_scan_coordinator_data_free);
  self->service_active = TRUE;
  self->profile9_fdt.owner = ssm;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
  fpi_ssm_start (ssm, goodix_scan_coordinator_done);
}

void
goodix_scan_join_service (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_assert (self->service_active && self->profile9_fdt.owner);
  goodix_scan_request_stop (fpi_ssm_get_data (self->profile9_fdt.owner), NULL);
}

gboolean
goodix_scan_continue_command_error (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gint state = fpi_ssm_get_cur_state (ssm);

  if (self->profile9_fdt.owner != ssm ||
      (state != GOODIX_SCAN_COORD_CLEANUP_SLEEP &&
       state != GOODIX_SCAN_COORD_DEACTIVATE_EC))
    return FALSE;
  fp_dbg ("Continuing after ordinary power command failure: %s", error->message);
  g_error_free (error);
  fpi_ssm_next_state (ssm);
  return TRUE;
}

void
goodix_scan_start_coordinator_subsm (
  FpiSsm                        *parent_ssm,
  FpDevice                      *dev,
  GoodixScanCaptureReadyCallback capture_ready,
  GoodixScanCycleSettledCallback cycle_settled,
  gpointer                       user_data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data;
  FpiSsm *ssm;

  g_return_if_fail (capture_ready != NULL);
  if (self->cancel && g_cancellable_is_cancelled (self->cancel))
    {
      fpi_ssm_mark_failed (parent_ssm,
                           g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                "Scan cancelled before admission"));
      return;
    }
  if (self->profile9_fdt.owner || self->profile9_fdt.lifecycle !=
      GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED)
    {
      fpi_ssm_mark_failed (
        parent_ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                              "Profile-9 scan coordinator is already active"));
      return;
    }

  data = g_new0 (GoodixScanCoordinatorData, 1);
  data->parent_ssm = parent_ssm;
  data->capture_ready = capture_ready;
  data->cycle_settled = cycle_settled;
  data->user_data = user_data;
  data->action_cancel = self->cancel ? g_object_ref (self->cancel) : NULL;
  ssm = fpi_ssm_new_full (dev, goodix_scan_coordinator_handler,
                          GOODIX_SCAN_COORD_NUM_STATES,
                          GOODIX_SCAN_COORD_CLEANUP_JOIN,
                          "goodix-profile9-scan");
  data->ssm = ssm;
  fpi_ssm_set_data (ssm, data,
                    (GDestroyNotify) goodix_scan_coordinator_data_free);
  self->profile9_fdt.owner = ssm;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
  /* device_get_data clears HAL +0x1e0 before EC control and initial arming.
   * Maintenance rearming and configuration repair do not change this mode. */
  self->requested_mode = GOODIX_REQUESTED_MODE_CAPTURE;
  /* The previous owner has joined. A new capture supersedes only its
   * unselected power-off notification; retain real sensor notifications.
   * Already-selected deactivation finishes before this admission point. */
  if (self->pending_fdt.event.pending &&
      self->pending_fdt.type == GOODIX_FDT_EVENT_DEACTIVATE)
    self->pending_fdt.event.pending = FALSE;
  self->capture_unread = fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL ? 2 : 1;
  goodix_health_note_capture (&self->health, self->capture_unread == 2);
  self->capture_callback_pending = TRUE;
  fpi_ssm_start (ssm, goodix_scan_coordinator_done);
  if (self->profile9_fdt.owner == ssm && data->action_cancel)
    data->action_cancel_id = g_cancellable_connect (
      data->action_cancel, G_CALLBACK (goodix_scan_action_cancelled), data,
      NULL);
}

void
goodix_scan_set_disposition (FpDevice             *dev,
                             GoodixScanDisposition disposition,
                             GError               *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data;

  if (!self->profile9_fdt.owner)
    {
      fp_warn ("Ignoring disposition for an inactive scan coordinator");
      g_clear_error (&error);
      return;
    }

  data = fpi_ssm_get_data (self->profile9_fdt.owner);
  if (!data->cycle_active || data->cpu_done || !data->cpu_outstanding)
    {
      fp_warn ("Ignoring duplicate scan-cycle disposition");
      g_clear_error (&error);
      return;
    }

  data->cpu_done = TRUE;
  data->cpu_outstanding = FALSE;
  data->disposition = disposition;
  if (fpi_ssm_get_cur_state (data->ssm) >= GOODIX_SCAN_COORD_CLEANUP_JOIN)
    {
      /* Cleanup was waiting for this join; the stop reason is already owned. */
      g_clear_error (&error);
      goodix_scan_detach_action (data->ssm, dev);
      return;
    }
  if (data->stop_requested)
    {
      g_clear_error (&error);
      goodix_scan_maybe_finish_requested (data);
      return;
    }
  if (disposition == GOODIX_SCAN_DISPOSITION_FATAL)
    {
      goodix_scan_request_stop (
        data, error ? error : fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
    }
  else if (disposition == GOODIX_SCAN_DISPOSITION_CANCELLED)
    {
      g_clear_error (&error);
      goodix_scan_request_stop (
        data, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Profile-9 scan cycle cancelled"));
    }
  else
    {
      g_clear_error (&error);
      if (!goodix_scan_disposition_waits_for_up (disposition))
        {
          /* Retain terminal intent while maybe_finish joins a deferred
           * selected refresh. Its rearm must not require a future release. */
          goodix_scan_request_stop (data, NULL);
        }
      else if (data->refresh_deferred)
        {
          data->refresh_deferred = FALSE;
          data->dispatching = TRUE;
          fpi_ssm_jump_to_state (data->ssm, GOODIX_SCAN_COORD_REFRESH);
        }
      else if (data->release_settled && !data->dispatching &&
               !data->waiting_event && !self->transport)
        {
          fpi_ssm_jump_to_state (data->ssm,
                                 GOODIX_SCAN_COORD_CYCLE_SETTLED);
        }
    }
}

void
goodix_scan_stop_coordinator (FpDevice *dev,
                              GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixScanCoordinatorData *data;

  if (!self->profile9_fdt.owner)
    {
      g_clear_error (&error);
      return;
    }

  data = fpi_ssm_get_data (self->profile9_fdt.owner);
  /* The stop can synchronously complete and free the coordinator. */
  g_autoptr(GCancellable) cancel = data->cpu_outstanding && data->action_cancel ?
                                   g_object_ref (data->action_cancel) : NULL;
  goodix_scan_request_stop (
    data, error ? error : g_error_new_literal (G_IO_ERROR,
                                               G_IO_ERROR_CANCELLED,
                                               "Profile-9 scan stopped"));
  if (cancel)
    g_cancellable_cancel (cancel);
}

/* Capture SSM */
typedef enum {
  GOODIX_CAPTURE_GET_IMAGE = 0,
  GOODIX_CAPTURE_DECRYPT,
  GOODIX_CAPTURE_DECODE,
  GOODIX_CAPTURE_STORE,
  GOODIX_CAPTURE_NUM_STATES,
} GoodixCaptureState;

typedef struct
{
  FpiSsm  *parent_ssm;
  gboolean ordinary_failure;
  guint16 *first_frame;
} GoodixCaptureData;

static void goodix_capture_ssm_handler (FpiSsm   *ssm,
                                        FpDevice *dev);

static void
goodix_capture_data_free (GoodixCaptureData *data)
{
  g_free (data->first_frame);
  g_free (data);
}

static void
goodix_capture_command_done (FpiSsm *ssm, FpDevice *dev, guint8 status,
                             gboolean native_zero, GError *error)
{
  GoodixCaptureData *data = fpi_ssm_get_data (ssm);

  data->ordinary_failure = error && native_zero;
  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

/* ========================================================================
 * Capture SSM
 * ======================================================================== */

static void
goodix_capture_ssm_handler (FpiSsm   *ssm,
                            FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  GOODIX53X5_DEBUG_ONLY (gint64 now_us = g_get_monotonic_time ();
                        )

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CAPTURE_GET_IMAGE:
      {
        GOODIX53X5_DEBUG_ONLY (
          self->debug_timing.capture_started_us = now_us;
          self->debug_timing.capture_phase_started_us = now_us;
                              )
        /* Live TX-on finger frame */
        goodix_cmd_request_image_result (ssm, dev, TRUE, TRUE, TRUE,
                                         self->calib.dac_h, goodix_capture_command_done);
      }
      break;

    case GOODIX_CAPTURE_DECRYPT:
      {
        g_autoptr(GError) error = NULL;
        GoodixCaptureData *data = fpi_ssm_get_data (ssm);
        g_autofree guint16 *frame = goodix_cmd_dup_image_reply (dev, &error);

        goodix_debug_timing_log (dev, "capture", "get_image",
                                 now_us - self->debug_timing.capture_phase_started_us,
                                 NULL);
        GOODIX53X5_DEBUG_ONLY (
          self->debug_timing.capture_phase_started_us = now_us;
                              )

        if (!frame)
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        /* Command success and raw decode precede adjustment. Receiver arrivals
         * and base captures do not adjust; metadata sees the post-read DAC. */
        g_mutex_lock (&goodix_dac_history_lock);
        goodix_dac_history.default_dac = self->dynamic_dac.default_dac;
        goodix_device_adjust_dac (&goodix_dac_history, &self->calib,
                                  frame,
                                  self->hardware_reference);
        self->dynamic_dac = goodix_dac_history;
        g_mutex_unlock (&goodix_dac_history_lock);

        /* Each success adjusts before decrement. A failed attempt discards
         * its first image but retains this count and all DAC/history effects. */
        self->capture_unread--;
        if (!data->first_frame)
          data->first_frame = g_steal_pointer (&frame);
        if (self->capture_unread)
          {
            fpi_ssm_jump_to_state (ssm, GOODIX_CAPTURE_GET_IMAGE);
            return;
          }

        GOODIX53X5_DEBUG_ONLY (
          if (goodix_debug_timing_enabled ())
      {
        gint64 done_us = g_get_monotonic_time ();

        goodix_debug_timing_log (dev, "capture", "process",
                                 done_us - self->debug_timing.capture_phase_started_us,
                                 NULL);
        if (self->debug_timing.capture_started_us != 0)
          goodix_debug_timing_log (dev, "capture", "total",
                                   done_us - self->debug_timing.capture_started_us,
                                   NULL);
        self->debug_timing.capture_started_us = 0;
      }
                              )

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_CAPTURE_DECODE:
      /* Already decoded in previous state, just advance */
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_CAPTURE_STORE:
      {
        GoodixCaptureData *data = fpi_ssm_get_data (ssm);

        /* Publish the first frame of this successful attempt with the DAC
         * produced by its last read. No partial attempt escapes to the CPU. */
        self->captured_raw_image = g_steal_pointer (&data->first_frame);
        self->captured_enroll_allowed = goodix_health_enroll_allowed (&self->health);
      }
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
goodix_capture_ssm_done (FpiSsm   *ssm,
                         FpDevice *dev,
                         GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixCaptureData *capture = fpi_ssm_get_data (ssm);
  gboolean read_failed;

  read_failed = error && capture->ordinary_failure;
  if (!read_failed)
    {
      if (error)
        fpi_ssm_mark_failed (capture->parent_ssm, error);
      else
        fpi_ssm_next_state (capture->parent_ssm);
      return;
    }

  g_assert (self->profile9_fdt.owner == capture->parent_ssm);
  g_assert (fpi_ssm_get_cur_state (capture->parent_ssm) ==
            GOODIX_SCAN_COORD_CAPTURE);
#ifdef GOODIX53X5_DEBUG
  self->debug_timing.capture_started_us = 0;
  self->debug_timing.capture_phase_started_us = 0;
#endif
  g_clear_error (&error);

  /* Application cancellation cannot cut short the selected handler's rearm. */
  fpi_ssm_jump_to_state (capture->parent_ssm, GOODIX_SCAN_COORD_REARM_DOWN);
}

/* ========================================================================
 * Sub-SSM start wrappers
 * ======================================================================== */

static void
goodix_scan_start_capture_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixCaptureData *data = g_new0 (GoodixCaptureData, 1);
  FpiSsm *sub = fpi_ssm_new (dev, goodix_capture_ssm_handler,
                             GOODIX_CAPTURE_NUM_STATES);

  data->parent_ssm = parent_ssm;
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  g_assert (self->capture_unread > 0);
  fpi_ssm_set_data (sub, data, (GDestroyNotify) goodix_capture_data_free);
  fpi_ssm_start (sub, goodix_capture_ssm_done);
}
