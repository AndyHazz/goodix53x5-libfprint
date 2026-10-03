/*
 * Goodix 53x5 driver for libfprint - native Milan base generation
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "device/base.h"
#include "device/persistence.h"

#include <string.h>

GQuark
goodix_milan_base_error_quark (void)
{
  return g_quark_from_static_string ("goodix-milan-base-error");
}

gboolean
goodix_milan_runtime_subtype_for_chip (guint32  chip_id,
                                       guint16 *subtype)
{
  if ((chip_id & GOODIX_MILAN_PROFILE9_CHIP_FAMILY_MASK) !=
      GOODIX_MILAN_PROFILE9_CHIP_FAMILY_PREFIX)
    return FALSE;

  if (subtype)
    *subtype = GOODIX_MILAN_VALIDATED_SUBTYPE;
  return TRUE;
}

gboolean
goodix_milan_base_pair_mad (const guint16 *tx_on,
                            gsize          tx_on_values,
                            const guint16 *tx_off,
                            gsize          tx_off_values,
                            guint64       *mad,
                            GError       **error)
{
  guint64 sum = 0;
  const gsize rows = GOODIX_MILAN_SENSOR_ROWS;
  const gsize columns = GOODIX_MILAN_SENSOR_COLUMNS;
  const gsize count = GOODIX_MILAN_SENSOR_PIXELS;
  const gsize interior =
    (rows - 2 * GOODIX_MILAN_BASE_BORDER) *
    (columns - 2 * GOODIX_MILAN_BASE_BORDER);

  if (!tx_on || !tx_off || tx_on_values != count || tx_off_values != count)
    {
      g_set_error_literal (error, GOODIX_MILAN_BASE_ERROR,
                           GOODIX_MILAN_BASE_ERROR_INVALID_FRAME,
                           "Milan base frames must each contain exactly 9504 values");
      return FALSE;
    }

  for (gsize row = GOODIX_MILAN_BASE_BORDER;
       row < rows - GOODIX_MILAN_BASE_BORDER; row++)
    for (gsize column = GOODIX_MILAN_BASE_BORDER;
         column < columns - GOODIX_MILAN_BASE_BORDER; column++)
      {
        const gsize index = row * columns + column;
        const guint16 first = tx_on[index];
        const guint16 second = tx_off[index];

        sum += first >= second ? first - second : second - first;
      }

  if (mad)
    *mad = sum / interior;
  return TRUE;
}

void
goodix_milan_base_attempt_init (GoodixMilanBaseAttempt *attempt)
{
  g_return_if_fail (attempt != NULL);
  memset (attempt, 0, sizeof (*attempt));
}

static void
goodix_milan_base_attempt_release_frames (GoodixMilanBaseAttempt *attempt)
{
  g_clear_pointer (&attempt->tx_on, g_free);
  g_clear_pointer (&attempt->tx_off, g_free);
  attempt->tx_on_values = 0;
  attempt->tx_off_values = 0;
  attempt->admitted = FALSE;
}

void
goodix_milan_base_attempt_reset (GoodixMilanBaseAttempt *attempt)
{
  if (!attempt)
    return;

  goodix_milan_base_attempt_release_frames (attempt);
  attempt->stage = GOODIX_MILAN_BASE_STAGE_IDLE;
  attempt->mad = 0;
  attempt->admission_status = 0;
}

void
goodix_milan_base_attempt_cancel (GoodixMilanBaseAttempt *attempt)
{
  if (!attempt)
    return;

  goodix_milan_base_attempt_release_frames (attempt);
  attempt->stage = GOODIX_MILAN_BASE_STAGE_CANCELLED;
  attempt->mad = 0;
  attempt->admission_status = 0;
}

void
goodix_milan_base_attempt_take_frame (GoodixMilanBaseAttempt *attempt,
                                      gboolean                tx_on,
                                      guint16               **frame,
                                      gsize                   values)
{
  guint16 **slot;
  gsize *slot_values;

  g_return_if_fail (attempt != NULL);
  g_return_if_fail (frame != NULL);

  slot = tx_on ? &attempt->tx_on : &attempt->tx_off;
  slot_values = tx_on ? &attempt->tx_on_values : &attempt->tx_off_values;
  g_clear_pointer (slot, g_free);
  *slot = g_steal_pointer (frame);
  *slot_values = values;
}

gboolean
goodix_milan_base_attempt_admit (GoodixMilanBaseAttempt *attempt,
                                 GError                **error)
{
  g_return_val_if_fail (attempt != NULL, FALSE);

  attempt->stage = GOODIX_MILAN_BASE_STAGE_ADMIT_PAIR;
  attempt->admission_status = 0;
  if (!goodix_milan_base_pair_mad (attempt->tx_on, attempt->tx_on_values,
                                   attempt->tx_off, attempt->tx_off_values,
                                   &attempt->mad, error))
    {
      goodix_milan_base_attempt_release_frames (attempt);
      return FALSE;
    }

  if (attempt->mad >= GOODIX_MILAN_BASE_MAD_LIMIT)
    {
      goodix_milan_base_attempt_release_frames (attempt);
      attempt->stage = GOODIX_MILAN_BASE_STAGE_REJECTED;
      return FALSE;
    }

  attempt->admitted = TRUE;
  return TRUE;
}

gboolean
goodix_milan_generation_allocate_id (guint64  *last_generation_id,
                                      guint64  *generation_id,
                                      GError  **error)
{
  g_return_val_if_fail (last_generation_id != NULL, FALSE);
  g_return_val_if_fail (generation_id != NULL, FALSE);

  if (*last_generation_id == G_MAXUINT64)
    {
      g_set_error_literal (error, GOODIX_MILAN_BASE_ERROR,
                           GOODIX_MILAN_BASE_ERROR_ID_EXHAUSTED,
                           "Milan generation IDs are exhausted");
      return FALSE;
    }

  *generation_id = ++(*last_generation_id);
  return TRUE;
}

void
goodix_milan_generation_reset_preprocess (GoodixMilanGeneration *generation)
{
  g_return_if_fail (generation != NULL);
  goodix_milan_preprocess_reset (&generation->state);
  memset (&generation->profile_state, 0, sizeof (generation->profile_state));
}

static void
goodix_milan_generation_transfer_process_state (
  GoodixMilanGeneration       *destination,
  const GoodixMilanGeneration *source)
{
  destination->state.stable_count = source->state.stable_count;
  destination->state.auxiliary_sample_count =
    source->state.auxiliary_sample_count;
  destination->state.application_gain_initialized =
    source->state.application_gain_initialized;
  memcpy (destination->state.coarse_reference, source->state.coarse_reference,
          sizeof (destination->state.coarse_reference));
  memcpy (destination->state.auxiliary_gain_map,
          source->state.auxiliary_gain_map,
          sizeof (destination->state.auxiliary_gain_map));
  memcpy (destination->state.secondary_auxiliary_gain_map,
          source->state.secondary_auxiliary_gain_map,
          sizeof (destination->state.secondary_auxiliary_gain_map));
  memcpy (destination->state.application_gain_map,
          source->state.application_gain_map,
          sizeof (destination->state.application_gain_map));
  /* Setup reloads the packet, but an entered native classifier imports it only
   * once per process lifetime. Keep the loaded snapshot separate from globals. */
  if (source->state.profile9_classifier_initialized)
    {
      destination->state.profile9_history_count =
        source->state.profile9_history_count;
      destination->state.profile9_history_update_count =
        source->state.profile9_history_update_count;
      destination->state.profile9_history_mask_threshold =
        source->state.profile9_history_mask_threshold;
      destination->state.profile9_history_mask_average =
        source->state.profile9_history_mask_average;
      memcpy (destination->state.profile9_history_reference,
              source->state.profile9_history_reference,
              sizeof (destination->state.profile9_history_reference));
      memcpy (destination->state.profile9_reference_age,
              source->state.profile9_reference_age,
              sizeof (destination->state.profile9_reference_age));
      memcpy (destination->state.profile9_component_age,
              source->state.profile9_component_age,
              sizeof (destination->state.profile9_component_age));
      destination->state.extraction_classification =
        source->state.extraction_classification;
      destination->state.profile9_classifier_initialized = 1;
    }
  destination->profile_state = source->profile_state;
  destination->profile_state.setup_refresh_pending = 1;
  destination->profile_state.setup_not_ready = 0;
  destination->process_state_retained = TRUE;
}

gboolean
goodix_milan_base_attempt_publish (GoodixMilanBaseAttempt  *attempt,
                                   guint64                  generation_id,
                                   GoodixMilanGeneration **generation,
                                   GError                 **error)
{
  GoodixMilanGeneration *published;

  g_return_val_if_fail (attempt != NULL, FALSE);
  g_return_val_if_fail (generation != NULL, FALSE);
  if (!attempt->admitted || !attempt->tx_on || !attempt->tx_off ||
      attempt->tx_on_values != GOODIX_MILAN_SENSOR_PIXELS ||
      attempt->tx_off_values != GOODIX_MILAN_SENSOR_PIXELS ||
      generation_id == 0)
    {
      g_set_error_literal (error, GOODIX_MILAN_BASE_ERROR,
                           GOODIX_MILAN_BASE_ERROR_INCOMPLETE,
                           "Cannot publish an incomplete Milan base generation");
      goodix_milan_base_attempt_release_frames (attempt);
      return FALSE;
    }

  published = g_new0 (GoodixMilanGeneration, 1);
  published->generation_id = generation_id;
  published->setup_tx_on = g_steal_pointer (&attempt->tx_on);
  published->admitted = TRUE;
  goodix_milan_generation_reset_preprocess (published);

  g_clear_pointer (&attempt->tx_off, g_free);
  attempt->tx_on_values = 0;
  attempt->tx_off_values = 0;
  attempt->admitted = FALSE;
  attempt->stage = GOODIX_MILAN_BASE_STAGE_PUBLISH;
  *generation = published;
  return TRUE;
}

void
goodix_milan_generation_free (GoodixMilanGeneration *generation)
{
  if (!generation)
    return;

  g_clear_pointer (&generation->setup_tx_on, g_free);
  g_clear_pointer (&generation->setup_save, goodix_milan_setup_save_free);
  memset (&generation->state, 0, sizeof (generation->state));
  memset (&generation->profile_state, 0, sizeof (generation->profile_state));
  g_free (generation);
}

void
goodix_milan_generation_invalidate (GoodixMilanGeneration **generation)
{
  if (!generation || !*generation)
    return;

  goodix_milan_generation_free (g_steal_pointer (generation));
}

guint64
goodix_milan_generation_note_use (GoodixMilanGeneration *generation)
{
  g_return_val_if_fail (generation != NULL, 0);
  g_return_val_if_fail (generation->admitted, 0);

  if (generation->use_count < G_MAXUINT64)
    generation->use_count++;
  return generation->use_count;
}

void
goodix_milan_generation_note_identify_prelude (GoodixMilanGeneration *generation)
{
  g_return_if_fail (generation != NULL);
  generation->identify_prelude_seen = TRUE;
  if (generation->identify_prelude_count < G_MAXUINT)
    generation->identify_prelude_count++;
}

gboolean
goodix_milan_replace_raw_frame (guint16 **owner,
                                guint16 **frame,
                                gsize     values,
                                GError  **error)
{
  g_return_val_if_fail (owner != NULL, FALSE);
  g_return_val_if_fail (frame != NULL, FALSE);

  if (!*frame || values != GOODIX_MILAN_SENSOR_PIXELS)
    {
      g_set_error_literal (error, GOODIX_MILAN_BASE_ERROR,
                           GOODIX_MILAN_BASE_ERROR_INVALID_FRAME,
                           "Live Milan raw frame must contain exactly 9504 values");
      g_clear_pointer (frame, g_free);
      return FALSE;
    }

  g_clear_pointer (owner, g_free);
  *owner = g_steal_pointer (frame);
  return TRUE;
}

/* Preserve release source locations after removing the compile seam. */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/calibration.h"
#include "device/commands.h"
#include "device/image.h"
#include "device/persistence.h"
#include "device/transport.h"

void
goodix_milan_generation_retain_process (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (!self->milan_generation)
    return;
  /* Native detach clears setup/workspace, not algorithm process globals. Keep
   * their source owner until the next base publication; never reuse its frame. */
  goodix_milan_generation_invalidate (&self->milan_retained_generation);
  self->milan_retained_generation = g_steal_pointer (&self->milan_generation);
  g_clear_pointer (&self->milan_retained_generation->setup_save,
                   goodix_milan_setup_save_free);
  g_clear_pointer (&self->milan_retained_generation->setup_tx_on, g_free);
  self->milan_retained_generation->profile_state.setup_initialized = 0;
  self->milan_retained_generation->profile_state.setup_refresh_pending = 0;
  self->milan_retained_generation->profile_state.setup_not_ready = 0;
}

void
goodix_milan_generation_prepare_setup (FpDevice              *dev,
                                       GoodixMilanGeneration *generation)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autofree GoodixMilanGeneration *restored = NULL;

  g_return_if_fail (generation != NULL);
  if (generation->profile_state.setup_initialized &&
      !generation->profile_state.setup_refresh_pending &&
      !self->hardware_refresh_pending)
    return;

  /* Hardware publication is not engine consumption. Select the newest base
   * only at sample delivery, while the coordinator excludes refresh/CPU work.
   * The native callback consumes its marker even if the engine later fails. */
  if (self->hardware_reference)
    {
      guint16 *setup = g_memdup2 (self->hardware_reference,
                                  GOODIX_SENSOR_PIXELS * sizeof (guint16));

      g_free (generation->setup_tx_on);
      generation->setup_tx_on = setup;
      /* Debug replay counts delivered samples within this reference, not
       * across the lifetime of the retained preprocessing state. */
      if (generation->generation_id != self->hardware_reference_id)
        generation->use_count = 0;
      generation->generation_id = self->hardware_reference_id;
    }
  if (self->hardware_refresh_pending)
    generation->profile_state.setup_refresh_pending = 1;
  self->hardware_refresh_pending = FALSE;

  /* Select disk workspace at sample delivery, retaining process-owned state
   * across a refresh. Setup admission and its flags remain runtime-owned. */
  restored = g_new0 (GoodixMilanGeneration, 1);
  goodix_milan_generation_reset_preprocess (restored);
  g_clear_pointer (&generation->setup_save, goodix_milan_setup_save_free);
  generation->setup_save = goodix_milan_persistence_restore (dev, restored);
  if (generation->profile_state.setup_initialized ||
      generation->process_state_retained)
    goodix_milan_generation_transfer_process_state (restored, generation);
  generation->state = restored->state;
}

typedef enum {
  GOODIX_BASE_UPLOAD_CONFIG = 0,
  GOODIX_BASE_UPLOAD_CONFIG_DONE,
  GOODIX_BASE_EC_POWER_ON,
  GOODIX_BASE_EC_POWER_ON_DONE,
  GOODIX_BASE_FDT_TX_ON_BEFORE,
  GOODIX_BASE_FDT_TX_ON_BEFORE_DONE,
  GOODIX_BASE_CAPTURE_TX_ON,
  GOODIX_BASE_CAPTURE_TX_ON_DONE,
  GOODIX_BASE_FDT_TX_OFF,
  GOODIX_BASE_FDT_TX_OFF_DONE,
  GOODIX_BASE_VALIDATE_FDT_PAIR,
  GOODIX_BASE_CAPTURE_TX_OFF,
  GOODIX_BASE_CAPTURE_TX_OFF_DONE,
  GOODIX_BASE_FDT_TX_ON_AFTER,
  GOODIX_BASE_FDT_TX_ON_AFTER_DONE,
  GOODIX_BASE_CLEANUP_SLEEP,
  GOODIX_BASE_CLEANUP_EC_POWER_OFF,
  GOODIX_BASE_CLEANUP_EC_POWER_OFF_DONE,
  GOODIX_BASE_NUM_STATES,
} GoodixBaseSsmState;

typedef struct
{
  GoodixMilanBaseAttempt  attempt;
  FpiSsm                 *parent_ssm;
  guint8                  fdt_tx_on_before[GOODIX_FDT_BASE_LEN];
  guint8                  fdt_tx_off[GOODIX_FDT_BASE_LEN];
  guint8                  candidate_base_down[GOODIX_FDT_BASE_LEN];
  guint8                  candidate_base_up[GOODIX_FDT_BASE_LEN];
  guint8                  candidate_base_manual[GOODIX_FDT_BASE_LEN];
  gboolean                forced_refresh;
  gboolean                manage_ec_power;
  gboolean                leave_powered;
  gboolean                first_fdt_ready;
  GoodixHealthMeasurement health_measurement;
} GoodixBaseSsmData;

static void
goodix_base_ssm_data_free (GoodixBaseSsmData *data)
{
  if (!data)
    return;
  goodix_milan_base_attempt_reset (&data->attempt);
  g_free (data);
}

static gboolean
goodix_base_check_cancelled (FpiSsm              *ssm,
                             FpiDeviceGoodix53x5 *self,
                             GoodixBaseSsmData   *data)
{
  /* A dispatched FDT handler is synchronous in the native event worker.
   * Finish its forced refresh before the coordinator honors action stop. */
  if (data->forced_refresh)
    return FALSE;

  if (!self->cancel || !g_cancellable_is_cancelled (self->cancel))
    return FALSE;

  goodix_milan_base_attempt_cancel (&data->attempt);
  fpi_ssm_mark_failed (ssm,
                       g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                            "Milan base acquisition cancelled"));
  return TRUE;
}

static guint16 *
goodix_base_decode_reply (FpDevice    *dev,
                          const gchar *role,
                          GError     **error)
{
  guint16 *frame = goodix_cmd_dup_image_reply (dev, error);

  if (!frame)
    g_prefix_error (error, "%s: ", role);
  return frame;
}

static gboolean
goodix_base_parse_fdt (FpDevice *dev,
                       guint8    fdt_base[GOODIX_FDT_BASE_LEN],
                       guint16  *touch_flag,
                       GError  **error)
{
  const guint8 *payload;
  gsize payload_len;

  if (!goodix_cmd_parse_fdt_manual_reply (dev, &payload, &payload_len, error))
    return FALSE;
  if (touch_flag)
    *touch_flag = payload[2] | ((guint16) payload[3] << 8);
  memcpy (fdt_base, payload + 4, GOODIX_FDT_BASE_LEN);
  return TRUE;
}

#ifdef GOODIX53X5_DEBUG
static void goodix_base_timing_start (FpiDeviceGoodix53x5 *self);
static void goodix_base_timing_done (FpiDeviceGoodix53x5 *self,
                                     FpDevice            *dev,
                                     const gchar         *event);
#else
#define goodix_base_timing_start(...) G_STMT_START { } G_STMT_END
#define goodix_base_timing_done(...) G_STMT_START { } G_STMT_END
#endif

static void
goodix_base_complete_recovery (FpiSsm            *ssm,
                               FpDevice          *dev,
                               GoodixBaseSsmData *data,
                               const guint8       fdt_tx_on[GOODIX_FDT_BASE_LEN],
                               guint16            touch_flag,
                               const gchar       *checkpoint)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  goodix_milan_base_attempt_reset (&data->attempt);
  self->profile9_fdt.base_valid = FALSE;
  goodix_device_generate_fdt_base (data->fdt_tx_on_before,
                                   GOODIX_FDT_BASE_LEN,
                                   self->profile9_fdt.base_down);
  memcpy (self->profile9_fdt.base_up, self->profile9_fdt.base_down,
          sizeof (self->profile9_fdt.base_up));
  memcpy (self->profile9_fdt.base_manual, self->profile9_fdt.base_down,
          sizeof (self->profile9_fdt.base_manual));

  if (data->forced_refresh)
    {
      self->profile9_fdt.refresh_outcome =
        GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_VALIDATION_FAILED;
      data->leave_powered = TRUE;
      fp_info ("Profile-9 FDT refresh validation failed at %s", checkpoint);
      goodix_base_timing_done (self, dev, "validation_failed");
      fpi_ssm_mark_completed (ssm);
      return;
    }

  goodix_milan_generation_retain_process (dev);
  memset (&self->profile9_fdt.event, 0, sizeof (self->profile9_fdt.event));
  if (fdt_tx_on)
    {
      self->profile9_fdt.event.touch_flag = touch_flag;
      memcpy (self->profile9_fdt.event.raw, fdt_tx_on, GOODIX_FDT_BASE_LEN);
      self->profile9_fdt.event.pending = TRUE;
    }
  /* Rejection admits recovery without manufacturing a sensor event. */
  self->profile9_fdt.initial_recovery_pending = TRUE;
  data->leave_powered = FALSE;

  fp_info ("Milan base acquisition validation failed at %s (touch_flag=0x%03x)",
           checkpoint, touch_flag & 0x0fff);
  goodix_base_timing_done (self, dev, "validation_failed");
  fpi_ssm_mark_completed (ssm);
}

#ifdef GOODIX53X5_DEBUG
static void
goodix_base_timing_start (FpiDeviceGoodix53x5 *self)
{
  self->debug_timing.ref_capture_started_us = g_get_monotonic_time ();
  self->debug_timing.ref_capture_phase_started_us =
    self->debug_timing.ref_capture_started_us;
}

static void
goodix_base_timing_done (FpiDeviceGoodix53x5 *self,
                         FpDevice            *dev,
                         const gchar         *event)
{
  const gint64 now_us = g_get_monotonic_time ();

  if (self->debug_timing.ref_capture_phase_started_us != 0)
    {
      goodix_debug_timing_log (
        dev, "ref_capture", event,
        now_us - self->debug_timing.ref_capture_phase_started_us,
        NULL);
    }
  if (self->debug_timing.ref_capture_started_us != 0)
    goodix_debug_timing_log (dev, "ref_capture", "total",
                             now_us - self->debug_timing.ref_capture_started_us,
                             NULL);
  self->debug_timing.ref_capture_started_us = 0;
  self->debug_timing.ref_capture_phase_started_us = 0;
}
#endif

/* Native update_allbase exits early before its first manual sample, and runs
 * the first-TX-on FDT postlude on every later ordinary acquisition failure.
 * This result is not permission to destroy the retained image or marker. */
static void
goodix_base_command_result (FpiSsm *ssm, FpDevice *dev, guint8 status,
                            gboolean native_zero, GError *error)
{
  GoodixBaseSsmData *data = fpi_ssm_get_data (ssm);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (!error)
    {
      fpi_ssm_next_state (ssm);
      return;
    }
  if (!native_zero)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fp_dbg ("Reference acquisition returned ordinary failure: %s", error->message);
  g_clear_error (&error);
  if (data->first_fdt_ready)
    {
      goodix_base_complete_recovery (ssm, dev, data, NULL, 0, "acquisition");
    }
  else
    {
      if (data->forced_refresh)
        self->profile9_fdt.refresh_outcome =
          GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_VALIDATION_FAILED;
      else
        self->profile9_fdt.initial_recovery_pending = TRUE;
      fpi_ssm_mark_completed (ssm);
    }
}

static void
goodix_base_health_done (FpDevice *dev,
                         const GoodixHealthMeasurement *measurement,
                         GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  GoodixBaseSsmData *data = fpi_ssm_get_data (ssm);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
    }
  else
    {
      /* The pair owns its frames and lends only these two measurement scalars. */
      data->health_measurement = *measurement;
      fpi_ssm_next_state (ssm);
    }
}

static void
goodix_base_ssm_handler (FpiSsm   *ssm,
                         FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixBaseSsmData *data = fpi_ssm_get_data (ssm);

  g_autoptr(GError) error = NULL;

  if (fpi_ssm_get_cur_state (ssm) < GOODIX_BASE_CLEANUP_SLEEP &&
      goodix_base_check_cancelled (ssm, self, data))
    return;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_BASE_UPLOAD_CONFIG:
      if (!data->forced_refresh)
        {
          goodix_base_timing_start (self);
          fpi_ssm_jump_to_state (ssm, data->manage_ec_power ?
                                 GOODIX_BASE_EC_POWER_ON :
                                 GOODIX_BASE_FDT_TX_ON_BEFORE);
          return;
        }
      else
        {
          goodix_cmd_restore_config (ssm, dev, goodix_base_command_result);
        }
      break;

    case GOODIX_BASE_UPLOAD_CONFIG_DONE:
      goodix_base_timing_start (self);
      fpi_ssm_jump_to_state (ssm, data->manage_ec_power ?
                             GOODIX_BASE_EC_POWER_ON :
                             GOODIX_BASE_FDT_TX_ON_BEFORE);
      break;

    case GOODIX_BASE_EC_POWER_ON:
      goodix_cmd_ec_control (ssm, dev, TRUE);
      break;

    case GOODIX_BASE_EC_POWER_ON_DONE:
      goodix_debug_timing_log (dev, "ref_capture", "ec_power_on",
                               g_get_monotonic_time () -
                               self->debug_timing.ref_capture_phase_started_us,
                               NULL);
      GOODIX53X5_DEBUG_ONLY (
        self->debug_timing.ref_capture_phase_started_us =
          g_get_monotonic_time ();
                            )
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_BASE_FDT_TX_ON_BEFORE:
      data->attempt.stage = GOODIX_MILAN_BASE_STAGE_FDT_TX_ON_BEFORE;
      goodix_cmd_fdt_manual_result (ssm, dev, TRUE,
                                    self->profile9_fdt.base_manual,
                                    goodix_base_command_result);
      break;

    case GOODIX_BASE_FDT_TX_ON_BEFORE_DONE:
      if (!goodix_base_parse_fdt (dev, data->fdt_tx_on_before, NULL, &error))
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      data->first_fdt_ready = TRUE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_BASE_CAPTURE_TX_ON:
      data->attempt.stage = GOODIX_MILAN_BASE_STAGE_CAPTURE_TX_ON;
      goodix_cmd_request_image_result (ssm, dev, TRUE, TRUE, FALSE,
                                       self->calib.dac_l, goodix_base_command_result);
      break;

    case GOODIX_BASE_CAPTURE_TX_ON_DONE:
      {
        g_autofree guint16 *frame =
          goodix_base_decode_reply (dev, "TX-on base", &error);

        if (!frame)
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        goodix_milan_base_attempt_take_frame (&data->attempt, TRUE, &frame,
                                              GOODIX_SENSOR_PIXELS);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_BASE_FDT_TX_OFF:
      data->attempt.stage = GOODIX_MILAN_BASE_STAGE_FDT_TX_OFF;
      goodix_cmd_fdt_manual_result (ssm, dev, FALSE,
                                    self->profile9_fdt.base_manual,
                                    goodix_base_command_result);
      break;

    case GOODIX_BASE_FDT_TX_OFF_DONE:
      if (!goodix_base_parse_fdt (dev, data->fdt_tx_off, NULL, &error))
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      goodix_health_start_pair (dev, GOODIX_HEALTH_PAIR_BASE,
                                goodix_base_health_done, ssm);
      break;

    case GOODIX_BASE_VALIDATE_FDT_PAIR:
      if (!goodix_device_is_fdt_base_valid (data->fdt_tx_on_before,
                                            data->fdt_tx_off,
                                            GOODIX_FDT_BASE_LEN,
                                            self->calib.delta_fdt))
        {
          goodix_base_complete_recovery (
            ssm, dev, data, NULL, 0, "fdt-tx-on/tx-off");
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_BASE_CAPTURE_TX_OFF:
      data->attempt.stage = GOODIX_MILAN_BASE_STAGE_CAPTURE_TX_OFF;
      goodix_cmd_request_image_result (ssm, dev, FALSE, TRUE, FALSE,
                                       self->calib.dac_l, goodix_base_command_result);
      break;

    case GOODIX_BASE_CAPTURE_TX_OFF_DONE:
      {
        g_autofree guint16 *frame =
          goodix_base_decode_reply (dev, "TX-off base", &error);

        if (!frame)
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        goodix_milan_base_attempt_take_frame (&data->attempt, FALSE, &frame,
                                              GOODIX_SENSOR_PIXELS);

        goodix_debug_dump_raw12 ("raw12-ref-txon", data->attempt.tx_on,
                                 GOODIX_SENSOR_PIXELS);
        goodix_debug_dump_raw12 ("raw12-ref", data->attempt.tx_off,
                                 GOODIX_SENSOR_PIXELS);

        if (!goodix_milan_base_attempt_admit (&data->attempt, &error))
          {
            if (error)
              fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            else
              goodix_base_complete_recovery (
                ssm, dev, data, NULL, 0, "tx-on/tx-off");
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_BASE_FDT_TX_ON_AFTER:
      data->attempt.stage = GOODIX_MILAN_BASE_STAGE_FDT_TX_ON_AFTER;
      goodix_cmd_fdt_manual_result (ssm, dev, TRUE,
                                    self->profile9_fdt.base_manual,
                                    goodix_base_command_result);
      break;

    case GOODIX_BASE_FDT_TX_ON_AFTER_DONE:
      {
        guint8 fdt_tx_on_after[GOODIX_FDT_BASE_LEN];
        guint64 generation_id;
        GoodixMilanGeneration *generation = NULL;
        g_autofree guint16 *hardware_reference = NULL;
        guint16 touch_flag;

        if (!goodix_base_parse_fdt (dev, fdt_tx_on_after, &touch_flag, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        if (!goodix_device_is_fdt_base_valid (fdt_tx_on_after,
                                              data->fdt_tx_off,
                                              GOODIX_FDT_BASE_LEN,
                                              self->calib.delta_fdt))
          {
            goodix_base_complete_recovery (
              ssm, dev, data, fdt_tx_on_after, touch_flag, "tx-on-after");
            return;
          }

        /* HAL+0x248 follows every admitted hardware base, even when the engine
         * keeps an older consumed setup after unmarked checkbase recovery. */
        hardware_reference = g_memdup2 (data->attempt.tx_on,
                                        GOODIX_SENSOR_PIXELS * sizeof (guint16));
        if (!goodix_milan_generation_allocate_id (&self->last_milan_generation_id,
                                                  &generation_id, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        /* Native update_allbase derives every FDT base from this first
         * TX-on sample after the complete sequence is admitted. */
        goodix_device_generate_fdt_base (data->fdt_tx_on_before,
                                         GOODIX_FDT_BASE_LEN,
                                         data->candidate_base_down);
        memcpy (data->candidate_base_up, data->candidate_base_down,
                GOODIX_FDT_BASE_LEN);
        memcpy (data->candidate_base_manual, data->candidate_base_down,
                GOODIX_FDT_BASE_LEN);
        data->attempt.stage = GOODIX_MILAN_BASE_STAGE_PUBLISH;
        if (data->forced_refresh && self->milan_generation)
          {
            /* Keep the engine-consumed reference/workspace until delivery. */
            goodix_milan_base_attempt_release_frames (&data->attempt);
          }
        else
          {
            if (!goodix_milan_base_attempt_publish (&data->attempt, generation_id,
                                                    &generation,
                                                    &error))
              {
                fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
                return;
              }

            if (self->milan_retained_generation)
              goodix_milan_generation_transfer_process_state (
                generation, self->milan_retained_generation);
            goodix_milan_generation_invalidate (&self->milan_generation);
            goodix_milan_generation_invalidate (&self->milan_retained_generation);
            self->milan_generation = generation;
          }
        /* Preparation above may fail; publish the admitted tuple only after
         * all owned replacements and the identity have been prepared. */
        g_clear_pointer (&self->hardware_reference, g_free);
        self->hardware_reference = g_steal_pointer (&hardware_reference);
        self->hardware_reference_id = generation_id;
        if (data->forced_refresh &&
            self->profile9_fdt.refresh_reason != GOODIX_PROFILE9_FDT_REFRESH_INVALID_BASE &&
            self->profile9_fdt.refresh_reason != GOODIX_PROFILE9_FDT_REFRESH_UP_INVALID_BASE)
          self->hardware_refresh_pending = TRUE;
        memcpy (self->profile9_fdt.base_down, data->candidate_base_down,
                GOODIX_FDT_BASE_LEN);
        memcpy (self->profile9_fdt.base_up, data->candidate_base_up,
                GOODIX_FDT_BASE_LEN);
        memcpy (self->profile9_fdt.base_manual, data->candidate_base_manual,
                GOODIX_FDT_BASE_LEN);
        /* Native false-down and up/checkbase callers retain the anchor. */
        if (!data->forced_refresh ||
            (self->profile9_fdt.refresh_reason != GOODIX_PROFILE9_FDT_REFRESH_FALSE_DOWN &&
             self->profile9_fdt.refresh_reason != GOODIX_PROFILE9_FDT_REFRESH_UP_INVALID_BASE))
          {
            memset (self->profile9_fdt.drift_anchor, 0,
                    sizeof (self->profile9_fdt.drift_anchor));
            self->profile9_fdt.drift_anchor_empty = TRUE;
          }
        self->profile9_fdt.base_valid = TRUE;
        goodix_health_seed_base (&self->health, &data->health_measurement);
        self->profile9_fdt.event.pending = FALSE;
        self->profile9_fdt.initial_recovery_pending = FALSE;
        if (data->forced_refresh)
          self->profile9_fdt.refresh_outcome =
            GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_PUBLISHED;
        GOODIX53X5_DEBUG_ONLY (
          fp_info ("Admitted Milan generation id=%" G_GUINT64_FORMAT
                   " subtype=%u MAD=%" G_GUINT64_FORMAT,
                   generation_id, self->milan_sensor_subtype,
                   data->attempt.mad);
                              )
        data->leave_powered = TRUE;
        goodix_base_timing_done (self, dev, "base_generation");
        fpi_ssm_mark_completed (ssm);
      }
      break;

    case GOODIX_BASE_CLEANUP_SLEEP:
      /* Cold initialization owns a common firmware-query/sleep tail, even
       * when allbase exits before its first manual sample or rejects a pair.
       * Do not insert a child power transition before that tail. */
      if (data->leave_powered ||
          (!data->forced_refresh && !data->manage_ec_power && !fpi_ssm_get_error (ssm)))
        fpi_ssm_jump_to_state (ssm, GOODIX_BASE_NUM_STATES);
      else
        goodix_cmd_set_sleep_mode (ssm, dev);
      break;

    case GOODIX_BASE_CLEANUP_EC_POWER_OFF:
      /* Keep shutdown best-effort after failures even when the nominal native
       * acquisition path does not own EC power transitions. */
      if (data->manage_ec_power || fpi_ssm_get_error (ssm))
        goodix_cmd_ec_control (ssm, dev, FALSE);
      else
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_BASE_CLEANUP_EC_POWER_OFF_DONE:
      goodix_base_timing_done (self, dev, "cleanup");
      fpi_ssm_mark_completed (ssm);
      break;

    case GOODIX_BASE_NUM_STATES:
      g_assert_not_reached ();
    }
}

static void
goodix_base_ssm_done (FpiSsm   *ssm,
                      FpDevice *dev,
                      GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixBaseSsmData *data = fpi_ssm_get_data (ssm);

  if (data->forced_refresh && error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          self->profile9_fdt.refresh_outcome =
            GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_CANCELLED;
        }
      else
        {
          self->profile9_fdt.refresh_outcome =
            GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_FATAL;
          self->needs_reinit = TRUE;
        }
    }

  if (error)
    fpi_ssm_mark_failed (data->parent_ssm, error);
  else
    fpi_ssm_next_state (data->parent_ssm);
}

static void
goodix_milan_base_start_subsm (FpiSsm                        *parent_ssm,
                               FpDevice                      *dev,
                               gboolean                       forced_refresh,
                               gboolean                       manage_ec_power,
                               GoodixProfile9FdtRefreshReason reason)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixBaseSsmData *data;
  FpiSsm *sub;

  if (forced_refresh)
    {
      self->profile9_fdt.refresh_reason = reason;
      self->profile9_fdt.refresh_outcome =
        GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_IN_PROGRESS;
      self->profile9_fdt.base_valid = FALSE;
    }

  if (self->milan_sensor_subtype != GOODIX_MILAN_VALIDATED_SUBTYPE)
    {
      if (forced_refresh)
        {
          self->profile9_fdt.refresh_outcome =
            GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_FATAL;
          self->needs_reinit = TRUE;
        }
      fpi_ssm_mark_failed (parent_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                     "Native Milan subtype invariant failed for chip 0x%08x subtype %u",
                                                     self->chip_id,
                                                     self->milan_sensor_subtype));
      return;
    }

  if (!forced_refresh && self->milan_generation != NULL)
    {
      fpi_ssm_next_state (parent_ssm);
      return;
    }

  if (!forced_refresh)
    {
      self->profile9_fdt.base_valid = FALSE;
      self->profile9_fdt.initial_recovery_pending = FALSE;
    }
  data = g_new0 (GoodixBaseSsmData, 1);
  data->parent_ssm = parent_ssm;
  data->forced_refresh = forced_refresh;
  data->manage_ec_power = manage_ec_power;
  data->leave_powered = forced_refresh;
  goodix_milan_base_attempt_init (&data->attempt);
  sub = fpi_ssm_new_full (dev, goodix_base_ssm_handler,
                          GOODIX_BASE_NUM_STATES,
                          GOODIX_BASE_CLEANUP_SLEEP,
                          "goodix-milan-base");
  fpi_ssm_set_data (sub, data, (GDestroyNotify) goodix_base_ssm_data_free);
  fpi_ssm_start (sub, goodix_base_ssm_done);
}

void
goodix_milan_base_start_ensure_subsm (FpiSsm   *parent_ssm,
                                      FpDevice *dev,
                                      gboolean  manage_ec_power)
{
  goodix_milan_base_start_subsm (parent_ssm, dev, FALSE, manage_ec_power,
                                 GOODIX_PROFILE9_FDT_REFRESH_NONE);
}

void
goodix_milan_base_start_forced_refresh_subsm (
  FpiSsm                        *parent_ssm,
  FpDevice                      *dev,
  GoodixProfile9FdtRefreshReason reason)
{
  g_return_if_fail (reason != GOODIX_PROFILE9_FDT_REFRESH_NONE);
  goodix_milan_base_start_subsm (parent_ssm, dev, TRUE, FALSE, reason);
}
