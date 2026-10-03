/*
 * Goodix 53x5 driver for libfprint - native Milan enrollment flow
 * Copyright (C) 2024-2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "fpi-print.h"
#include "device/enroll.h"
#include "milan/match/match.h"
#include "milan/print.h"
#include "driver-private.h"
#include "milan/runtime.h"
#include "device/persistence.h"
#include "device/scan.h"
#include "device/session.h"

typedef enum {
  GOODIX_ENROLL_REINIT = 0,
  GOODIX_ENROLL_REINIT_DONE,
  GOODIX_ENROLL_SCAN,
  GOODIX_ENROLL_FINISH,
  GOODIX_ENROLL_NUM_STATES,
} GoodixEnrollState;

typedef struct
{
  GoodixMilanRuntimeInput *runtime_input;
  guint64                  action_epoch;
  guint64                  generation_id;
  guint                    stage;
  GOODIX53X5_DEBUG_ONLY (GoodixDebugRuntimeMetadata debug_metadata;
                        )
} GoodixEnrollTaskData;

#ifdef GOODIX53X5_DEBUG
static void
goodix_enroll_log_runtime_result (FpDevice                       *dev,
                                  GoodixEnrollTaskData           *data,
                                  const GoodixMilanRuntimeOutput *output,
                                  gboolean                        driver_cancellation_observed)
{
  goodix_debug_log_runtime_result (dev, data->stage + 1,
                                   &data->debug_metadata, output,
                                   driver_cancellation_observed);
}
#else
#define goodix_enroll_log_runtime_result(...) G_STMT_START { } G_STMT_END
#endif

static void
goodix_enroll_task_data_free (GoodixEnrollTaskData *data)
{
  if (!data)
    return;
  goodix_milan_runtime_input_free (data->runtime_input);
  GOODIX53X5_DEBUG_ONLY (
    goodix_debug_clear_runtime_metadata (&data->debug_metadata);
                        )
  g_free (data);
}

static gboolean
goodix_enroll_runtime_cancelled (GoodixMilanRuntimeCheckpoint checkpoint,
                                 gsize                        gallery_position,
                                 gpointer                     user_data)
{
  (void) checkpoint;
  (void) gallery_position;
  return g_cancellable_is_cancelled (G_CANCELLABLE (user_data));
}

static void
goodix_enroll_worker (GTask        *task,
                      gpointer      source_object,
                      gpointer      task_data,
                      GCancellable *cancellable)
{
  GoodixEnrollTaskData *data = task_data;

  (void) source_object;
  (void) cancellable;
  g_task_return_pointer (
    task, goodix_milan_runtime_run (data->runtime_input),
    (GDestroyNotify) goodix_milan_runtime_output_free);
}

#ifdef GOODIX53X5_DEBUG
static void
goodix_enroll_set_processed_image (FpiDeviceGoodix53x5      *self,
                                   GoodixMilanRuntimeOutput *output)
{
  const guint8 *image;
  gsize size;

  g_clear_pointer (&self->captured_image, g_free);
  image = output->processed_image ?
          g_bytes_get_data (output->processed_image, &size) : NULL;
  if (image && size == GOODIX_SENSOR_PIXELS)
    self->captured_image = g_memdup2 (image, size);
}
#endif

static void
goodix_enroll_task_done (GObject      *source_object,
                         GAsyncResult *result,
                         gpointer      user_data)
{
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixEnrollTaskData *data = g_task_get_task_data (G_TASK (result));

  g_autoptr(GError) task_error = NULL;
  GoodixMilanRuntimeOutput *output = g_task_propagate_pointer (
    G_TASK (result), &task_error);
  gboolean task_owned;
  gboolean same_action;
  gboolean action_owned;
  gboolean generation_current;
  gboolean cancelled;
  gboolean enrollment_admitted;
  GoodixMilanEnrollmentAttemptStatus enrollment_status =
    GOODIX_MILAN_ENROLLMENT_RETRY_REMOVE;
  GoodixMilanEnrollmentResult enrollment_result = { 0 };

  (void) user_data;
  task_owned = self->milan_task == G_TASK (result);
  same_action = task_owned &&
                fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL &&
                self->enroll_stage == (gint) data->stage;
  cancelled = same_action &&
              (fpi_device_action_is_cancelled (dev) ||
               !self->cancel || g_cancellable_is_cancelled (self->cancel) ||
               (output && output->status == GOODIX_MILAN_RUNTIME_CANCELLED) ||
               (task_error && g_error_matches (task_error, G_IO_ERROR,
                                               G_IO_ERROR_CANCELLED)));
  action_owned = same_action &&
                 (self->action_epoch == data->action_epoch || cancelled);
  generation_current = action_owned && self->milan_generation &&
                       self->milan_generation->generation_id ==
                       data->generation_id;
  if (task_owned)
    g_clear_object (&self->milan_task);

  if (!action_owned)
    {
      if (output)
        goodix_enroll_log_runtime_result (dev, data, output, FALSE);
      goodix_milan_runtime_output_free (output);
      g_clear_pointer (&self->captured_raw_image, g_free);
      if (task_owned && self->profile9_fdt.owner)
        goodix_scan_set_disposition (dev, GOODIX_SCAN_DISPOSITION_CANCELLED,
                                     NULL);
      return;
    }

  if (generation_current && output &&
      output->action_epoch == data->action_epoch &&
      output->generation_id == data->generation_id &&
      output->preprocess_state_valid && !cancelled)
    {
      self->milan_generation->state = output->preprocess_state;
      self->milan_generation->profile_state = output->profile_state;
    }
  else if (generation_current && output &&
           output->action_epoch == data->action_epoch &&
           output->generation_id == data->generation_id &&
           output->setup_state_valid)
    {
      self->milan_generation->profile_state.setup_initialized =
        output->profile_state.setup_initialized;
      self->milan_generation->profile_state.setup_refresh_pending =
        output->profile_state.setup_refresh_pending;
      self->milan_generation->profile_state.setup_not_ready =
        output->profile_state.setup_not_ready;
    }

  if (cancelled)
    {
      if (output)
        goodix_enroll_log_runtime_result (dev, data, output, TRUE);
      goodix_milan_runtime_output_free (output);
      g_clear_pointer (&self->captured_raw_image, g_free);
      goodix_scan_set_disposition (dev, GOODIX_SCAN_DISPOSITION_CANCELLED,
                                   NULL);
      return;
    }

  if (!output || task_error ||
      output->action_epoch != data->action_epoch ||
      output->generation_id != data->generation_id)
    {
      goodix_milan_runtime_output_free (output);
      g_clear_pointer (&self->captured_raw_image, g_free);
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        task_error ? g_steal_pointer (&task_error) :
        fpi_device_error_new_msg (
          FP_DEVICE_ERROR_GENERAL,
          "Native Milan enrollment task returned invalid output"));
      return;
    }

  GOODIX53X5_DEBUG_ONLY (goodix_enroll_set_processed_image (self, output);
                        )
  enrollment_admitted = goodix_milan_runtime_enrollment_admitted (output);
  /* Native non-policy merge failures break an unsaturated rollback streak,
   * including extraction that succeeds with no records to insert. Sample
   * quality/preprocessing rejection never enters that merge boundary. */
  if (output->enrollment_sample_admitted && !enrollment_admitted &&
      self->enroll_bad_continue_count < 3)
    self->enroll_bad_continue_count = 0;

  if (enrollment_admitted)
    {
      enrollment_status = goodix_milan_enrollment_transaction_attempt (
        &self->enroll_transaction, output->probe_template,
        &self->enroll_bad_record_count, &self->enroll_bad_continue_count,
        &enrollment_result);
      if (enrollment_status == GOODIX_MILAN_ENROLLMENT_RETRY_REMOVE)
        fp_dbg ("Native Milan enrollment retry stage %u: relation/combine "
                "failed",
                data->stage + 1);
    }

  if (enrollment_admitted &&
      enrollment_status == GOODIX_MILAN_ENROLLMENT_ACCEPTED)
    {
      GOODIX53X5_DEBUG_ONLY (
        g_autofree gchar * prefix = g_strdup_printf (
          "enroll-stage-%u", data->stage + 1);

        goodix_debug_dump_pair (prefix, self->captured_raw_image,
                                self->captured_image);
                            )
      self->enroll_stage = (gint) goodix_milan_enrollment_transaction_count (
        self->enroll_transaction);
      g_clear_pointer (&self->pending_persistence_state, g_free);
      /* Only final publication consumes this snapshot; every attempt already
       * installed its valid preprocessing mutations into the live generation. */
      if (self->enroll_stage == GOODIX_ENROLL_SAMPLES &&
          output->preprocess_state_valid)
        self->pending_persistence_state = g_memdup2 (
          &output->preprocess_state, sizeof (output->preprocess_state));
      GOODIX53X5_DEBUG_ONLY (
        fp_dbg ("Native Milan enrollment stage %d/%d quality=%d coverage=%d "
                "records=%u partitions=%u/%u",
                self->enroll_stage, GOODIX_ENROLL_SAMPLES, output->quality,
                output->coverage, output->probe_record_count,
                output->probe_partition0_count,
                output->probe_partition1_count);
                            )
      self->pending_enroll_progress = TRUE;
      self->pending_enroll_stage = self->enroll_stage;
      g_clear_error (&self->pending_enroll_error);
    }
  else if (enrollment_admitted &&
           enrollment_status == GOODIX_MILAN_ENROLLMENT_RETRY_CENTER)
    {
      GOODIX53X5_DEBUG_ONLY (
        fp_dbg ("Native Milan enrollment rollback stage %u: overlap=%d/%d "
                "detail=%u",
                data->stage + 1, enrollment_result.previous_overlap,
                enrollment_result.overlap, enrollment_result.reject_detail);
                            )
      self->pending_enroll_progress = TRUE;
      self->pending_enroll_stage = self->enroll_stage;
      g_clear_error (&self->pending_enroll_error);
      self->pending_enroll_error =
        fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
    }
  else if (enrollment_admitted &&
           enrollment_status == GOODIX_MILAN_ENROLLMENT_RETRY_REMOVE)
    {
      GOODIX53X5_DEBUG_ONLY (
        g_autofree gchar * prefix = g_strdup_printf (
          "enroll-retry-stage-%u-relation-combine", data->stage + 1);

        goodix_debug_dump_pair (prefix, self->captured_raw_image,
                                self->captured_image);
                            )
      self->pending_enroll_progress = TRUE;
      self->pending_enroll_stage = self->enroll_stage;
      g_clear_error (&self->pending_enroll_error);
      self->pending_enroll_error =
        fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);
    }
  else if (output->status == GOODIX_MILAN_RUNTIME_RETRY ||
           output->preprocess_state_valid)
    {
      GOODIX53X5_DEBUG_ONLY (
        const gchar * reason = output->status == GOODIX_MILAN_RUNTIME_RETRY ?
                               "extract" : "quality";
        g_autofree gchar *prefix = g_strdup_printf (
          "enroll-retry-stage-%u-%s", data->stage + 1, reason);

        goodix_debug_dump_pair (prefix, self->captured_raw_image,
                                self->captured_image);
                            )
      self->pending_enroll_progress = TRUE;
      self->pending_enroll_stage = self->enroll_stage;
      g_clear_error (&self->pending_enroll_error);
      self->pending_enroll_error = fpi_device_retry_new (
        output->coverage < GOODIX_MILAN_ENROLL_MIN_COVERAGE ?
        FP_DEVICE_RETRY_CENTER_FINGER : FP_DEVICE_RETRY_REMOVE_FINGER);
    }
  else
    {
      GError *error = fpi_device_error_new_msg (
        FP_DEVICE_ERROR_GENERAL, "Native Milan enrollment extraction failed");

      goodix_enroll_log_runtime_result (dev, data, output, FALSE);
      goodix_milan_runtime_output_free (output);
#ifdef GOODIX53X5_DEBUG
      g_clear_pointer (&self->captured_image, g_free);
#endif
      g_clear_pointer (&self->captured_raw_image, g_free);
      goodix_scan_set_disposition (dev, GOODIX_SCAN_DISPOSITION_FATAL, error);
      return;
    }

  goodix_enroll_log_runtime_result (dev, data, output, FALSE);
  goodix_milan_runtime_output_free (output);
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  goodix_scan_set_disposition (
    dev,
    self->enroll_stage >= GOODIX_ENROLL_SAMPLES ?
    GOODIX_SCAN_DISPOSITION_ENROLL_FINAL_AFTER_UP :
    GOODIX_SCAN_DISPOSITION_ENROLL_CONTINUE_AFTER_UP,
    NULL);
}

static void
goodix_enroll_start_task (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixEnrollTaskData *data = g_new0 (GoodixEnrollTaskData, 1);

  g_autoptr(GTask) task = NULL;

  if (!self->milan_generation || !self->captured_raw_image || self->milan_task)
    {
      g_free (data);
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        fpi_device_error_new_msg (
          FP_DEVICE_ERROR_GENERAL,
          "Native Milan enrollment input is missing or busy"));
      return;
    }
  data->action_epoch = self->action_epoch;
  data->generation_id = self->milan_generation->generation_id;
  data->stage = self->enroll_stage;
  GOODIX53X5_DEBUG_ONLY (
    goodix_debug_capture_runtime_metadata (
      &data->debug_metadata, FPI_DEVICE_ACTION_ENROLL,
      self->milan_generation->setup_tx_on, self->captured_raw_image,
      self->milan_generation->use_count,
      self->milan_generation->profile_state.setup_initialized,
      self->milan_generation->profile_state.setup_refresh_pending,
      self->milan_generation->profile_state.setup_not_ready);
                        )
  data->runtime_input = goodix_milan_runtime_input_new (
    data->action_epoch, data->generation_id, GOODIX_MILAN_PURPOSE_ENROLL,
    &self->milan_generation->state,
    &self->milan_generation->profile_state,
    self->milan_generation->setup_tx_on,
    self->captured_raw_image, self->calib.tcode, self->calib.dac_h,
    self->calib.dac_l, self->milan_sensor_subtype, NULL, 0);
  if (!data->runtime_input)
    {
      goodix_enroll_task_data_free (data);
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }
  goodix_milan_persistence_bind_setup (data->runtime_input,
                                      self->milan_generation);
  goodix_milan_runtime_input_set_capture_health (data->runtime_input,
                                                 self->captured_enroll_allowed);
  goodix_milan_runtime_input_set_cancel_check (
    data->runtime_input, goodix_enroll_runtime_cancelled,
    g_object_ref (self->cancel), g_object_unref);
  task = g_task_new (dev, self->cancel, goodix_enroll_task_done, NULL);
  g_task_set_check_cancellable (task, FALSE);
  g_task_set_task_data (task, data,
                        (GDestroyNotify) goodix_enroll_task_data_free);
  self->milan_task = g_object_ref (task);
  g_task_run_in_thread (task, goodix_enroll_worker);
}

static void
goodix_enroll_capture_ready (FpDevice *dev,
                             gpointer  user_data)
{
  (void) user_data;
  goodix_enroll_start_task (dev);
}

static void
goodix_enroll_cycle_settled (FpDevice             *dev,
                             GoodixScanDisposition disposition,
                             gpointer              user_data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  (void) disposition;
  (void) user_data;
  if (!self->pending_enroll_progress)
    return;

  self->pending_enroll_progress = FALSE;
  fpi_device_enroll_progress (dev, self->pending_enroll_stage, NULL,
                              g_steal_pointer (&self->pending_enroll_error));
}

static void
goodix_enroll_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_ENROLL_REINIT:
      if (!goodix_maybe_start_reinit_subsm (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_ENROLL_REINIT_DONE:
      goodix_debug_timing_open_done (self, dev, "reinit");
      self->needs_reinit = FALSE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_ENROLL_SCAN:
      goodix_scan_start_coordinator_subsm (
        ssm, dev, goodix_enroll_capture_ready,
        goodix_enroll_cycle_settled, NULL);
      break;

    case GOODIX_ENROLL_FINISH:
      fpi_ssm_mark_completed (ssm);
      break;

    case GOODIX_ENROLL_NUM_STATES:
      g_assert_not_reached ();
    }
}

static void
goodix_enroll_complete (FpDevice *dev,
                        GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpPrint *print = NULL;

  g_autoptr(GBytes) combined = NULL;
  g_autoptr(GVariant) data = NULL;

#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);

  if (error)
    {
      if (goodix_error_indicates_stale_device (error))
        self->needs_reinit = TRUE;
      self->pending_enroll_progress = FALSE;
      g_clear_error (&self->pending_enroll_error);
      g_clear_pointer (&self->enroll_transaction,
                       goodix_milan_enrollment_transaction_free);
      g_clear_pointer (&self->pending_persistence_state, g_free);
      goodix_debug_timing_action_done (self, dev, error->message);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  if (self->enroll_stage != GOODIX_ENROLL_SAMPLES ||
      !self->enroll_transaction ||
      goodix_milan_enrollment_transaction_count (
        self->enroll_transaction) != GOODIX_ENROLL_SAMPLES ||
      !self->pending_persistence_state)
    {
      GError *chronology_error = fpi_device_error_new_msg (
        FP_DEVICE_ERROR_GENERAL,
        "Native Milan enrollment action state is incomplete");

      g_clear_pointer (&self->enroll_transaction,
                       goodix_milan_enrollment_transaction_free);
      g_clear_pointer (&self->pending_persistence_state, g_free);
      fpi_device_enroll_complete (dev, NULL, chronology_error);
      return;
    }

  combined = goodix_milan_enrollment_transaction_publish (
    self->enroll_transaction);
  if (combined)
    data = goodix_milan_print_build_data (combined, &error);
  if (!combined || !data)
    {
      g_clear_pointer (&self->enroll_transaction,
                       goodix_milan_enrollment_transaction_free);
      g_clear_pointer (&self->pending_persistence_state, g_free);
      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                          "Failed to build native Milan template");
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  g_clear_pointer (&self->enroll_transaction,
                   goodix_milan_enrollment_transaction_free);
  fp_info ("Native Milan enrollment complete with %d stages",
           GOODIX_ENROLL_SAMPLES);
  goodix_milan_persistence_save (dev, self->pending_persistence_state);
  g_clear_pointer (&self->pending_persistence_state, g_free);
  goodix_debug_timing_action_done (self, dev, NULL);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
goodix_enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  goodix_session_action_done (dev, error, goodix_enroll_complete);
}

void
goodix_enroll_start (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  self->action_epoch++;
  if (self->action_epoch == 0)
    self->action_epoch++;
  self->enroll_stage = 0;
  g_clear_pointer (&self->enroll_transaction,
                   goodix_milan_enrollment_transaction_free);
  self->enroll_transaction = goodix_milan_enrollment_transaction_new ();
  self->enroll_bad_record_count = 0;
  self->enroll_bad_continue_count = 0;
  self->pending_enroll_progress = FALSE;
  self->pending_enroll_stage = 0;
  g_clear_error (&self->pending_enroll_error);
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  g_clear_pointer (&self->pending_persistence_state, g_free);
  if (!self->enroll_transaction)
    {
      goodix_session_action_done (
        dev, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL), goodix_enroll_complete);
      return;
    }
  goodix_debug_timing_action_start (self, dev, NULL);

  ssm = fpi_ssm_new (dev, goodix_enroll_ssm_handler,
                     GOODIX_ENROLL_NUM_STATES);
  fpi_ssm_start (ssm, goodix_enroll_ssm_done);
}
