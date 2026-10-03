/*
 * Goodix 53x5 driver for libfprint - native Milan verify/identify flow
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
#include "device/auth.h"
#include "milan/print.h"
#include "driver-private.h"
#include "milan/runtime.h"
#include "device/persistence.h"
#include "device/scan.h"
#include "device/session.h"

typedef enum
{
  GOODIX_VERIFY_REINIT = 0,
  GOODIX_VERIFY_REINIT_DONE,
  GOODIX_VERIFY_SCAN,
  GOODIX_VERIFY_FINISH,
  GOODIX_VERIFY_NUM_STATES,
} GoodixVerifyState;

typedef struct
{
  GoodixMilanRuntimeInput *runtime_input;
  GPtrArray               *originals;
  FpiDeviceAction          action;
  guint64                  action_epoch;
  guint64                  generation_id;
  GOODIX53X5_DEBUG_ONLY (GoodixDebugRuntimeMetadata debug_metadata;)
} GoodixAuthTaskData;

#ifdef GOODIX53X5_DEBUG
static const gchar *
goodix_auth_finger_name (FpFinger finger)
{
  static const gchar * const names[] = {
    "unknown", "left-thumb", "left-index", "left-middle", "left-ring",
    "left-little", "right-thumb", "right-index", "right-middle",
    "right-ring", "right-little"
  };

  return (guint) finger < G_N_ELEMENTS (names) ? names[finger] : "unknown";
}

static void
goodix_auth_log_runtime_result (FpDevice                       *dev,
                                GoodixAuthTaskData              *data,
                                const GoodixMilanRuntimeOutput *output,
                                gboolean driver_cancellation_observed)
{
  goodix_debug_log_runtime_result (dev, 0, &data->debug_metadata, output,
                                   driver_cancellation_observed);
}
#else
#define goodix_auth_log_runtime_result(...) G_STMT_START { } G_STMT_END
#endif

static void
goodix_auth_print_unref (gpointer object)
{
  if (object)
    g_object_unref (object);
}

static void
goodix_auth_task_data_free (GoodixAuthTaskData *data)
{
  if (!data)
    return;
  goodix_milan_runtime_input_free (data->runtime_input);
  GOODIX53X5_DEBUG_ONLY (
    goodix_debug_clear_runtime_metadata (&data->debug_metadata);)
  g_clear_pointer (&data->originals, g_ptr_array_unref);
  g_free (data);
}

void
goodix_clear_pending_result_report (FpiDeviceGoodix53x5 *self)
{
  self->pending_result_report = FALSE;
  self->pending_result_action = 0;
  self->pending_verify_result = 0;
  g_clear_object (&self->pending_identify_match);
  g_clear_object (&self->pending_update_target);
  g_clear_pointer (&self->pending_update_data, g_variant_unref);
  g_clear_pointer (&self->pending_persistence_state, g_free);
  g_clear_error (&self->pending_result_error);
  g_clear_error (&self->pending_learning_error);
}

static void
goodix_queue_verify_report (FpiDeviceGoodix53x5 *self,
                             FpiMatchResult       result,
                             GError              *error)
{
  goodix_clear_pending_result_report (self);
  self->pending_result_report = TRUE;
  self->pending_result_action = FPI_DEVICE_ACTION_VERIFY;
  self->pending_verify_result = result;
  self->pending_result_error = error;
}

static void
goodix_queue_identify_report (FpiDeviceGoodix53x5 *self,
                               FpPrint             *match,
                               GError              *error)
{
  goodix_clear_pending_result_report (self);
  self->pending_result_report = TRUE;
  self->pending_result_action = FPI_DEVICE_ACTION_IDENTIFY;
  if (match)
    self->pending_identify_match = g_object_ref (match);
  self->pending_result_error = error;
}

static void
goodix_flush_pending_result_report (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autoptr(GError) learning_error = NULL;

  if (!self->pending_result_report)
    return;

  self->pending_result_report = FALSE;
  learning_error = g_steal_pointer (&self->pending_learning_error);
  if (learning_error)
    fp_warn ("Native Milan learning was discarded after a positive match: %s",
             learning_error->message);

  if (self->pending_result_action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_report (
      dev, self->pending_identify_match, NULL,
      g_steal_pointer (&self->pending_result_error));
  else
    fpi_device_verify_report (
      dev, self->pending_verify_result, NULL,
      g_steal_pointer (&self->pending_result_error));
}

static gboolean
goodix_auth_runtime_cancelled (GoodixMilanRuntimeCheckpoint checkpoint,
                               gsize                        gallery_position,
                               gpointer                     user_data)
{
  (void) checkpoint;
  (void) gallery_position;
  return g_cancellable_is_cancelled (G_CANCELLABLE (user_data));
}

static gboolean
goodix_auth_get_template (FpPrint  *print,
                          GBytes  **template_bytes,
                          GError  **error)
{
  g_autoptr(GVariant) data = NULL;
  FpiPrintType type;

  g_object_get (print, "fpi-type", &type, "fpi-data", &data, NULL);
  if (type != FPI_PRINT_RAW)
    {
      g_set_error_literal (error, GOODIX_MILAN_PRINT_ERROR,
                           GOODIX_MILAN_PRINT_ERROR_INCOMPATIBLE,
                           "Native Milan requires a raw runtime print");
      return FALSE;
    }
  return goodix_milan_print_parse_data (data, template_bytes, error);
}

static void
goodix_auth_worker (GTask        *task,
                    gpointer      source_object,
                    gpointer      task_data,
                    GCancellable *cancellable)
{
  GoodixAuthTaskData *data = task_data;
  GoodixMilanRuntimeOutput *output;

  (void) source_object;
  (void) cancellable;
  output = goodix_milan_runtime_run (data->runtime_input);
  g_task_return_pointer (task, output,
                         (GDestroyNotify) goodix_milan_runtime_output_free);
}

static GVariant *
goodix_auth_build_update (GoodixMilanRuntimeOutput *output)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) data = NULL;

  if (!output->final_candidate)
    return NULL;
  data = goodix_milan_print_build_data (output->final_candidate, &error);
  if (!data)
    {
      if (!output->learning_error)
        output->learning_error = g_steal_pointer (&error);
      return NULL;
    }
  return g_steal_pointer (&data);
}

#ifdef GOODIX53X5_DEBUG
static void
goodix_auth_set_processed_image (FpiDeviceGoodix53x5    *self,
                                 GoodixMilanRuntimeOutput *output)
{
  const guint8 *image;
  gsize size;

  g_clear_pointer (&self->captured_image, g_free);
  image = output->processed_image
            ? g_bytes_get_data (output->processed_image, &size) : NULL;
  if (image && size == GOODIX_SENSOR_PIXELS)
    self->captured_image = g_memdup2 (image, size);
}
#endif

static void
goodix_auth_task_done (GObject      *source_object,
                       GAsyncResult *result,
                       gpointer      user_data)
{
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixAuthTaskData *data = g_task_get_task_data (G_TASK (result));
  g_autoptr(GError) task_error = NULL;
  GoodixMilanRuntimeOutput *output = g_task_propagate_pointer (
    G_TASK (result), &task_error);
  gboolean task_owned;
  gboolean same_action;
  gboolean action_owned;
  gboolean generation_current;
  gboolean cancelled;
  gboolean matched = FALSE;
  GOODIX53X5_DEBUG_ONLY (const gchar *finger_name = "none";)
  GOODIX53X5_DEBUG_ONLY (FpPrint *winner_print = NULL;)
  GOODIX53X5_DEBUG_ONLY (g_autofree gchar *template_features = NULL;)
  GOODIX53X5_DEBUG_ONLY (g_autofree gchar *winner = NULL;)

  (void) user_data;
  task_owned = self->milan_task == G_TASK (result);
  same_action = task_owned &&
                fpi_device_get_current_action (dev) == data->action;
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
        goodix_auth_log_runtime_result (dev, data, output, FALSE);
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
      if (data->action == FPI_DEVICE_ACTION_IDENTIFY)
        goodix_milan_generation_note_identify_prelude (self->milan_generation);
    }
  else if (generation_current && output &&
           output->action_epoch == data->action_epoch &&
           output->generation_id == data->generation_id &&
           output->setup_state_valid)
    {
      /* Setup-save has already happened, even if cancellation discards live
       * processing. Preserve only its three flags, not cancelled gain changes. */
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
        goodix_auth_log_runtime_result (dev, data, output, TRUE);
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
        task_error ? g_steal_pointer (&task_error)
                   : fpi_device_error_new_msg (
                       FP_DEVICE_ERROR_GENERAL,
                       "Native Milan auth task returned invalid output"));
      return;
    }

  GOODIX53X5_DEBUG_ONLY (goodix_auth_set_processed_image (self, output);)
  switch (output->status)
    {
    case GOODIX_MILAN_RUNTIME_MATCH:
      {
        FpPrint *original = output->winner_index < data->originals->len
                              ? g_ptr_array_index (data->originals,
                                                   output->winner_index)
                              : NULL;
        g_autoptr(GVariant) update_data = NULL;

        if (!original)
          {
            goodix_scan_set_disposition (
              dev, GOODIX_SCAN_DISPOSITION_FATAL,
              fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
            goto out;
          }
        update_data = goodix_auth_build_update (output);
        if (data->action == FPI_DEVICE_ACTION_IDENTIFY)
          {
            goodix_debug_dump_probe (data->action, "match",
                                     self->captured_raw_image,
                                     self->captured_image);
            goodix_queue_identify_report (self, original, NULL);
          }
        else
          {
            goodix_debug_dump_probe (data->action, "pass",
                                     self->captured_raw_image,
                                     self->captured_image);
            goodix_queue_verify_report (self, FPI_MATCH_SUCCESS, NULL);
          }
        if (update_data)
          {
            self->pending_update_target = g_object_ref (original);
            self->pending_update_data = g_steal_pointer (&update_data);
            if (output->preprocess_state_valid)
              self->pending_persistence_state = g_memdup2 (
                &output->preprocess_state, sizeof (output->preprocess_state));
          }
        if (output->learning_error)
          self->pending_learning_error = g_error_copy (output->learning_error);
        matched = TRUE;
      }
      break;

    case GOODIX_MILAN_RUNTIME_NO_MATCH:
      if (data->action == FPI_DEVICE_ACTION_IDENTIFY)
        {
          goodix_debug_dump_probe (data->action, "miss",
                                   self->captured_raw_image,
                                   self->captured_image);
          goodix_queue_identify_report (self, NULL, NULL);
        }
      else
        {
          goodix_debug_dump_probe (data->action, "fail",
                                   self->captured_raw_image,
                                   self->captured_image);
          goodix_queue_verify_report (self, FPI_MATCH_FAIL, NULL);
        }
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_AUTH_RETRY_AFTER_UP, NULL);
      break;

    case GOODIX_MILAN_RUNTIME_RETRY:
      goodix_debug_dump_probe (data->action, "weak",
                               self->captured_raw_image,
                               self->captured_image);
      if (data->action == FPI_DEVICE_ACTION_IDENTIFY)
        goodix_queue_identify_report (
          self, NULL,
          fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
      else
        goodix_queue_verify_report (
          self, FPI_MATCH_ERROR,
          fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_AUTH_RETRY_AFTER_UP, NULL);
      break;

    case GOODIX_MILAN_RUNTIME_INVALID_DATA:
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      break;

    case GOODIX_MILAN_RUNTIME_CANCELLED:
      g_assert_not_reached ();
    }

  goodix_auth_log_runtime_result (dev, data, output, FALSE);
  GOODIX53X5_DEBUG_ONLY (
    winner = goodix_debug_format_winner (output->winner_index,
                                         output->winner_position);
    template_features = goodix_debug_format_template_features (output);
    if (output->winner_index < data->originals->len)
      winner_print = g_ptr_array_index (data->originals, output->winner_index);
    if (winner_print)
      finger_name = goodix_auth_finger_name (
        fp_print_get_finger (winner_print));

    fp_dbg ("Native Milan %s status=%s(%u) score=%d finger=%s winner=%s "
            "study=%s(%u) template_features=%s quality=%d coverage=%d",
            data->action == FPI_DEVICE_ACTION_IDENTIFY ? "identify" : "verify",
            goodix_debug_runtime_status_name (output->status),
            (guint) output->status, output->score, finger_name, winner,
            goodix_debug_study_action_name (output->study_action),
            (guint) output->study_action,
            template_features, output->quality, output->coverage);)
out:
  goodix_milan_runtime_output_free (output);
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  /* The coordinator hands the action back as soon as this join settles;
   * the report itself is delivered by goodix_verify_complete. */
  if (matched)
    goodix_scan_set_disposition (
      dev, GOODIX_SCAN_DISPOSITION_AUTH_SUCCESS, NULL);
}

static void
goodix_auth_start_task (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  g_autoptr(GPtrArray) runtime_gallery = g_ptr_array_new_with_free_func (
    (GDestroyNotify) goodix_milan_runtime_gallery_input_free);
  GoodixAuthTaskData *task_data = g_new0 (GoodixAuthTaskData, 1);
  GPtrArray *gallery = NULL;
  guint invalid_count = 0;

  task_data->action = action;
  task_data->action_epoch = self->action_epoch;
  if (!self->milan_generation || !self->captured_raw_image || self->milan_task)
    {
      goodix_auth_task_data_free (task_data);
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "Native Milan auth input is missing or busy"));
      return;
    }
  task_data->generation_id = self->milan_generation->generation_id;
  GOODIX53X5_DEBUG_ONLY (
    goodix_debug_capture_runtime_metadata (
      &task_data->debug_metadata, action,
      self->milan_generation->setup_tx_on, self->captured_raw_image,
      self->milan_generation->use_count,
      self->milan_generation->profile_state.setup_initialized,
      self->milan_generation->profile_state.setup_refresh_pending,
      self->milan_generation->profile_state.setup_not_ready);)

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print = NULL;
      g_autoptr(GBytes) template_bytes = NULL;
      g_autoptr(GError) error = NULL;

      task_data->originals = g_ptr_array_new_with_free_func (
        goodix_auth_print_unref);
      fpi_device_get_verify_data (dev, &print);
      if (!goodix_auth_get_template (print, &template_bytes, &error))
        {
          goodix_auth_task_data_free (task_data);
          goodix_scan_set_disposition (
            dev, GOODIX_SCAN_DISPOSITION_FATAL,
            fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return;
        }
      g_ptr_array_add (task_data->originals, g_object_ref (print));
      g_ptr_array_add (runtime_gallery,
                       goodix_milan_runtime_gallery_input_new (0, template_bytes));
    }
  else
    {
      fpi_device_get_identify_data (dev, &gallery);
      task_data->originals = g_ptr_array_new_with_free_func (
        goodix_auth_print_unref);
      g_ptr_array_set_size (task_data->originals, gallery->len);
      for (guint i = 0; i < gallery->len; i++)
        {
          FpPrint *print = g_ptr_array_index (gallery, i);
          g_autoptr(GBytes) template_bytes = NULL;
          g_autoptr(GError) error = NULL;

          if (!goodix_auth_get_template (print, &template_bytes, &error))
            {
              invalid_count++;
              fp_warn ("Skipping invalid Milan identify gallery entry %u", i);
              continue;
            }
          task_data->originals->pdata[i] = g_object_ref (print);
          g_ptr_array_add (runtime_gallery,
                           goodix_milan_runtime_gallery_input_new (
                             i, template_bytes));
        }
      if (gallery->len > 0 && runtime_gallery->len == 0 && invalid_count > 0)
        {
          goodix_auth_task_data_free (task_data);
          goodix_scan_set_disposition (
            dev, GOODIX_SCAN_DISPOSITION_FATAL,
            fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return;
        }
    }

  task_data->runtime_input = goodix_milan_runtime_input_new (
    task_data->action_epoch, task_data->generation_id,
    GOODIX_MILAN_PURPOSE_IDENTIFY, &self->milan_generation->state,
    &self->milan_generation->profile_state,
    self->milan_generation->setup_tx_on, self->captured_raw_image,
    self->calib.tcode, self->calib.dac_h, self->calib.dac_l,
    self->milan_sensor_subtype,
    (GoodixMilanRuntimeGalleryInput *const *) runtime_gallery->pdata,
    runtime_gallery->len);
  if (!task_data->runtime_input)
    {
      goodix_auth_task_data_free (task_data);
      goodix_scan_set_disposition (
        dev, GOODIX_SCAN_DISPOSITION_FATAL,
        fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }
  goodix_milan_persistence_bind_setup (task_data->runtime_input,
                                      self->milan_generation);
  goodix_milan_runtime_input_set_capture_health (task_data->runtime_input,
                                                 self->captured_enroll_allowed);
  goodix_milan_runtime_input_set_cancel_check (
    task_data->runtime_input, goodix_auth_runtime_cancelled,
    g_object_ref (self->cancel), g_object_unref);
  g_autoptr(GTask) task = g_task_new (dev, self->cancel,
                                       goodix_auth_task_done, NULL);
  /* Runtime cancellation still suppresses results. Keep the joined output so
   * an entered setup publication can retain its independent state flags. */
  g_task_set_check_cancellable (task, FALSE);
  g_task_set_task_data (task, task_data,
                        (GDestroyNotify) goodix_auth_task_data_free);
  self->milan_task = g_object_ref (task);
  g_task_run_in_thread (task, goodix_auth_worker);
}

static void
goodix_auth_capture_ready (FpDevice *dev,
                           gpointer  user_data)
{
  (void) user_data;
  goodix_auth_start_task (dev);
}

static void
goodix_verify_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_VERIFY_REINIT:
      if (!goodix_maybe_start_reinit_subsm (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;
    case GOODIX_VERIFY_REINIT_DONE:
      goodix_debug_timing_open_done (self, dev, "reinit");
      self->needs_reinit = FALSE;
      fpi_ssm_next_state (ssm);
      break;
    case GOODIX_VERIFY_SCAN:
      goodix_scan_start_coordinator_subsm (
        ssm, dev, goodix_auth_capture_ready, NULL, NULL);
      break;
    case GOODIX_VERIFY_FINISH:
      fpi_ssm_mark_completed (ssm);
      break;
    case GOODIX_VERIFY_NUM_STATES:
      g_assert_not_reached ();
    }
}

static void
goodix_verify_complete (FpDevice *dev,
                        GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  gboolean updated = FALSE;
  gboolean removed = FALSE;
  gboolean cancelled;

#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);

  g_object_get (dev, "removed", &removed, NULL);
  cancelled = fpi_device_action_is_cancelled (dev) ||
              (self->cancel && g_cancellable_is_cancelled (self->cancel));
  if (!error && cancelled)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Authentication cancelled");
  if (!error && removed)
    error = fpi_device_error_new (FP_DEVICE_ERROR_REMOVED);
  if (!error && !self->pending_result_report)
    error = fpi_device_error_new_msg (
      FP_DEVICE_ERROR_GENERAL,
      "Native Milan auth completed without a result");
  if (!error)
    {
      /* Adaptive update and its persistence publish with the result, before
       * the application learns of the match. */
      if (self->pending_update_target && self->pending_update_data)
        {
          fpi_print_set_raw_data (self->pending_update_target,
                                  self->pending_update_data);
          updated = TRUE;
          goodix_milan_persistence_save (dev, self->pending_persistence_state);
        }
      goodix_flush_pending_result_report (dev);
    }
  goodix_clear_pending_result_report (self);

  if (error && goodix_error_indicates_stale_device (error))
    self->needs_reinit = TRUE;
  goodix_debug_timing_action_done (self, dev,
                                   error ? error->message : NULL);
  if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_complete_with_update (dev, updated, error);
  else
    fpi_device_verify_complete_with_update (dev, updated, error);
}

static void
goodix_verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  goodix_session_action_done (dev, error, goodix_verify_complete);
}

void
goodix_auth_start (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  goodix_clear_pending_result_report (self);
  self->action_epoch++;
  if (self->action_epoch == 0)
    self->action_epoch++;
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  goodix_debug_timing_action_start (self, dev, NULL);

  ssm = fpi_ssm_new (dev, goodix_verify_ssm_handler,
                     GOODIX_VERIFY_NUM_STATES);
  fpi_ssm_start (ssm, goodix_verify_ssm_done);
}
