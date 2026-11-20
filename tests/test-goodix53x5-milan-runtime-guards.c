/*
 * Goodix 53x5 driver for libfprint - current Milan runtime contracts
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-runtime-support.h"

static void
replace_generation (FpiDeviceGoodix53x5 *self)
{
  guint64 generation_id = self->last_milan_generation_id + 1;
  g_autofree guint16 *live = g_new (guint16, PIXELS);

  goodix_milan_generation_invalidate (&self->milan_generation);
  self->last_milan_generation_id = generation_id;
  self->milan_generation = g_new0 (GoodixMilanGeneration, 1);
  self->milan_generation->generation_id = generation_id;
  self->milan_generation->admitted = TRUE;
  self->milan_generation->setup_tx_on = g_new (guint16, PIXELS);
  generate_frames (self->milan_generation->setup_tx_on, live, 0);
  goodix_milan_preprocess_reset (&self->milan_generation->state);
}

void
test_cancellation_no_publication (void)
{
  static const gint32 positive[] = { 37 };

  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(GBytes) stored = generate_template (0);
  g_autoptr(GBytes) update = generate_template (1);
  GBytes *templates[] = { stored };
  g_autoptr(FpPrint) print = make_print (device, stored);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
  AsyncResult result = { 0 };
  guint32 sample_count = self->milan_generation->state.sample_count;
  guint64 action_epoch;

  reset_plan (positive, templates, G_N_ELEMENTS (positive), update);
  pause_before_capture = TRUE;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  fp_device_verify (device, print, cancel, match_report, &result, NULL,
                    verify_done, &result);
  wait_paused ();
  GCancellable *action_cancel = fpi_device_get_cancellable (device);
  g_assert_true (G_IS_CANCELLABLE (action_cancel));
  g_assert_true (action_cancel != self->cancel);
  g_assert_false (g_cancellable_is_cancelled (action_cancel));
  g_cancellable_cancel (cancel);
  g_assert_true (g_cancellable_is_cancelled (action_cancel));
  fpi_ssm_mark_failed (paused_ssm, g_error_new_literal (
                         G_IO_ERROR, G_IO_ERROR_CANCELLED, "early cancellation"));
  paused_ssm = NULL;
  pause_before_capture = FALSE;
  wait_done (&result);
  g_assert_cmpuint (result.reports, ==, 0);
  g_assert_false (result.updated);
  g_assert_cmpuint (plan.match_calls, ==, 0);
  g_assert_cmpuint (self->milan_generation->state.sample_count, ==,
                    sample_count);
  clear_result (&result);

  reset_plan (positive, templates, G_N_ELEMENTS (positive), update);
  plan.block_study = TRUE;
  cancel = g_cancellable_new ();
  fp_device_verify (device, print, cancel, match_report, &result, NULL,
                    verify_done, &result);
  wait_study ();
  action_epoch = self->action_epoch;
  g_cancellable_cancel (cancel);
  wait_cancelled ();
  g_assert_cmpuint (self->action_epoch, ==, action_epoch + 1);
  release_study ();
  wait_done (&result);
  g_assert_cmpuint (result.reports, ==, 0);
  g_assert_false (result.updated);
  g_assert_cmpuint (plan.match_calls, ==, 1);
  g_assert_cmpuint (plan.study_calls, ==, 1);
  g_assert_cmpuint (self->milan_generation->state.sample_count, ==,
                    sample_count);
  clear_result (&result);

  /* A positive result and its update are retained until the action completes;
   * the report and the completion are delivered together. */
  reset_plan (positive, templates, G_N_ELEMENTS (positive), update);
  pause_cycle_settled = TRUE;
  cancel = g_cancellable_new ();
  fp_device_verify (device, print, cancel, match_report, &result, NULL,
                    verify_done, &result);
  wait_paused ();
  g_assert_true (self->pending_result_report);
  g_assert_cmpuint (result.reports, ==, 0);
  g_assert_cmpuint (result.completions, ==, 0);
  g_assert_true (self->pending_update_target == print);
  g_assert_nonnull (self->pending_update_data);
  g_autoptr(GBytes) pending = get_print_template (print);
  g_assert_true (g_bytes_equal (pending, stored));
  fpi_ssm_mark_completed (paused_ssm);
  paused_ssm = NULL;
  pause_cycle_settled = FALSE;
  wait_done (&result);
  g_assert_cmpuint (result.reports, ==, 1);
  g_assert_cmpuint (result.completions, ==, 1);
  g_assert_true (result.success);
  g_assert_true (result.matched);
  g_assert_true (result.updated);
  g_autoptr(GBytes) updated = get_print_template (print);
  g_assert_true (g_bytes_equal (updated, update));
  g_assert_false (self->pending_result_report);
  g_assert_null (self->pending_update_target);
  g_assert_null (self->pending_update_data);
  /* Client cleanup after the completed report changes nothing. */
  g_cancellable_cancel (cancel);
  clear_result (&result);
  close_device (device);
}

typedef enum {
  STALE_ACTION_EPOCH,
  STALE_GENERATION,
  STALE_TASK_AND_SSM,
} StaleKind;

void
test_stale_result_guards (void)
{
  static const gint32 positive[] = { 37 };
  static const StaleKind rows[] = {
    STALE_ACTION_EPOCH,
    STALE_GENERATION,
    STALE_TASK_AND_SSM,
  };

  for (gsize row = 0; row < G_N_ELEMENTS (rows); row++)
    {
      g_autoptr(FpDevice) device = new_device ();
      g_autoptr(GBytes) stored = generate_template (0);
      g_autoptr(GBytes) update = generate_template (1);
      GBytes *templates[] = { stored };
      g_autoptr(FpPrint) print = make_print (device, stored);
      FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
      AsyncResult result = { 0 };
      guint32 sample_count = self->milan_generation->state.sample_count;
      guint32 calibration_ready =
        self->milan_generation->profile_state.calibration_ready;
      FpiSsm *original_ssm;
      FpiSsm *replacement_ssm = NULL;
      GTask *replacement_task = NULL;

      reset_plan (positive, templates, G_N_ELEMENTS (positive), update);
      plan.block_study = TRUE;
      fp_device_verify (device, print, NULL, match_report, &result, NULL,
                        verify_done, &result);
      wait_study ();
      original_ssm = self->profile9_fdt.owner;
      if (rows[row] == STALE_ACTION_EPOCH)
        {
          self->action_epoch++;
        }
      else if (rows[row] == STALE_GENERATION)
        {
          replace_generation (self);
          sample_count = self->milan_generation->state.sample_count;
          calibration_ready =
            self->milan_generation->profile_state.calibration_ready;
        }
      else
        {
          replacement_ssm = fpi_ssm_new (device,
                                         milan_runtime_harness_scan_handler, 1);
          replacement_task = g_task_new (device, NULL, NULL, NULL);
          g_clear_object (&self->milan_task);
          self->milan_task = g_object_ref (replacement_task);
          self->profile9_fdt.owner = replacement_ssm;
        }
      release_study ();

      if (rows[row] == STALE_TASK_AND_SSM)
        {
          while (self->captured_raw_image)
            g_main_context_iteration (NULL, TRUE);
          g_clear_object (&self->milan_task);
          g_task_return_boolean (replacement_task, TRUE);
          g_clear_object (&replacement_task);
          self->profile9_fdt.owner = original_ssm;
          fpi_ssm_free (replacement_ssm);
          fpi_ssm_mark_failed (original_ssm, g_error_new_literal (
                                 G_IO_ERROR, G_IO_ERROR_CANCELLED, "task/SSM owner replaced"));
        }
      wait_done (&result);
      g_test_message ("stale row=%u", (guint) rows[row]);
      if (rows[row] == STALE_GENERATION)
        {
          g_autoptr(GBytes) updated = get_print_template (print);

          g_assert_true (result.success);
          g_assert_true (result.matched);
          g_assert_cmpuint (result.reports, ==, 1);
          g_assert_true (result.updated);
          g_assert_true (g_bytes_equal (updated, update));
        }
      else
        {
          g_assert_cmpuint (result.reports, ==, 0);
          g_assert_false (result.updated);
        }
      g_assert_cmpuint (self->milan_generation->state.sample_count, ==,
                        sample_count);
      g_assert_cmpuint (
        self->milan_generation->profile_state.calibration_ready, ==,
        calibration_ready);
      g_assert_false (self->pending_result_report);
      clear_result (&result);
      close_device (device);
    }
}
