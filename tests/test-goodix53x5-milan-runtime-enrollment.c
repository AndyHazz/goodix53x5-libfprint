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

typedef struct
{
  AsyncResult *result;
  guint        calls;
  gint         stage;
  gint         retry_code;
  gint         stages[GOODIX_ENROLL_SAMPLES + 1];
  gint         retry_codes[GOODIX_ENROLL_SAMPLES + 1];
  gboolean     early_publication;
} EnrollProgress;

static void
enroll_done (GObject      *source,
             GAsyncResult *async,
             gpointer      user_data)
{
  AsyncResult *result = user_data;

  result->enrolled = fp_device_enroll_finish (
    FP_DEVICE (source), async, &result->error);
  result->success = result->enrolled != NULL;
  result->completions++;
  result->done = TRUE;
}

static void
enroll_progress (FpDevice *device,
                 gint      completed_stages,
                 FpPrint  *print,
                 gpointer  user_data,
                 GError   *error)
{
  EnrollProgress *progress = user_data;
  guint index = progress->calls;

  (void) device;
  (void) print;
  g_assert_cmpuint (index, <, G_N_ELEMENTS (progress->stages));
  if (progress->result && progress->result->completions != 0)
    progress->early_publication = TRUE;
  progress->stages[index] = completed_stages;
  progress->retry_codes[index] = error ? error->code : -1;
  progress->calls++;
  progress->stage = completed_stages;
  progress->retry_code = error ? error->code : -1;
}

void
test_enrollment_combine_retry (void)
{
  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(FpPrint) print = g_object_ref_sink (fp_print_new (device));
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
  AsyncResult result = { 0 };
  EnrollProgress progress = { 0 };

  reset_plan (NULL, NULL, 0, NULL);
  plan.fail_next_combine = TRUE;
  pause_cycle_settled = TRUE;
  fp_device_enroll (device, print, NULL, enroll_progress, &progress, NULL,
                    enroll_done, &result);
  wait_paused ();
  g_assert_cmpuint (plan.combine_calls, ==, 1);
  g_assert_cmpuint (progress.calls, ==, 1);
  g_assert_cmpint (progress.stage, ==, 0);
  g_assert_cmpint (progress.retry_code, ==, FP_DEVICE_RETRY_REMOVE_FINGER);
  g_assert_cmpint (self->enroll_stage, ==, 0);
  g_assert_nonnull (self->enroll_transaction);
  g_assert_cmpuint (goodix_milan_enrollment_transaction_count (
                      self->enroll_transaction), ==, 0);
  g_assert_cmpuint (self->enroll_bad_record_count, ==, 0);
  g_assert_cmpuint (self->enroll_bad_continue_count, ==, 0);

  fpi_ssm_mark_failed (paused_ssm, g_error_new_literal (
                         G_IO_ERROR, G_IO_ERROR_CANCELLED, "combine retry observed"));
  paused_ssm = NULL;
  pause_cycle_settled = FALSE;
  wait_done (&result);
  g_assert_false (result.success);
  g_assert_null (result.enrolled);
  clear_result (&result);
  close_device (device);
}

void
test_complete_enrollment_after_combine_retry (void)
{
  static const gint32 no_match[] = { 0 };

  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(FpPrint) print = g_object_ref_sink (fp_print_new (device));
  g_autoptr(GBytes) stored = generate_template (0);
  GBytes *templates[] = { stored };
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (
    g_object_unref);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
  AsyncResult result = { 0 };
  EnrollProgress progress = { .result = &result };
  GoodixMilanPrintTemplateInfo info = { 0 };
  GoodixMilanGeneration *generation = self->milan_generation;
  guint64 generation_id = generation->generation_id;
  FpiPrintType print_type;

  g_ptr_array_add (gallery, make_print (device, stored));
  reset_plan (no_match, templates, G_N_ELEMENTS (no_match), NULL);
  fp_device_identify (device, gallery, NULL, match_report, &result, NULL,
                      identify_done, &result);
  wait_done (&result);
  g_assert_true (result.success);
  g_assert_no_error (result.error);
  g_assert_cmpuint (result.completions, ==, 1);
  g_assert_cmpuint (result.reports, ==, 1);
  g_assert_null (result.match);
  g_assert_null (result.reported_match);
  g_assert_null (result.reported_print);
  g_assert_null (result.reported_error);
  g_assert_false (result.updated);
  g_assert_cmpuint (plan.match_calls, ==, 1);
  g_assert_cmpuint (plan.study_calls, ==, 0);
  g_assert_true (self->milan_generation == generation);
  g_assert_cmpuint (self->milan_generation->generation_id, ==, generation_id);
  g_assert_true (self->milan_generation->identify_prelude_seen);
  clear_result (&result);

  reset_plan (NULL, NULL, 0, NULL);
  plan.fail_next_combine = TRUE;
  capture_enroll_stage_pattern = TRUE;
  fp_device_enroll (device, print, NULL, enroll_progress, &progress, NULL,
                    enroll_done, &result);
  wait_done (&result);
  capture_enroll_stage_pattern = FALSE;

  g_assert_true (result.success);
  g_assert_no_error (result.error);
  g_assert_cmpuint (result.completions, ==, 1);
  g_assert_false (progress.early_publication);
  g_assert_cmpuint (progress.calls, ==, GOODIX_ENROLL_SAMPLES + 1);
  g_assert_cmpint (progress.stages[0], ==, 0);
  g_assert_cmpint (progress.retry_codes[0], ==,
                   FP_DEVICE_RETRY_REMOVE_FINGER);
  for (guint i = 1; i < G_N_ELEMENTS (progress.stages); i++)
    {
      g_assert_cmpint (progress.stages[i], ==, i);
      g_assert_cmpint (progress.retry_codes[i], ==, -1);
    }
  g_assert_cmpuint (plan.combine_calls, ==, GOODIX_ENROLL_SAMPLES + 1);
  g_assert_cmpint (self->enroll_stage, ==, GOODIX_ENROLL_SAMPLES);
  g_assert_null (self->enroll_transaction);
  g_assert_true (result.enrolled == print);
  g_object_get (result.enrolled, "fpi-type", &print_type, NULL);
  g_assert_cmpint (print_type, ==, FPI_PRINT_RAW);
  g_autoptr(GBytes) enrolled_template = get_print_template (result.enrolled);
  g_assert_true (goodix_milan_print_validate_template (
                   enrolled_template, &info, NULL));
  g_assert_cmpuint (info.byte_size, ==, g_bytes_get_size (enrolled_template));
  g_assert_cmpuint (info.feature_count, ==, GOODIX_ENROLL_SAMPLES);
  g_assert_cmpuint (info.registration_count, ==, 67);
  g_assert_cmpuint (info.relation_count, ==, 9);
  g_assert_cmpuint (info.graph_established, ==, 1);
  g_assert_cmpint (info.graph_reference_index, ==, 0);
  g_assert_cmpuint (info.maximum_features, ==,
                    GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT);
  g_assert_cmpuint (info.maximum_records, ==, 150);
  g_assert_cmpuint (info.queue_state, ==, 0);
  g_assert_cmpuint (info.queue_transaction_counter, ==, 0);

  clear_result (&result);
  close_device (device);
}
