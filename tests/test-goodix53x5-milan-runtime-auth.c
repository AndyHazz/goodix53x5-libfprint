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

static FpPrint *
make_malformed_current_print (FpDevice *device)
{
  static const guint8 malformed[] = "bad";
  GVariant *payload = g_variant_new_fixed_array (
    G_VARIANT_TYPE_BYTE, malformed, sizeof (malformed) - 1, 1);

  g_autoptr(GVariant) data = g_variant_ref_sink (g_variant_new (
                                                   "(uuuus@ay)", 4U, 9U, 12U, 1U, "canonical-zero-v1", payload));
  FpPrint *print = fp_print_new (device);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  return g_object_ref_sink (print);
}

void
test_auth_gallery_outcomes (void)
{
  static const gint32 first_positive[] = { -4, 37, 999 };
  static const gint32 all_negative[] = { -4, 0, -7 };
  static const gint32 positive[] = { 37 };

  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(GBytes) stored0 = generate_template (0);
  g_autoptr(GBytes) stored1 = generate_template (1);
  g_autoptr(GBytes) stored2 = generate_template (2);
  g_autoptr(GBytes) update = generate_template (3);
  GBytes *templates[] = { stored0, stored1, stored2 };
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  AsyncResult result = { 0 };

  g_assert_false (g_bytes_equal (stored0, stored1));
  g_assert_false (g_bytes_equal (stored1, stored2));
  g_assert_false (g_bytes_equal (stored1, update));
  for (gsize i = 0; i < G_N_ELEMENTS (templates); i++)
    g_ptr_array_add (gallery, make_print (device, templates[i]));

  reset_plan (first_positive, templates, G_N_ELEMENTS (first_positive), update);
  fp_device_identify (device, gallery, NULL, match_report, &result, NULL,
                      identify_done, &result);
  wait_done (&result);
  g_assert_true (result.success);
  g_assert_true (result.match == g_ptr_array_index (gallery, 1));
  g_assert_true (result.reported_match == result.match);
  g_assert_cmpuint (result.reports, ==, 1);
  g_assert_true (result.updated);
  g_autoptr(GBytes) updated = get_print_template (result.match);
  g_assert_true (g_bytes_equal (updated, update));
  g_autoptr(GBytes) unchanged0 = get_print_template (g_ptr_array_index (gallery, 0));
  g_autoptr(GBytes) unchanged2 = get_print_template (g_ptr_array_index (gallery, 2));
  g_assert_true (g_bytes_equal (unchanged0, stored0));
  g_assert_true (g_bytes_equal (unchanged2, stored2));
  g_assert_cmpuint (plan.match_calls, ==, 2);
  g_assert_cmpuint (plan.study_calls, ==, 1);
  clear_result (&result);
  templates[1] = update;

  reset_plan (all_negative, templates, G_N_ELEMENTS (all_negative), NULL);
  fp_device_identify (device, gallery, NULL, match_report, &result, NULL,
                      identify_done, &result);
  wait_done (&result);
  g_assert_true (result.success);
  g_assert_null (result.match);
  g_assert_false (result.updated);
  g_assert_cmpuint (result.reports, ==, 1);
  g_assert_cmpuint (plan.match_calls, ==, 3);
  g_assert_cmpuint (plan.study_calls, ==, 0);
  clear_result (&result);

  reset_plan (positive, templates, G_N_ELEMENTS (positive), NULL);
  plan.study_action = GOODIX_MILAN_STUDY_NONE;
  fp_device_verify (device, g_ptr_array_index (gallery, 0), NULL,
                    match_report, &result, NULL, verify_done, &result);
  wait_done (&result);
  g_assert_true (result.success);
  g_assert_true (result.matched);
  g_assert_false (result.updated);
  g_autoptr(GBytes) action0 = get_print_template (g_ptr_array_index (gallery, 0));
  g_assert_true (g_bytes_equal (action0, stored0));
  g_assert_cmpuint (plan.study_calls, ==, 1);
  clear_result (&result);

  reset_plan (positive, templates, G_N_ELEMENTS (positive), update);
  plan.study_failure = TRUE;
  g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                         "*learning was discarded after a positive match*");
  fp_device_verify (device, g_ptr_array_index (gallery, 0), NULL,
                    match_report, &result, NULL, verify_done, &result);
  wait_done (&result);
  g_test_assert_expected_messages ();
  g_assert_true (result.success);
  g_assert_true (result.matched);
  g_assert_cmpuint (result.reports, ==, 1);
  g_assert_false (result.updated);
  g_assert_cmpuint (plan.match_calls, ==, 1);
  g_assert_cmpuint (plan.study_calls, ==, 1);
  clear_result (&result);
  close_device (device);
}

typedef enum {
  AUTH_PRINT_INVALID,
  AUTH_PRINT_VALID_0,
  AUTH_PRINT_VALID_1,
  AUTH_PRINT_VALID_2,
} AuthPrintKind;

typedef struct
{
  const gchar         *name;
  gboolean             identify;
  const AuthPrintKind *prints;
  gsize                print_count;
  const gint32        *scores;
  gsize                score_count;
  gint                 expected_match_index;
  guint                expected_reports;
  guint                expected_study_calls;
  gint                 expected_error_code;
} AuthPublicationCase;

void
test_auth_publication_contracts (void)
{
  static const AuthPrintKind mixed_prints[] = {
    AUTH_PRINT_INVALID,
    AUTH_PRINT_VALID_0,
    AUTH_PRINT_INVALID,
    AUTH_PRINT_VALID_1,
    AUTH_PRINT_VALID_2,
  };
  static const AuthPrintKind invalid_prints[] = {
    AUTH_PRINT_INVALID,
    AUTH_PRINT_INVALID,
  };
  static const AuthPrintKind verify_prints[] = { AUTH_PRINT_VALID_0 };
  static const gint32 mixed_scores[] = { -4, 37 };
  static const gint32 no_match_score[] = { 0 };
  static const AuthPublicationCase rows[] = {
    {
      "mixed-identify-first-positive", TRUE,
      mixed_prints, G_N_ELEMENTS (mixed_prints),
      mixed_scores, G_N_ELEMENTS (mixed_scores), 3, 1, 1, -1,
    },
    {
      "all-invalid-identify", TRUE,
      invalid_prints, G_N_ELEMENTS (invalid_prints),
      NULL, 0, -1, 0, 0, FP_DEVICE_ERROR_DATA_INVALID,
    },
    {
      "verify-no-match", FALSE,
      verify_prints, G_N_ELEMENTS (verify_prints),
      no_match_score, G_N_ELEMENTS (no_match_score), -1, 1, 0, -1,
    },
  };

  g_autoptr(GBytes) stored0 = generate_template (0);
  g_autoptr(GBytes) stored1 = generate_template (1);
  g_autoptr(GBytes) stored2 = generate_template (2);
  GBytes *stored[] = { stored0, stored1, stored2 };

  for (gsize row_index = 0; row_index < G_N_ELEMENTS (rows); row_index++)
    {
      const AuthPublicationCase *row = &rows[row_index];
      g_autoptr(FpDevice) device = new_device ();
      g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (
        g_object_unref);
      GBytes *expected_gallery[G_N_ELEMENTS (mixed_prints)] = { 0 };
      gsize valid_count = 0;
      guint invalid_count = 0;
      AsyncResult result = { 0 };

      for (gsize i = 0; i < row->print_count; i++)
        {
          if (row->prints[i] == AUTH_PRINT_INVALID)
            {
              g_ptr_array_add (gallery, make_malformed_current_print (device));
              invalid_count++;
            }
          else
            {
              GBytes *template_bytes = stored[row->prints[i] - AUTH_PRINT_VALID_0];

              g_ptr_array_add (gallery, make_print (device, template_bytes));
              expected_gallery[valid_count++] = template_bytes;
            }
        }
      g_assert_cmpuint (row->score_count, <=, valid_count);
      reset_plan (row->scores, expected_gallery, row->score_count, NULL);
      if (row->expected_study_calls != 0)
        plan.study_action = GOODIX_MILAN_STUDY_NONE;
      for (guint i = 0; i < invalid_count; i++)
        g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                               "*Skipping invalid Milan identify gallery entry*");

      if (row->identify)
        fp_device_identify (device, gallery, NULL, match_report, &result, NULL,
                            identify_done, &result);
      else
        fp_device_verify (device, g_ptr_array_index (gallery, 0), NULL,
                          match_report, &result, NULL, verify_done, &result);
      wait_done (&result);
      if (invalid_count != 0)
        g_test_assert_expected_messages ();

      g_test_message ("auth publication row=%s", row->name);
      g_assert_cmpuint (result.completions, ==, 1);
      g_assert_cmpuint (result.reports, ==, row->expected_reports);
      g_assert_false (result.updated);
      g_assert_cmpuint (plan.match_calls, ==, row->score_count);
      g_assert_cmpuint (plan.study_calls, ==, row->expected_study_calls);
      g_assert_null (result.reported_print);
      g_assert_null (result.reported_error);
      if (row->expected_error_code >= 0)
        {
          g_assert_false (result.success);
          g_assert_error (result.error, FP_DEVICE_ERROR,
                          row->expected_error_code);
          g_assert_null (result.match);
          g_assert_null (result.reported_match);
        }
      else if (row->expected_match_index >= 0)
        {
          FpPrint *expected = g_ptr_array_index (
            gallery, row->expected_match_index);

          g_assert_true (result.success);
          g_assert_true (result.match == expected);
          g_assert_true (result.reported_match == expected);
        }
      else
        {
          g_assert_true (result.success);
          g_assert_false (result.matched);
          g_assert_null (result.match);
          g_assert_null (result.reported_match);
        }
      clear_result (&result);
      close_device (device);
    }
}

void
test_malformed_current_print (void)
{
  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(FpPrint) print = make_malformed_current_print (device);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
  AsyncResult result = { 0 };
  guint32 sample_count = self->milan_generation->state.sample_count;

  reset_plan (NULL, NULL, 0, NULL);
  fp_device_verify (device, print, NULL, match_report, &result, NULL,
                    verify_done, &result);
  wait_done (&result);
  g_assert_false (result.success);
  g_assert_error (result.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_cmpuint (result.reports, ==, 0);
  g_assert_false (result.updated);
  g_assert_cmpuint (plan.match_calls, ==, 0);
  g_assert_cmpuint (plan.study_calls, ==, 0);
  g_assert_cmpuint (self->milan_generation->state.sample_count, ==,
                    sample_count);
  clear_result (&result);
  close_device (device);
}

void
test_auth_cleanup_results (gconstpointer user_data)
{
  guint row = GPOINTER_TO_UINT (user_data);
  gboolean missing = row == 7;
  gboolean failed_cleanup = row % 2 || row >= 6;
  gboolean matched = row < 4 || row >= 6;
  /* A scan failure after the comparison only invalidates negative results;
   * cancellation, removal and a missing capture still fail the action. */
  gboolean publish = (row < 6 && (matched || !failed_cleanup)) || row == 6;
  gboolean update_expected = publish && (row < 2 || row == 6);
  gint32 score = matched ? 37 : 0;
  g_autoptr(FpDevice) device = new_device ();
  g_autoptr(GBytes) stored = generate_template (0);
  g_autoptr(GBytes) update = generate_template (1);
  g_autoptr(FpPrint) print = make_print (device, stored);
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  GBytes *gallery[] = { stored };
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);
  AsyncResult result = { 0 };

  reset_plan (&score, gallery, 1, update);
  if (row >= 2 && row < 6)
    plan.study_action = GOODIX_MILAN_STUDY_NONE;
  pause_before_capture = missing;
  pause_cycle_settled = !missing;
  fp_device_verify (device, print, cancel, match_report, &result, NULL, verify_done, &result);
  wait_paused ();
  /* Nothing reaches the application until the action completes. */
  g_assert_cmpuint (result.reports, ==, 0);
  g_assert_cmpuint (result.completions, ==, 0);
  g_assert_cmpint (self->pending_result_report, ==, !missing);
  g_autoptr(GBytes) before = get_print_template (print);
  g_assert_true (g_bytes_equal (before, stored));

  /* Scan provenance is the seam here; the USB suite proves its actual producer.
   * All matching, update admission and deferred publication use real owners. */
  if (failed_cleanup)
    self->needs_reinit = TRUE;
  if (row == 8)
    {
      /* Internal power/terminal cancellation still owns the completion error,
       * unlike ordinary client cleanup after a reported positive match. */
      g_cancellable_cancel (fpi_device_get_cancellable (device));
      wait_cancelled ();
    }
  if (row == 9)
    fpi_device_remove (device);
  if (failed_cleanup)
    fpi_ssm_mark_failed (paused_ssm, g_error_new_literal (
                          G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                          "Scheduled terminal transport failure"));
  else
    fpi_ssm_mark_completed (paused_ssm);
  paused_ssm = NULL;
  pause_before_capture = FALSE;
  pause_cycle_settled = FALSE;
  wait_done (&result);

  /* Nonfatal assertions retain every baseline row's cleanup and evidence. */
  if (result.completions != 1 || result.success != publish ||
      result.reports != (publish ? 1 : 0) || result.updated != update_expected ||
      (publish && result.matched != matched) ||
      (failed_cleanup && !self->needs_reinit))
    g_test_fail ();
  g_autoptr(GBytes) after = get_print_template (print);
  if (!g_bytes_equal (after, update_expected ? update : stored))
    g_test_fail ();
  clear_result (&result);
  if (row == 9)
    fp_device_close_sync (device, NULL, NULL);
  else
    close_device (device);
}
