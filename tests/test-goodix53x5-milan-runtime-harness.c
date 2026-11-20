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
  FpiSsm                        *parent_ssm;
  GoodixScanCaptureReadyCallback capture_ready;
  GoodixScanCycleSettledCallback cycle_settled;
  gpointer                       user_data;
  gboolean                       matched;
} HarnessScanCoordinator;

HarnessPlan plan;
FpiSsm *paused_ssm;
gboolean pause_before_capture;
gboolean pause_cycle_settled;
gboolean capture_enroll_stage_pattern;

void
milan_runtime_harness_bind_setup (GoodixMilanRuntimeInput *input,
                                  GoodixMilanGeneration   *generation)
{
  /* This existing harness supplies frames without disk selection and keeps
   * runtime execution filesystem-free. Production binds its selected record. */
  (void) input;
  (void) generation;
}

void
reset_plan (const gint32  *scores,
            GBytes *const *expected_gallery,
            gsize          score_count,
            GBytes        *study_candidate)
{
  g_mutex_lock (&plan.mutex);
  plan.scores = scores;
  plan.expected_gallery = expected_gallery;
  plan.score_count = score_count;
  plan.match_calls = 0;
  plan.study_candidate = study_candidate;
  plan.study_failure = FALSE;
  plan.block_study = FALSE;
  plan.study_entered = FALSE;
  plan.release_study = FALSE;
  plan.cancel_called = FALSE;
  plan.study_calls = 0;
  plan.study_action = GOODIX_MILAN_STUDY_APPEND;
  plan.fail_next_combine = FALSE;
  plan.combine_calls = 0;
  g_mutex_unlock (&plan.mutex);
}

GoodixSigfmTemplateStatus
milan_runtime_harness_match (GoodixMatchInfo        *probe,
                             const guint8           *feature,
                             gsize                   feature_len,
                             GoodixMilanMatchResult *match_result,
                             GBytes                **after_match,
                             GoodixStudyQueue       *queue)
{
  GBytes *expected;
  const guint8 *expected_data;
  gsize expected_size;
  gsize index;
  gint32 score;

  (void) probe;
  (void) queue;
  g_mutex_lock (&plan.mutex);
  index = plan.match_calls++;
  g_assert_cmpuint (index, <, plan.score_count);
  score = plan.scores[index];
  expected = plan.expected_gallery[index];
  g_mutex_unlock (&plan.mutex);

  expected_data = g_bytes_get_data (expected, &expected_size);
  g_assert_cmpmem (feature, feature_len, expected_data, expected_size);
  memset (match_result, 0, sizeof (*match_result));
  match_result->score = score;
  *after_match = g_bytes_new (feature, feature_len);
  return GOODIX_SIGFM_TEMPLATE_OK;
}

GoodixSigfmTemplateStatus
milan_runtime_harness_study (GoodixMatchInfo              *probe,
                             const guint8                 *feature,
                             gsize                         feature_len,
                             const GoodixMilanMatchResult *match_result,
                             gboolean                      study_eligible,
                             GoodixStudyQueue             *queue,
                             GBytes                      **after_study,
                             GoodixMilanStudyAction       *action)
{
  GBytes *candidate;
  gboolean failure;
  GoodixMilanStudyAction study_action;

  (void) probe;
  (void) feature;
  (void) feature_len;
  (void) match_result;
  (void) study_eligible;
  (void) queue;
  g_mutex_lock (&plan.mutex);
  plan.study_calls++;
  plan.study_entered = TRUE;
  g_cond_broadcast (&plan.condition);
  while (plan.block_study && !plan.release_study)
    g_cond_wait (&plan.condition, &plan.mutex);
  failure = plan.study_failure;
  candidate = plan.study_candidate;
  study_action = plan.study_action;
  g_mutex_unlock (&plan.mutex);

  if (failure)
    return GOODIX_SIGFM_TEMPLATE_INVALID;
  if (study_action != GOODIX_MILAN_STUDY_NONE)
    {
      g_assert_nonnull (candidate);
      *after_study = g_bytes_ref (candidate);
    }
  *action = study_action;
  return GOODIX_SIGFM_TEMPLATE_OK;
}

GoodixMilanEnrollmentAttemptStatus
milan_runtime_harness_enrollment_attempt (
  GoodixMilanEnrollmentTransaction **transaction,
  GBytes                            *probe_template,
  guint                             *bad_record_count,
  guint                             *bad_continue_count,
  GoodixMilanEnrollmentResult       *enrollment_result)
{
  gboolean fail;

  g_mutex_lock (&plan.mutex);
  plan.combine_calls++;
  fail = plan.fail_next_combine;
  plan.fail_next_combine = FALSE;
  g_mutex_unlock (&plan.mutex);
  if (fail)
    {
      memset (enrollment_result, 0, sizeof (*enrollment_result));
      if (*bad_continue_count < 3)
        *bad_continue_count = 0;
      return GOODIX_MILAN_ENROLLMENT_RETRY_REMOVE;
    }
  return goodix_milan_enrollment_transaction_attempt (
    transaction, probe_template, bad_record_count, bad_continue_count,
    enrollment_result);
}

static void
milan_runtime_harness_scan_capture (FpDevice               *dev,
                                    HarnessScanCoordinator *coordinator)
{
  static const guint enrollment_patterns[GOODIX_ENROLL_SAMPLES] = {
    0, 12, 4, 16, 20, 8, 2, 14, 6, 18, 10, 22
  };
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint pattern = capture_enroll_stage_pattern ?
                  enrollment_patterns[self->enroll_stage] : 0;

  g_assert_nonnull (self->milan_generation);
  g_clear_pointer (&self->captured_raw_image, g_free);
  self->captured_raw_image = g_new (guint16, PIXELS);
  generate_frames (self->milan_generation->setup_tx_on,
                   self->captured_raw_image, pattern);
  self->captured_enroll_allowed = TRUE;
  goodix_milan_generation_note_use (self->milan_generation);
  coordinator->capture_ready (dev, coordinator->user_data);
}

void
milan_runtime_harness_scan_handler (FpiSsm   *ssm,
                                    FpDevice *dev)
{
  HarnessScanCoordinator *coordinator = fpi_ssm_get_data (ssm);

  if (pause_before_capture)
    paused_ssm = ssm;
  else
    milan_runtime_harness_scan_capture (dev, coordinator);
}

static void
milan_runtime_harness_scan_done (FpiSsm   *ssm,
                                 FpDevice *dev,
                                 GError   *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  HarnessScanCoordinator *coordinator = fpi_ssm_get_data (ssm);

  if (self->profile9_fdt.owner == ssm)
    self->profile9_fdt.owner = NULL;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED;
  /* Like the production coordinator, a hardware failure after a positive
   * comparison does not invalidate that result. */
  if (error && coordinator->matched &&
      !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    g_clear_error (&error);
  if (error)
    fpi_ssm_mark_failed (coordinator->parent_ssm, error);
  else
    fpi_ssm_next_state (coordinator->parent_ssm);
}

void
milan_runtime_harness_scan_start (
  FpiSsm                        *parent_ssm,
  FpDevice                      *dev,
  GoodixScanCaptureReadyCallback capture_ready,
  GoodixScanCycleSettledCallback cycle_settled,
  gpointer                       user_data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  HarnessScanCoordinator *coordinator = g_new0 (HarnessScanCoordinator, 1);
  FpiSsm *ssm;

  coordinator->parent_ssm = parent_ssm;
  coordinator->capture_ready = capture_ready;
  coordinator->cycle_settled = cycle_settled;
  coordinator->user_data = user_data;
  ssm = fpi_ssm_new (dev, milan_runtime_harness_scan_handler, 1);
  fpi_ssm_set_data (ssm, coordinator, g_free);
  self->profile9_fdt.owner = ssm;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
  fpi_ssm_start (ssm, milan_runtime_harness_scan_done);
}

void
milan_runtime_harness_scan_set_disposition (
  FpDevice             *dev,
  GoodixScanDisposition disposition,
  GError               *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm = self->profile9_fdt.owner;
  HarnessScanCoordinator *coordinator;

  g_assert_nonnull (ssm);
  coordinator = fpi_ssm_get_data (ssm);
  if (disposition == GOODIX_SCAN_DISPOSITION_FATAL)
    {
      fpi_ssm_mark_failed (
        ssm, error ? error : fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }
  g_clear_error (&error);
  if (disposition == GOODIX_SCAN_DISPOSITION_CANCELLED)
    {
      fpi_ssm_mark_failed (
        ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                  "Harness scan coordinator cancelled"));
      return;
    }
  if (disposition == GOODIX_SCAN_DISPOSITION_AUTH_SUCCESS)
    {
      coordinator->matched = TRUE;
      if (pause_cycle_settled)
        {
          paused_ssm = ssm;
          return;
        }
      fpi_ssm_mark_completed (ssm);
      return;
    }

  if (coordinator->cycle_settled)
    coordinator->cycle_settled (dev, disposition, coordinator->user_data);
  if (pause_cycle_settled)
    {
      paused_ssm = ssm;
      return;
    }
  if (disposition == GOODIX_SCAN_DISPOSITION_ENROLL_CONTINUE_AFTER_UP)
    milan_runtime_harness_scan_capture (dev, coordinator);
  else
    fpi_ssm_mark_completed (ssm);
}

gboolean
milan_runtime_harness_reinit (FpiSsm   *ssm,
                              FpDevice *dev)
{
  (void) ssm;
  (void) dev;
  return FALSE;
}

gboolean
milan_runtime_harness_stale_error (const GError *error)
{
  (void) error;
  return FALSE;
}
