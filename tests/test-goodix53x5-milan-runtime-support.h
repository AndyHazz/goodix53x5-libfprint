/*
 * Goodix 53x5 driver for libfprint - current Milan runtime contracts
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "drivers_api.h"

#include "fpi-print.h"
#include "drivers/goodix53x5/device/scan.h"
#include "drivers/goodix53x5/driver-private.h"
#include "drivers/goodix53x5/milan/match/match.h"
#include "drivers/goodix53x5/milan/print.h"
#include "drivers/goodix53x5/milan/runtime.h"

#include <glib.h>
#include <stdint.h>
#include <string.h>

#define PIXELS GOODIX_MILAN_SENSOR_PIXELS

typedef struct
{
  const gint32          *scores;
  GBytes *const         *expected_gallery;
  gsize                  score_count;
  gsize                  match_calls;
  GBytes                *study_candidate;
  gboolean               study_failure;
  gboolean               block_study;
  gboolean               study_entered;
  gboolean               release_study;
  gboolean               cancel_called;
  gsize                  study_calls;
  GoodixMilanStudyAction study_action;
  gboolean               fail_next_combine;
  gsize                  combine_calls;
  GMutex                 mutex;
  GCond                  condition;
} HarnessPlan;

typedef struct
{
  gboolean done;
  gboolean success;
  gboolean matched;
  guint    completions;
  guint    reports;
  FpPrint *match;
  FpPrint *reported_match;
  FpPrint *reported_print;
  GError  *reported_error;
  gboolean updated;
  FpPrint *enrolled;
  GError  *error;
  GCancellable *cancel_on_report; /* Borrowed reentrant client cleanup token. */
} AsyncResult;

/* One shared plan and scan state for all runtime tests and seam callbacks. */
extern HarnessPlan plan;
extern FpiSsm *paused_ssm;
extern gboolean pause_before_capture;
extern gboolean pause_cycle_settled;
extern gboolean capture_enroll_stage_pattern;

void generate_frames (guint16 setup[PIXELS], guint16 live[PIXELS], guint pattern);
GBytes *generate_template (guint pattern);
void reset_plan (const gint32 *scores, GBytes *const *expected_gallery,
                 gsize score_count, GBytes *study_candidate);
FpDevice *new_device (void);
FpPrint *make_print (FpDevice *device, GBytes *template_bytes);
GBytes *get_print_template (FpPrint *print);
void match_report (FpDevice *device, FpPrint *match, FpPrint *print,
                   gpointer user_data, GError *error);
void verify_done (GObject *source, GAsyncResult *async, gpointer user_data);
void identify_done (GObject *source, GAsyncResult *async, gpointer user_data);
void wait_done (AsyncResult *result);
void wait_paused (void);
void wait_study (void);
void wait_cancelled (void);
void release_study (void);
void clear_result (AsyncResult *result);
void close_device (FpDevice *device);

void milan_runtime_test_auth_start (FpDevice *dev);
void milan_runtime_test_enroll_start (FpDevice *dev);
void milan_runtime_test_clear_pending_result_report (FpiDeviceGoodix53x5 *self);
void milan_runtime_harness_bind_setup (GoodixMilanRuntimeInput *input,
                                       GoodixMilanGeneration   *generation);
GoodixSigfmTemplateStatus milan_runtime_harness_match (GoodixMatchInfo        *probe,
                                                       const guint8           *feature,
                                                       gsize                   feature_len,
                                                       GoodixMilanMatchResult *match_result,
                                                       GBytes                **after_match,
                                                       GoodixStudyQueue       *queue);
GoodixSigfmTemplateStatus milan_runtime_harness_study (GoodixMatchInfo              *probe,
                                                       const guint8                 *feature,
                                                       gsize                         feature_len,
                                                       const GoodixMilanMatchResult *match_result,
                                                       gboolean                      study_eligible,
                                                       GoodixStudyQueue             *queue,
                                                       GBytes                      **after_study,
                                                       GoodixMilanStudyAction       *action);
GoodixMilanEnrollmentAttemptStatus milan_runtime_harness_enrollment_attempt (GoodixMilanEnrollmentTransaction **transaction,
                                                                             GBytes                            *probe_template,
                                                                             guint                             *bad_record_count,
                                                                             guint                             *bad_continue_count,
                                                                             GoodixMilanEnrollmentResult       *enrollment_result);
void milan_runtime_harness_scan_start (FpiSsm                        *parent_ssm,
                                       FpDevice                      *dev,
                                       GoodixScanCaptureReadyCallback capture_ready,
                                       GoodixScanCycleSettledCallback cycle_settled,
                                       gpointer                       user_data);
void milan_runtime_harness_scan_set_disposition (FpDevice             *dev,
                                                 GoodixScanDisposition disposition,
                                                 GError               *error);
void milan_runtime_harness_scan_handler (FpiSsm *ssm, FpDevice *dev);
gboolean milan_runtime_harness_reinit (FpiSsm   *ssm,
                                       FpDevice *dev);
gboolean milan_runtime_harness_stale_error (const GError *error);

void test_auth_gallery_outcomes (void);
void test_auth_publication_contracts (void);
void test_auth_cleanup_results (gconstpointer user_data);
void test_malformed_current_print (void);
void test_cancellation_no_publication (void);
void test_enrollment_combine_retry (void);
void test_complete_enrollment_after_combine_retry (void);
void test_stale_result_guards (void);
