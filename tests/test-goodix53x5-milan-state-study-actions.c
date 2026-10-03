/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-state-study-support.h"
#include "test-goodix53x5-milan-state-tests.h"

typedef struct
{
  const gchar *name;
  GoodixMilanStudyAction action;
  gint32 retained_flag;
  gsize selected_index;
  guint32 relation_count;
} StudyActionCase;

static GBytes *
run_study_action_case (const StudyActionCase *test_case)
{
  g_autoptr(GBytes) gallery = study_gallery (test_case->action, FALSE);
  GoodixMatchInfo *probe = study_match_info (9, FALSE, 0);
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
  GoodixMilanMatchResult result = study_primary_result (
    test_case->retained_flag);
  GoodixMilanStudyAction action = GOODIX_MILAN_STUDY_NONE;
  GBytes *updated = NULL;
  const guint8 *gallery_data;
  gsize gallery_size;
  GoodixMilanPrintTemplateInfo info;
  GoodixMilanUnpackedTemplate before;
  GoodixMilanUnpackedTemplate unpacked;
  GoodixMilanUnpackedTemplate probe_unpacked;

  unpack_study_template (gallery, &before);
  unpack_study_template (probe->template, &probe_unpacked);
  gallery_data = g_bytes_get_data (gallery, &gallery_size);
  g_assert_cmpint (goodix_milan_match_study_feature_queued (
                     probe, gallery_data, gallery_size, &result, TRUE, queue,
                     &updated, &action), ==, GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_cmpint (action, ==, test_case->action);
  g_assert_nonnull (updated);
  g_assert_false (g_bytes_equal (gallery, updated));
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
  assert_study_template (
    updated, test_case->relation_count, &info, &unpacked);
  assert_replacement_semantics (
    &before, &unpacked, &probe_unpacked, test_case->action,
    test_case->selected_index, 1, 0, FALSE);

  goodix_milan_study_queue_free (queue);
  goodix_milan_match_free_info (probe);
  return updated;
}

void
test_study_actions (void)
{
  static const StudyActionCase cases[] = {
    { "replace-no-relation", GOODIX_MILAN_STUDY_REPLACE_NO_RELATION,
      0, 1, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 2 },
    { "geometric", GOODIX_MILAN_STUDY_GEOMETRIC,
      1, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1,
      GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1 },
    { "replace", GOODIX_MILAN_STUDY_REPLACE,
      1, 1, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1 },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GBytes) first = NULL;

      for (gsize repeat = 0; repeat < 2; repeat++)
        {
          g_autoptr(GBytes) current = run_study_action_case (&cases[i]);

          g_test_message ("study action=%s repeat=%zu", cases[i].name, repeat);
          if (!first)
            first = g_bytes_ref (current);
          else
            g_assert_true (g_bytes_equal (first, current));
        }
    }
}

static GBytes *
run_queued_study_case (void)
{
  static const gint32 primary_marker = INT32_C (0x13579bdf);
  static const gint32 queued_marker = INT32_C (0x2468ace0);
  g_autoptr(GBytes) baseline_gallery = study_gallery (
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, FALSE);
  g_autoptr(GBytes) queued_gallery = study_gallery (
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, FALSE);
  GoodixMatchInfo *primary = study_match_info (9, TRUE, primary_marker);
  GoodixMatchInfo *queued = study_match_info (9, TRUE, queued_marker);
  GoodixStudyQueue *baseline_queue = goodix_milan_study_queue_new (0, 7);
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
  GoodixMilanMatchResult primary_result = study_primary_result (0);
  GoodixMilanMatchResult queued_primary_result = study_primary_result (0);
  GoodixMilanMatchResult followup = { 0 };
  GoodixMilanStudyAction action = GOODIX_MILAN_STUDY_NONE;
  GBytes *baseline = NULL;
  GBytes *updated = NULL;
  const guint8 *gallery_data;
  const guint8 *baseline_data;
  const guint8 *baseline_payload;
  gsize gallery_size;
  gsize baseline_size;
  gsize baseline_payload_size;
  const GoodixMilanFeatureRecord *live_records[GOODIX_MILAN_TEMPLATE_FEATURE_CAPACITY] = { 0 };
  size_t live_record_counts[GOODIX_MILAN_TEMPLATE_FEATURE_CAPACITY] = { 0 };
  size_t live_partition_counts[GOODIX_MILAN_TEMPLATE_FEATURE_CAPACITY] = { 0 };
  GoodixMilanPrintTemplateInfo info;
  GoodixMilanUnpackedTemplate before;
  GoodixMilanUnpackedTemplate unpacked;
  GoodixMilanUnpackedTemplate baseline_unpacked;
  GoodixMilanUnpackedTemplate probe_unpacked;
  GoodixMilanUnpackedTemplate queued_probe_unpacked;
  GoodixMilanFeatureView primary_feature;
  GoodixMilanFeatureView queued_feature;
  GoodixMilanFeatureView selected_feature;

  unpack_study_template (baseline_gallery, &before);
  unpack_study_template (primary->template, &probe_unpacked);
  unpack_study_template (queued->template, &queued_probe_unpacked);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     probe_unpacked.feature_elements[0],
                     probe_unpacked.feature_element_sizes[0],
                     &primary_feature), ==, 0);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     queued_probe_unpacked.feature_elements[0],
                     queued_probe_unpacked.feature_element_sizes[0],
                     &queued_feature), ==, 0);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     &primary->antifake), ==,
                   primary_marker);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     &queued->antifake), ==,
                   queued_marker);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     &primary->antifake), !=,
                   goodix_milan_antifake_calibration_scalar (
                     &queued->antifake));
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     primary_feature.antifake), ==,
                   primary_marker);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     queued_feature.antifake), ==,
                   queued_marker);
  gallery_data = g_bytes_get_data (baseline_gallery, &gallery_size);
  g_assert_cmpint (goodix_milan_match_study_feature_queued (
                     primary, gallery_data, gallery_size, &primary_result, TRUE,
                     baseline_queue, &baseline, &action), ==,
                   GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_cmpint (action, ==, GOODIX_MILAN_STUDY_REPLACE_NO_RELATION);
  assert_study_template (
    baseline, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 2,
    &info, &baseline_unpacked);
  assert_replacement_semantics (
    &before, &baseline_unpacked, &probe_unpacked,
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, 1, 1, 0, FALSE);

  baseline_data = g_bytes_get_data (baseline, &baseline_size);
  baseline_payload = baseline_data;
  baseline_payload_size = baseline_size;
  live_records[1] = primary->records;
  live_record_counts[1] = (size_t) primary->record_count;
  live_partition_counts[1] = (size_t) primary->partition_count;
  g_assert_cmpint (goodix_milan_match_live_probe_result (
                     queued->feature_bitmaps.high_bitmap,
                     queued->feature_bitmaps.enhanced_bitmap,
                     queued->feature_bitmaps.low_bitmap, queued->inline_mask,
                     queued->rescue_mask, queued->records,
                     (size_t) queued->record_count,
                     (size_t) queued->partition_count,
                     queued->extraction_metadata.quality,
                     queued->extraction_metadata.coverage,
                     queued->extraction_metadata.optional_c7,
                     baseline_payload, baseline_payload_size, live_records,
                     live_record_counts, live_partition_counts, 1,
                     &followup), ==, 0);
  g_assert_cmpint (followup.score, ==, 100);
  g_assert_cmpuint (followup.matched_feature_index, ==, 1);
  g_assert_true (followup.relation.relation_valid);
  g_assert_cmpint (followup.study_control.study_finalization_gate, ==, 1);
  g_assert_cmpint (followup.study_control.study_action_gate, ==, 1);
  g_assert_cmpuint (followup.lifecycle_update_feature_mask, ==, UINT64_C (2));

  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, queued, NULL, NULL), ==,
                   GOODIX_STUDY_QUEUE_ENQUEUED);
  action = GOODIX_MILAN_STUDY_NONE;
  gallery_data = g_bytes_get_data (queued_gallery, &gallery_size);
  g_assert_cmpint (goodix_milan_match_study_feature_queued (
                     primary, gallery_data, gallery_size,
                     &queued_primary_result, TRUE, queue, &updated, &action),
                   ==, GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_cmpint (action, ==, GOODIX_MILAN_STUDY_QUEUED);
  g_assert_nonnull (updated);
  g_assert_false (g_bytes_equal (queued_gallery, updated));
  g_assert_false (g_bytes_equal (baseline, updated));
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
  assert_study_template (
    updated, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 2,
    &info, &unpacked);
  assert_replacement_semantics (
    &before, &unpacked, &queued_probe_unpacked,
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, 1, 2, 1, FALSE);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     unpacked.feature_elements[1],
                     unpacked.feature_element_sizes[1], &selected_feature), ==,
                   0);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     selected_feature.antifake), ==,
                   queued_marker);
  g_assert_cmpint (goodix_milan_antifake_calibration_scalar (
                     selected_feature.antifake), !=,
                   primary_marker);

  g_bytes_unref (baseline);
  goodix_milan_study_queue_free (queue);
  goodix_milan_study_queue_free (baseline_queue);
  goodix_milan_match_free_info (queued);
  goodix_milan_match_free_info (primary);
  return updated;
}

void
test_queued_study_action (void)
{
  g_autoptr(GBytes) first = NULL;

  for (gsize repeat = 0; repeat < 2; repeat++)
    {
      g_autoptr(GBytes) current = run_queued_study_case ();

      if (!first)
        first = g_bytes_ref (current);
      else
        g_assert_true (g_bytes_equal (first, current));
    }
}
