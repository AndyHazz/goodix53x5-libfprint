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

static void
assert_match_update_semantics (const GoodixMilanUnpackedTemplate *before,
                               const GoodixMilanUnpackedTemplate *after,
                               const GoodixStudyQueue            *queue,
                               gsize                               matched_index)
{
  g_assert_cmpmem (&after->metadata, sizeof(after->metadata),
                   &before->metadata, sizeof(before->metadata));
  g_assert_cmpuint (after->feature_count, ==, before->feature_count);
  g_assert_cmpuint (after->relation_count, ==, before->relation_count);
  g_assert_cmpmem (after->relations,
                   after->relation_count * sizeof(after->relations[0]),
                   before->relations,
                   before->relation_count * sizeof(before->relations[0]));
  g_assert_cmpmem (after->tail_state, sizeof(after->tail_state),
                   before->tail_state, sizeof(before->tail_state));

  for (gsize i = 0; i < before->feature_count; i++)
    {
      GoodixMilanFeatureView before_view;
      GoodixMilanFeatureView after_view;
      GoodixMilanFeatureRecord expected_live[150];
      g_autofree guint8 *expected_packed = NULL;
      gsize adjusted_angles = 0;

      g_assert_cmpint (goodix_milan_template_parse_feature_element (
                         before->feature_elements[i],
                         before->feature_element_sizes[i], &before_view), ==, 0);
      g_assert_cmpint (goodix_milan_template_parse_feature_element (
                         after->feature_elements[i],
                         after->feature_element_sizes[i], &after_view), ==, 0);
      expected_packed = g_memdup2 (before_view.packed_records,
                                   before_view.record_count * 32);
      g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                         before_view.packed_records, before_view.record_count,
                         before_view.fields.tagged_values[2], expected_live,
                         G_N_ELEMENTS (expected_live)), ==, 0);
      for (gsize record = 0; record < before_view.record_count; record++)
        {
          guint8 angle = before_view.packed_records[record * 32];

          if (angle <= 0x80)
            continue;
          /* This fixture imports -0x800..-0x100. Native full decode adds
           * 0x3244 once: live words retain 0x44, which packing discards. */
          g_assert_cmpuint (angle, >=, 0x81);
          g_assert_cmpuint (angle, <=, 0x88);
          expected_packed[record * 32] = 0xb2 - angle;
          expected_live[record].orientation =
            (gint16) ((0xb2 - angle) * 0x100 + 0x44);
          adjusted_angles++;
        }
      GoodixMilanFeatureView expected_view = before_view;

      expected_view.packed_records = expected_packed;
      assert_feature_material_equal (&after_view, &expected_view);
      g_assert_cmpuint (adjusted_angles, ==, i == matched_index ? 78 : 0);
      if (adjusted_angles != 0)
        {
          g_assert_nonnull (queue->live_features[i]);
          g_assert_cmpint (queue->live_features[i]->record_count, ==,
                           before_view.record_count);
          g_assert_cmpint (queue->live_features[i]->partition_count, ==,
                           before_view.fields.tagged_values[2]);
          g_assert_cmpmem (queue->live_features[i]->records,
                           before_view.record_count * sizeof (expected_live[0]),
                           expected_live,
                           before_view.record_count * sizeof (expected_live[0]));
        }
      else
        {
          g_assert_null (queue->live_features[i]);
        }
      for (gsize field = 0; field < G_N_ELEMENTS (before_view.fields.tagged_values);
           field++)
        {
          gint32 expected = before_view.fields.tagged_values[field];

          if (field == 6)
            expected = 0;
          if (field == 9 && i == matched_index)
            expected++;
          g_assert_cmpint (after_view.fields.tagged_values[field], ==, expected);
        }
      g_assert_cmpint (after_view.fields.optional_c7, ==,
                       before_view.fields.optional_c7);
    }
  g_assert_cmpmem (after->feature_elements[0], after->feature_element_sizes[0],
                   before->feature_elements[0], before->feature_element_sizes[0]);
}

static GBytes *
run_production_match_study_handoff (void)
{
  g_autoptr(GBytes) gallery = study_gallery (
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
  g_autoptr(GError) error = NULL;
  GoodixMatchInfo *probe = study_match_info (9, TRUE, 0);
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
  GoodixMilanMatchResult result;
  GoodixMilanStudyAction action = GOODIX_MILAN_STUDY_NONE;
  GBytes *after_match = NULL;
  GBytes *after_study = NULL;
  const guint8 *data;
  gsize size;
  GoodixMilanPrintTemplateInfo match_info;
  GoodixMilanPrintTemplateInfo study_info;
  GoodixMilanUnpackedTemplate before;
  GoodixMilanUnpackedTemplate matched;
  GoodixMilanUnpackedTemplate studied;
  GoodixMilanUnpackedTemplate probe_unpacked;

  unpack_study_template (gallery, &before);
  unpack_study_template (probe->template, &probe_unpacked);
  data = g_bytes_get_data (gallery, &size);
  g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                     probe, data, size, &result, &after_match, queue), ==,
                   GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_nonnull (after_match);
  g_assert_false (g_bytes_equal (gallery, after_match));
  g_assert_cmpint (result.score, ==, 100);
  g_assert_cmpuint (result.matched_feature_index, ==, 1);
  static const gint32 identity_relation[7] = {
    0, 0x100, 0, 0, 0, 0x100, 0,
  };

  g_assert_true (result.relation.relation_valid);
  g_assert_cmpint (result.relation.relation_count, ==, 42);
  g_assert_cmpmem (result.relation.relation_values,
                   sizeof(identity_relation), identity_relation,
                   sizeof(identity_relation));
  g_assert_cmpmem (result.match_transform, 6 * sizeof(gint32),
                   identity_relation + 1, 6 * sizeof(gint32));
  g_assert_cmpuint (result.direct_positive_feature_mask, ==, UINT64_C (2));
  g_assert_cmpuint (result.contributor_feature_mask, ==, UINT64_C (2));
  g_assert_cmpuint (result.lifecycle_update_feature_mask, ==, UINT64_C (2));
  g_assert_cmpuint (result.retained_evidence_count, ==, 0);
  g_assert_cmpint (result.retained_evidence_flag, ==, 1);
  g_assert_cmpint (result.study_control.study_finalization_gate, ==, 1);
  g_assert_cmpint (result.study_control.study_action_gate, ==, 1);
  g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 0);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_true (goodix_milan_print_validate_template (
    after_match, &match_info, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (match_info.queue_state, ==, 0);
  unpack_study_template (after_match, &matched);
  assert_match_update_semantics (&before, &matched, queue, 1);

  data = g_bytes_get_data (after_match, &size);
  g_assert_cmpint (goodix_milan_match_study_feature_queued (
                     probe, data, size, &result, TRUE, queue, &after_study,
                     &action), ==, GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_nonnull (after_study);
  g_assert_cmpint (action, ==, GOODIX_MILAN_STUDY_REPLACE);
  g_assert_false (g_bytes_equal (after_match, after_study));
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
  assert_study_template (
    after_study, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1,
    &study_info, &studied);
  assert_replacement_semantics (
    &before, &studied, &probe_unpacked, GOODIX_MILAN_STUDY_REPLACE,
    1, 1, 1, TRUE);
  /* Replacement installs the independent live probe, not the imported angles
   * or a fresh decode of their lossy packed projection. */
  g_assert_nonnull (queue->live_features[1]);
  g_assert_true (queue->live_features[1]->records != probe->records);
  g_assert_cmpint (queue->live_features[1]->record_count, ==, probe->record_count);
  g_assert_cmpint (queue->live_features[1]->partition_count, ==,
                   probe->partition_count);
  g_assert_cmpmem (queue->live_features[1]->records,
                   probe->record_count * sizeof (probe->records[0]),
                   probe->records,
                   probe->record_count * sizeof (probe->records[0]));

  g_bytes_unref (after_match);
  goodix_milan_study_queue_free (queue);
  goodix_milan_match_free_info (probe);
  return after_study;
}

void
test_production_match_study_handoff (void)
{
  g_autoptr(GBytes) first = NULL;

  for (gsize repeat = 0; repeat < 2; repeat++)
    {
      g_autoptr(GBytes) current = run_production_match_study_handoff ();

      if (!first)
        first = g_bytes_ref (current);
      else
        g_assert_true (g_bytes_equal (first, current));
    }
}
