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

GBytes *
study_candidate_feature (gint32 ordinal,
                         gint32 coverage)
{
  g_autoptr(GBytes) base = ordered_match_feature (ordinal, ordinal == 2 ? 4 : 0);
  GoodixMilanFeatureView view;
  GoodixMilanFeatureRecord records[150];
  GoodixMilanAntifakeBlob antifake = { 0 };
  gsize size;
  gsize packed_size = 0;
  const guint8 *data = g_bytes_get_data (base, &size);
  g_autofree guint8 *packed = g_malloc (size);

  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     data, size, &view), ==, 0);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, 150, 0, records, 150), ==, 0);
  view.fields.tagged_values[4] = coverage;
  g_assert_cmpint (goodix_milan_template_pack_feature_element (
                     view.high_bitmap, view.enhanced_bitmap, view.inline_mask,
                     view.low_bitmap, records, 150, &antifake, &view.fields,
                     packed, size, &packed_size), ==, 0);
  return g_bytes_new_take (g_steal_pointer (&packed), packed_size);
}

void
test_production_study_competing_candidates (void)
{
  g_autoptr(GBytes) probe_feature = study_candidate_feature (0, 100);
  g_autoptr(GBytes) first = study_candidate_feature (1, 70);
  g_autoptr(GBytes) translated = study_candidate_feature (2, 100);

  /* Native 180045530 ranks residual, coverage, then overlap count, retaining
   * the first physical index on a complete tie. The real match selects slot 2
   * with residual 88; study must select another slot. Native 18005edb0 followed
   * by 180044fc0 agrees on complete match/study outputs for both fixtures.
   * These are matcher-boundary inputs, not sensor/enrollment chronology. */
  for (guint tie = 0; tie < 2; tie++)
    {
      g_autoptr(GBytes) third = study_candidate_feature (3, tie ? 70 : 69);
      g_autoptr(GBytes) base = study_gallery (
        GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
      g_autoptr(GBytes) gallery = NULL;
      g_autoptr(GBytes) after_match = NULL;
      g_autoptr(GBytes) after_study = NULL;
      GoodixMilanUnpackedTemplate before;
      GoodixMilanUnpackedTemplate matched;
      GoodixMilanUnpackedTemplate studied;
      GoodixMilanFeatureView probe_view;
      GoodixMilanPrintTemplateInfo info;
      GoodixMilanMatchResult result;
      GoodixMilanStudyAction action = GOODIX_MILAN_STUDY_NONE;
      GoodixMatchInfo *probe = study_match_info_from_feature (probe_feature, TRUE);
      GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
      const gsize selected = tie ? 1 : 3;
      gsize capacity = g_bytes_get_size (base) + g_bytes_get_size (translated) +
                       g_bytes_get_size (third);
      g_autofree guint8 *packed = g_malloc (capacity);
      gsize size = 0;
      const guint8 *data;

      g_test_message ("study coverage tie=%u selected slot=%" G_GSIZE_FORMAT,
                      tie, selected);
      unpack_study_template (base, &before);
      before.feature_elements[1] = g_bytes_get_data (
        first, &before.feature_element_sizes[1]);
      before.feature_elements[2] = g_bytes_get_data (
        translated, &before.feature_element_sizes[2]);
      before.feature_elements[3] = g_bytes_get_data (
        third, &before.feature_element_sizes[3]);
      before.relations[1].values[3] = -0x400;
      goodix_milan_template_write_u32 (before.tail_state, 2);
      goodix_milan_template_write_u32 (before.tail_state + 8, 0);
      g_assert_cmpint (goodix_milan_template_pack (
                         before.feature_elements, before.feature_element_sizes,
                         before.feature_count, before.relations,
                         before.relation_count, &before.metadata,
                         before.tail_state, sizeof (before.tail_state), packed,
                         capacity, &size), ==, 0);
      gallery = g_bytes_new_take (g_steal_pointer (&packed), size);
      g_assert_true (goodix_milan_print_validate_template (gallery, &info, NULL));
      data = g_bytes_get_data (gallery, &size);
      g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                         probe, data, size, &result, &after_match, queue), ==,
                       GOODIX_SIGFM_TEMPLATE_OK);
      g_assert_cmpint (result.score, ==, 100);
      g_assert_cmpuint (result.matched_feature_index, ==, 2);
      g_assert_cmpint (result.retained_evidence_flag, ==, 1);
      g_assert_cmpint (result.study_control.study_action_gate, ==, 1);
      g_assert_cmpint (result.study_control.study_finalization_gate, ==, 1);
      g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 0);
      g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
      g_assert_nonnull (after_match);
      unpack_study_template (after_match, &matched);
      data = g_bytes_get_data (after_match, &size);
      g_assert_cmpint (goodix_milan_match_study_feature_queued (
                         probe, data, size, &result, TRUE, queue, &after_study,
                         &action), ==, GOODIX_SIGFM_TEMPLATE_OK);
      g_assert_cmpint (action, ==, GOODIX_MILAN_STUDY_REPLACE);
      g_assert_nonnull (after_study);
      assert_study_template (after_study, before.relation_count, &info, &studied);
      g_assert_cmpuint (studied.metadata.maximum_records, ==,
                        before.metadata.maximum_records);
      g_assert_cmpint (studied.metadata.graph_companion_f3, ==,
                       before.metadata.graph_companion_f3);
      g_assert_cmpint (studied.metadata.graph_companion_f4, ==,
                       before.metadata.graph_companion_f4);
      g_assert_true (goodix_milan_study_queue_validate (queue));
      g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
      g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
      data = g_bytes_get_data (probe_feature, &size);
      g_assert_cmpint (goodix_milan_template_parse_feature_element (
                         data, size, &probe_view), ==, 0);
      for (gsize i = 0; i < studied.feature_count; i++)
        {
          GoodixMilanFeatureView original;
          GoodixMilanFeatureView updated;

          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             matched.feature_elements[i],
                             matched.feature_element_sizes[i], &original), ==, 0);
          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             studied.feature_elements[i],
                             studied.feature_element_sizes[i], &updated), ==, 0);
          g_assert_cmpint (original.fields.tagged_values[6], ==, i == 2 ? 88 : 0);
          g_assert_cmpint (original.fields.tagged_values[9], ==, i == 2 ? 1 : 0);
          assert_feature_material_equal (
            &updated, i == selected ? &probe_view : &original);
          for (gsize field = 0; field < G_N_ELEMENTS (original.fields.tagged_values);
               field++)
            {
              gint32 expected = original.fields.tagged_values[field];

              if (i == selected)
                {
                  if (field == 3 || field == 4)
                    expected = 100;
                  if (field == 5)
                    expected = 2;
                  if (field == 8 || field == 9)
                    expected = 1;
                }
              if (field == 7)
                expected = i == selected ? (gint32) studied.feature_count - 1 :
                           (gint32) i - (i > selected);
              g_assert_cmpint (updated.fields.tagged_values[field], ==, expected);
            }
          g_assert_cmpint (updated.fields.optional_c7, ==, original.fields.optional_c7);
        }
      for (gsize i = 0; i < before.relation_count; i++)
        {
          g_assert_cmpint (studied.relations[i].index, ==, before.relations[i].index);
          g_assert_cmpmem (studied.relations[i].values,
                           sizeof (studied.relations[i].values),
                           before.relations[i].values,
                           sizeof (before.relations[i].values));
        }
      /* Replacement inherits the matched slot's lifecycle, so both precede
       * untouched features; the replacement's new ordinal breaks their tie. */
      gsize position = 0;

      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          studied.tail_state + position++ * 4), ==, selected);
      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          studied.tail_state + position++ * 4), ==, 2);
      for (gsize i = studied.feature_count; i-- > 0;)
        if (i != selected && i != 2)
          g_assert_cmpuint (goodix_milan_template_read_u32 (
                              studied.tail_state + position++ * 4), ==, i);
      g_assert_cmpmem (studied.tail_state + position * 4, 0x50c - position * 4,
                       before.tail_state + position * 4, 0x50c - position * 4);
      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          studied.tail_state + 0x50c), ==, 1);
      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          studied.tail_state + 0x510), ==, 1);
      g_assert_cmpmem (studied.tail_state + 0x514, sizeof (studied.tail_state) - 0x514,
                       before.tail_state + 0x514, sizeof (before.tail_state) - 0x514);
      goodix_milan_study_queue_free (queue);
      goodix_milan_match_free_info (probe);
    }
}
