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

void
test_production_match_order_lifecycle (void)
{
  static const gint32 identity[7] = { 0, 0x100, 0, 0, 0, 0x100, 0 };

  g_autoptr(GBytes) probe_feature = ordered_match_feature (0, 0);
  g_autoptr(GBytes) first = ordered_match_feature (1, 0);
  g_autoptr(GBytes) translated = ordered_match_feature (2, 4);

  /* Native 180055a40 traverses a1 physical indices, then skips later active
   * features in a full gallery after retaining an active match. 1800619a0
   * routes the selected slot's affine to the graph reference independently.
   * Both orders and complete after-match bytes were checked against the DLL.
   * These are constructed matcher inputs, not sensor-generated features. */
  for (guint reverse = 0; reverse < 2; reverse++)
    {
      g_autoptr(GBytes) base = study_gallery (
        GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
      g_autoptr(GBytes) gallery = NULL;
      g_autoptr(GBytes) after_match = NULL;
      g_autoptr(GError) error = NULL;
      GoodixMilanUnpackedTemplate before;
      GoodixMilanUnpackedTemplate after;
      GoodixMilanPrintTemplateInfo info;
      GoodixMilanMatchResult result;
      GoodixMatchInfo *probe = study_match_info_from_feature (
        probe_feature, TRUE);
      GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
      const gsize winner = reverse ? 2 : 1;
      const guint64 mask = reverse ? UINT64_C (4) : UINT64_C (2);
      const gint32 transform[6] = {
        0x100, 0, reverse ? 0x400 : 0, 0, 0x100, 0,
      };
      gsize capacity = g_bytes_get_size (base) + g_bytes_get_size (translated);
      g_autofree guint8 *packed = g_malloc (capacity);
      gsize size = 0;
      const guint8 *data;

      g_test_message ("first matchable physical slot=%" G_GSIZE_FORMAT, winner);
      unpack_study_template (base, &before);
      before.feature_elements[1] = g_bytes_get_data (
        first, &before.feature_element_sizes[1]);
      before.feature_elements[2] = g_bytes_get_data (
        translated, &before.feature_element_sizes[2]);
      before.relations[1].values[3] = -0x400;
      goodix_milan_template_write_u32 (before.tail_state + 4, (guint32) winner);
      goodix_milan_template_write_u32 (before.tail_state + 8, reverse ? 1 : 2);
      g_assert_cmpint (goodix_milan_template_pack (
                         before.feature_elements, before.feature_element_sizes,
                         before.feature_count, before.relations,
                         before.relation_count, &before.metadata,
                         before.tail_state, sizeof (before.tail_state), packed,
                         capacity, &size), ==, 0);
      gallery = g_bytes_new_take (g_steal_pointer (&packed), size);
      g_assert_true (goodix_milan_print_validate_template (gallery, &info, &error));
      g_assert_no_error (error);
      data = g_bytes_get_data (gallery, &size);
      g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                         probe, data, size, &result, &after_match, queue), ==,
                       GOODIX_SIGFM_TEMPLATE_OK);
      g_assert_cmpint (result.score, ==, 100);
      g_assert_cmpuint (result.matched_feature_index, ==, winner);
      g_assert_cmpmem (result.match_transform, sizeof (transform),
                       transform, sizeof (transform));
      g_assert_true (result.relation.relation_valid);
      g_assert_cmpint (result.relation.relation_count, ==, 42);
      g_assert_cmpmem (result.relation.relation_values, sizeof (identity),
                       identity, sizeof (identity));
      g_assert_cmpuint (result.direct_positive_feature_mask, ==, mask);
      g_assert_cmpuint (result.contributor_feature_mask, ==, mask);
      g_assert_cmpuint (result.lifecycle_update_feature_mask, ==, mask);
      g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 0);
      g_assert_true (goodix_milan_study_queue_validate (queue));
      g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
      g_assert_nonnull (after_match);
      g_assert_false (g_bytes_equal (gallery, after_match));
      g_assert_true (goodix_milan_print_validate_template (
                       after_match, &info, &error));
      g_assert_no_error (error);
      unpack_study_template (after_match, &after);
      g_assert_cmpuint (after.feature_count, ==, before.feature_count);
      g_assert_cmpuint (after.metadata.registration_count, ==,
                        before.metadata.registration_count);
      g_assert_cmpint (after.metadata.graph_reference_index, ==,
                       before.metadata.graph_reference_index);
      g_assert_cmpuint (after.metadata.graph_established, ==,
                        before.metadata.graph_established);
      g_assert_cmpint (after.metadata.graph_companion_f3, ==,
                       before.metadata.graph_companion_f3);
      g_assert_cmpint (after.metadata.graph_companion_f4, ==,
                       before.metadata.graph_companion_f4);
      g_assert_cmpuint (after.metadata.queue_state, ==, 0);
      g_assert_cmpuint (after.metadata.queue_transaction_counter, ==, 7);
      g_assert_cmpuint (after.relation_count, ==, before.relation_count);
      for (gsize i = 0; i < before.relation_count; i++)
        {
          g_assert_cmpint (after.relations[i].index, ==, before.relations[i].index);
          g_assert_cmpmem (after.relations[i].values, sizeof (identity),
                           before.relations[i].values, sizeof (identity));
        }
      g_assert_cmpmem (after.tail_state, sizeof (after.tail_state),
                       before.tail_state, sizeof (before.tail_state));
      for (gsize i = 0; i < before.feature_count; i++)
        {
          GoodixMilanFeatureView original;
          GoodixMilanFeatureView updated;

          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             before.feature_elements[i],
                             before.feature_element_sizes[i], &original), ==, 0);
          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             after.feature_elements[i],
                             after.feature_element_sizes[i], &updated), ==, 0);
          assert_feature_material_equal (&updated, &original);
          for (gsize field = 0; field < G_N_ELEMENTS (original.fields.tagged_values);
               field++)
            {
              gint32 expected = original.fields.tagged_values[field];

              /* Two bitmap columns of unique residual coverage: 2 * 44. */
              if (field == 6)
                expected = i == 2 ? 88 : 0;
              if (field == 9 && i == winner)
                expected++;
              g_assert_cmpint (updated.fields.tagged_values[field], ==, expected);
            }
          g_assert_cmpint (updated.fields.optional_c7, ==,
                           original.fields.optional_c7);
        }
      goodix_milan_study_queue_free (queue);
      goodix_milan_match_free_info (probe);
    }
}
