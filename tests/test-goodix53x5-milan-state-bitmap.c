/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-state-support.h"
#include "test-goodix53x5-milan-state-study-support.h"
#include "test-goodix53x5-milan-state-tests.h"

static GBytes *
bitmap_decision_feature (gsize changed_bytes)
{
  g_autoptr(GBytes) base = ordered_match_feature (0, 0);
  GoodixMilanFeatureView view;
  GoodixMilanFeatureRecord records[150];
  guint8 high[286], enhanced[286], low[286];
  gsize size, packed_size;
  const guint8 *data = g_bytes_get_data (base, &size);
  g_autofree guint8 *packed = g_malloc (size);

  g_assert_cmpuint (changed_bytes, <=, sizeof (high));
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     data, size, &view), ==, 0);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, 150, 0, records, 150), ==, 0);
  for (gsize i = 0; i < sizeof (high); i++)
    {
      guint8 flip = i < changed_bytes ? 0xff : 0;

      high[i] = view.high_bitmap[i] ^ flip;
      enhanced[i] = view.enhanced_bitmap[i] ^ flip;
      low[i] = view.low_bitmap[i] ^ flip;
    }
  g_assert_cmpint (goodix_milan_template_pack_feature_element (
                     high, enhanced, view.inline_mask, low, records, 150,
                     view.antifake, &view.fields, packed, size, &packed_size), ==, 0);
  return g_bytes_new_take (g_steal_pointer (&packed), packed_size);
}

static GBytes *
bitmap_decision_gallery (void)
{
  g_autoptr(GBytes) base = study_gallery (
    GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
  g_autoptr(GBytes) feature = ordered_match_feature (1, 0);
  GoodixMilanUnpackedTemplate unpacked;
  gsize capacity = g_bytes_get_size (base) + g_bytes_get_size (feature);
  g_autofree guint8 *packed = g_malloc (capacity);
  gsize size;

  unpack_study_template (base, &unpacked);
  unpacked.feature_elements[1] = g_bytes_get_data (
    feature, &unpacked.feature_element_sizes[1]);
  g_assert_cmpint (goodix_milan_template_pack (
                     unpacked.feature_elements, unpacked.feature_element_sizes,
                     unpacked.feature_count, unpacked.relations,
                     unpacked.relation_count, &unpacked.metadata,
                     unpacked.tail_state, sizeof (unpacked.tail_state), packed,
                     capacity, &size), ==, 0);
  return g_bytes_new_take (g_steal_pointer (&packed), size);
}

void
test_production_match_bitmap_decision (void)
{
  static const struct
  {
    gsize changed_bytes;
    gint  score;
  } cases[] = { { 48, 100 }, { 56, -7 } };

  /* Boundary-valid synthetic features, not sensor/enrollment chronology.
   * Record descriptors, positions and angles are identical in both cases;
   * all three balanced maps change together. Native 2.0.310.900 type-12
   * dispatch accepts 48 flipped bytes but rejects 56. Both enqueue a probe;
   * queue admission is distinct from recognition acceptance.
   * Complete native/current after-match bytes were compared for both cases. */
  for (gsize c = 0; c < G_N_ELEMENTS (cases); c++)
    {
      const gboolean accepted = cases[c].score > 0;
      g_autoptr(GBytes) feature = bitmap_decision_feature (cases[c].changed_bytes);
      g_autoptr(GBytes) gallery = bitmap_decision_gallery ();
      g_autoptr(GBytes) after_match = NULL;
      g_autoptr(GError) error = NULL;
      GoodixMilanUnpackedTemplate before, after;
      GoodixMilanPrintTemplateInfo info;
      GoodixMilanMatchResult result;
      GoodixMatchInfo *probe = study_match_info_from_feature (feature, TRUE);
      GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
      const GoodixMatchInfo *queued;
      gsize size;
      const guint8 *data = g_bytes_get_data (gallery, &size);

      g_test_message ("flipped bitmap bytes=%" G_GSIZE_FORMAT,
                      cases[c].changed_bytes);
      g_assert_true (goodix_milan_print_validate_template (gallery, &info, &error));
      g_assert_no_error (error);
      unpack_study_template (gallery, &before);
      g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                         probe, data, size, &result, &after_match, queue), ==,
                       GOODIX_SIGFM_TEMPLATE_OK);
      g_assert_cmpint (result.score, ==, cases[c].score);
      g_assert_cmpuint (result.matched_feature_index, ==, accepted ? 1 : SIZE_MAX);
      g_assert_cmpint (result.relation.relation_valid, ==, accepted);
      g_assert_cmpint (result.relation.relation_count, ==, accepted ? 42 : 0);
      g_assert_cmpuint (result.direct_positive_feature_mask, ==, accepted ? 2 : 0);
      g_assert_cmpuint (result.contributor_feature_mask, ==, accepted ? 2 : 0);
      g_assert_cmpuint (result.lifecycle_update_feature_mask, ==, accepted ? 2 : 0);
      g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 1);
      g_assert_true (goodix_milan_study_queue_validate (queue));
      g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 1);
      queued = queue_entry_at_rank (queue, 0);
      g_assert_cmpuint (queue->enabled_state, ==, 0);
      g_assert_cmpuint (queue->transaction_counter, ==, 7);
      g_assert_cmpint (queued->record_count, ==, 150);
      g_assert_cmpint (queued->partition_count, ==, 0);
      g_assert_cmpmem (queued->feature_bitmaps.high_bitmap, 286,
                       probe->feature_bitmaps.high_bitmap, 286);
      g_assert_cmpmem (queued->feature_bitmaps.enhanced_bitmap, 286,
                       probe->feature_bitmaps.enhanced_bitmap, 286);
      g_assert_cmpmem (queued->feature_bitmaps.low_bitmap, 286,
                       probe->feature_bitmaps.low_bitmap, 286);

      g_assert_nonnull (after_match);
      g_assert_true (goodix_milan_print_validate_template (after_match, &info, &error));
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
          g_assert_cmpmem (after.relations[i].values, sizeof (after.relations[i].values),
                           before.relations[i].values, sizeof (before.relations[i].values));
        }
      g_assert_cmpmem (after.tail_state, sizeof (after.tail_state),
                       before.tail_state, sizeof (before.tail_state));
      for (gsize i = 0; i < before.feature_count; i++)
        {
          GoodixMilanFeatureView original, updated;

          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             before.feature_elements[i], before.feature_element_sizes[i],
                             &original), ==, 0);
          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             after.feature_elements[i], after.feature_element_sizes[i],
                             &updated), ==, 0);
          assert_feature_material_equal (&updated, &original);
          for (gsize field = 0; field < G_N_ELEMENTS (original.fields.tagged_values); field++)
            {
              gint32 expected = original.fields.tagged_values[field];

              /* Identity-aligned galleries have no unique residual coverage. */
              if (field == 6)
                expected = 0;
              if (field == 9 && accepted && i == 1)
                expected++;
              g_assert_cmpint (updated.fields.tagged_values[field], ==, expected);
            }
          g_assert_cmpint (updated.fields.optional_c7, ==, original.fields.optional_c7);
        }
      goodix_milan_study_queue_free (queue);
      goodix_milan_match_free_info (probe);
    }
}
