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

void
assert_study_template (GBytes                       *bytes,
                       guint32                       expected_relations,
                       GoodixMilanPrintTemplateInfo *info,
                       GoodixMilanUnpackedTemplate  *unpacked)
{
  g_autoptr(GError) error = NULL;
  const guint8 *template_data;
  gsize template_size;

  g_assert_true (goodix_milan_print_validate_template (bytes, info, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (info->feature_count, ==,
                    GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT);
  g_assert_cmpuint (info->maximum_features, ==,
                    GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT);
  g_assert_cmpuint (info->relation_count, ==, expected_relations);
  g_assert_cmpuint (info->queue_state, ==, 1);
  g_assert_cmpuint (info->queue_transaction_counter, ==, 7);
  g_assert_cmpuint (info->registration_count, ==,
                    1 + GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT *
                          (GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1) / 2);
  g_assert_cmpuint (info->graph_established, ==, 1);
  g_assert_cmpint (info->graph_reference_index, ==, 0);
  template_data = g_bytes_get_data (bytes, &template_size);
  g_assert_cmpint (goodix_milan_template_unpack (
                     template_data, template_size, unpacked), ==, 0);
}

void
unpack_study_template (GBytes                      *bytes,
                       GoodixMilanUnpackedTemplate *unpacked)
{
  const guint8 *template_data;
  gsize template_size;

  template_data = g_bytes_get_data (bytes, &template_size);
  g_assert_cmpint (goodix_milan_template_unpack (
                     template_data, template_size, unpacked), ==, 0);
}

void
assert_feature_material_equal (const GoodixMilanFeatureView *actual,
                               const GoodixMilanFeatureView *expected)
{
  g_assert_cmpuint (actual->record_count, ==, expected->record_count);
  g_assert_cmpmem (actual->high_bitmap, 286, expected->high_bitmap, 286);
  g_assert_cmpmem (actual->enhanced_bitmap, 286,
                   expected->enhanced_bitmap, 286);
  g_assert_cmpmem (actual->inline_mask, 72, expected->inline_mask, 72);
  g_assert_cmpmem (actual->low_bitmap, 286, expected->low_bitmap, 286);
  g_assert_cmpmem (actual->packed_records, actual->record_count * 32,
                   expected->packed_records, expected->record_count * 32);
  g_assert_cmpmem (actual->antifake, GOODIX_MILAN_ANTIFAKE_SIZE,
                   expected->antifake, GOODIX_MILAN_ANTIFAKE_SIZE);
}

static void
assert_replacement_relations (const GoodixMilanUnpackedTemplate *unpacked,
                              GoodixMilanStudyAction              action,
                              gsize                               selected_index)
{
  static const gint32 identity_relation[7] = {
    0, 0x100, 0, 0, 0, 0x100, 0,
  };
  gsize relation = 0;

  for (gsize i = 1; i < GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT; i++)
    {
      if (action == GOODIX_MILAN_STUDY_REPLACE_NO_RELATION &&
          i == selected_index)
        continue;
      g_assert_cmpuint (relation, <, unpacked->relation_count);
      g_assert_cmpint (unpacked->relations[relation].index, ==,
                       1 + (gint32) (i * (i - 1) / 2));
      g_assert_cmpmem (unpacked->relations[relation].values,
                       sizeof(identity_relation), identity_relation,
                       sizeof(identity_relation));
      relation++;
    }
  g_assert_cmpuint (relation, ==, unpacked->relation_count);
}

void
assert_replacement_semantics (
  const GoodixMilanUnpackedTemplate *before,
  const GoodixMilanUnpackedTemplate *after,
  const GoodixMilanUnpackedTemplate *probe,
  GoodixMilanStudyAction              action,
  gsize                               selected_index,
  gint32                              generation_count,
  gint32                              lifecycle_count,
  gboolean                            finalize_transaction)
{
  GoodixMilanFeatureView before_selected;
  GoodixMilanFeatureView after_selected;
  GoodixMilanFeatureView probe_view;
  gint32 selected_ordinal;

  g_assert_cmpuint (before->feature_count, ==, after->feature_count);
  g_assert_cmpuint (after->metadata.sensor_type, ==,
                    before->metadata.sensor_type);
  g_assert_cmpuint (after->metadata.maximum_features, ==,
                    before->metadata.maximum_features);
  g_assert_cmpuint (after->metadata.registration_count, ==,
                    before->metadata.registration_count);
  g_assert_cmpuint (after->metadata.maximum_records, ==,
                    before->metadata.maximum_records);
  g_assert_cmpuint (after->metadata.queue_state, ==, 1);
  g_assert_cmpuint (after->metadata.queue_transaction_counter, ==,
                    before->metadata.queue_transaction_counter);
  g_assert_cmpint (after->metadata.graph_reference_index, ==,
                   before->metadata.graph_reference_index);
  g_assert_cmpint (after->metadata.graph_companion_f3, ==,
                   before->metadata.graph_companion_f3);
  g_assert_cmpint (after->metadata.graph_companion_f4, ==,
                   before->metadata.graph_companion_f4);
  g_assert_cmpuint (after->metadata.graph_established, ==,
                    before->metadata.graph_established);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     before->feature_elements[selected_index],
                     before->feature_element_sizes[selected_index],
                     &before_selected), ==, 0);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     after->feature_elements[selected_index],
                     after->feature_element_sizes[selected_index],
                     &after_selected), ==, 0);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     probe->feature_elements[0], probe->feature_element_sizes[0],
                     &probe_view), ==, 0);
  assert_feature_material_equal (&after_selected, &probe_view);
  selected_ordinal = before_selected.fields.tagged_values[7];

  const gint32 expected_selected[11] = {
    action == GOODIX_MILAN_STUDY_REPLACE_NO_RELATION
      ? 0 : before_selected.fields.tagged_values[0],
    before_selected.fields.tagged_values[1],
    probe_view.fields.tagged_values[2],
    probe_view.fields.tagged_values[3],
    probe_view.fields.tagged_values[4],
    before_selected.fields.tagged_values[5] == 0 ? 0 : 2,
    action == GOODIX_MILAN_STUDY_REPLACE_NO_RELATION
      ? before_selected.fields.tagged_values[6] : 0,
    GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT - 1,
    before_selected.fields.tagged_values[8] + generation_count,
    lifecycle_count,
    before_selected.fields.tagged_values[10],
  };

  g_assert_cmpmem (after_selected.fields.tagged_values,
                   sizeof(expected_selected), expected_selected,
                   sizeof(expected_selected));
  g_assert_cmpint (after_selected.fields.optional_c7, ==,
                   before_selected.fields.optional_c7);

  for (gsize i = 0; i < before->feature_count; i++)
    {
      GoodixMilanFeatureView before_view;
      GoodixMilanFeatureView after_view;

      if (i == selected_index)
        continue;
      g_assert_cmpint (goodix_milan_template_parse_feature_element (
                         before->feature_elements[i],
                         before->feature_element_sizes[i], &before_view), ==, 0);
      g_assert_cmpint (goodix_milan_template_parse_feature_element (
                         after->feature_elements[i],
                         after->feature_element_sizes[i], &after_view), ==, 0);
      assert_feature_material_equal (&after_view, &before_view);
      for (gsize field = 0; field < G_N_ELEMENTS (before_view.fields.tagged_values);
           field++)
        {
          gint32 expected = before_view.fields.tagged_values[field];

          if (field == 6 && action != GOODIX_MILAN_STUDY_REPLACE_NO_RELATION)
            expected = 0;
          if (field == 7 && expected > selected_ordinal)
            expected--;
          g_assert_cmpint (after_view.fields.tagged_values[field], ==, expected);
        }
      g_assert_cmpint (after_view.fields.optional_c7, ==,
                       before_view.fields.optional_c7);
    }

  /* Feature zero has zero residual and precedes every replacement ordinal. */
  g_assert_cmpmem (after->feature_elements[0], after->feature_element_sizes[0],
                   before->feature_elements[0], before->feature_element_sizes[0]);
  assert_replacement_relations (after, action, selected_index);
  if (finalize_transaction)
    {
      gsize position = 0;

      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          after->tail_state + position++ * 4), ==,
                        selected_index);
      for (gsize i = before->feature_count; i-- > 0;)
        if (i != selected_index)
          g_assert_cmpuint (goodix_milan_template_read_u32 (
                              after->tail_state + position++ * 4), ==, i);
      g_assert_cmpuint (position, ==, before->feature_count);
      g_assert_cmpmem (after->tail_state + before->feature_count * 4,
                       0x50c - before->feature_count * 4,
                       before->tail_state + before->feature_count * 4,
                       0x50c - before->feature_count * 4);
      g_assert_cmpuint (goodix_milan_template_read_u32 (
                          after->tail_state + 0x50c), ==,
                        goodix_milan_template_read_u32 (
                          before->tail_state + 0x50c) + 1);
    }
  else
    {
      g_assert_cmpmem (after->tail_state, 0x510, before->tail_state, 0x510);
      for (gsize i = 0; i < before->feature_count; i++)
        g_assert_cmpuint (goodix_milan_template_read_u32 (
                            after->tail_state + i * 4), ==, i);
    }
  g_assert_cmpuint (goodix_milan_template_read_u32 (after->tail_state + 0x510),
                    ==,
                    goodix_milan_template_read_u32 (before->tail_state + 0x510) +
                      (guint32) generation_count);
  g_assert_cmpmem (after->tail_state + 0x514,
                   sizeof(after->tail_state) - 0x514,
                   before->tail_state + 0x514,
                   sizeof(before->tail_state) - 0x514);
}
