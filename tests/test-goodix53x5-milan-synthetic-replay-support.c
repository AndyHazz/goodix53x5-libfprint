/*
 * Goodix 53x5 driver for libfprint - generated Milan parity tests
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-synthetic-replay-support.h"
#include "drivers/goodix53x5/milan/match/info-private.h"
#include "drivers/goodix53x5/milan/private.h"
#include "drivers/goodix53x5/milan/template/codec-private.h"

#include <string.h>

static void
unpack_test_template (GBytes                       *template_bytes,
                       GoodixMilanUnpackedTemplate *unpacked)
{
  const guint8 *data;
  gsize size;

  data = g_bytes_get_data (template_bytes, &size);
  g_assert_cmpint (goodix_milan_template_unpack (data, size, unpacked), ==, 0);
}

static int32_t
distinct_fixture_scalar (int32_t probe_value,
                         int32_t fixture_value)
{
  return probe_value == fixture_value ? fixture_value + 1 : fixture_value;
}

GoodixMatchInfo *
make_distinct_append_fixture (const GoodixMatchInfo *probe)
{
  static const struct
  {
    size_t field;
    uint8_t tag;
  } probe_owned_fields[] = {
    { 2, 0xb7 }, { 3, 0xb8 }, { 4, 0xb9 }, { 8, 0xbd }, { 10, 0xc0 },
  };
  GoodixMatchInfo *fixture = goodix_milan_match_info_new_empty ();
  g_autofree GoodixMilanUnpackedTemplate *unpacked = g_new0 (
    GoodixMilanUnpackedTemplate, 1);
  g_autofree guint8 *feature_element = NULL;
  g_autofree guint8 *packed = NULL;
  GoodixMilanFeatureView serialized_view;
  GoodixMilanAntifakeBlob *serialized_antifake;
  GBytes *template_bytes;
  gsize template_size;
  size_t packed_size = 0;

  g_assert_true (goodix_milan_match_info_copy (fixture, probe));
  goodix_milan_antifake_set_texture (
    &fixture->antifake,
    distinct_fixture_scalar (goodix_milan_antifake_texture (&probe->antifake),
                             0x1020304));
  goodix_milan_antifake_set_mean (
    &fixture->antifake,
    distinct_fixture_scalar (goodix_milan_antifake_mean (&probe->antifake),
                             -0x1020304));
  goodix_milan_antifake_set_threshold (
    &fixture->antifake,
    distinct_fixture_scalar (goodix_milan_antifake_threshold (&probe->antifake),
                             0x11223344));
  goodix_milan_antifake_set_pair_score (
    &fixture->antifake,
    distinct_fixture_scalar (goodix_milan_antifake_pair_score (&probe->antifake),
                             -0x11223344));
  goodix_milan_antifake_mask (&fixture->antifake)[0] ^= 1;
  g_assert_cmpint (goodix_milan_antifake_texture (&fixture->antifake),
                   !=, goodix_milan_antifake_texture (&probe->antifake));
  g_assert_cmpint (goodix_milan_antifake_mean (&fixture->antifake),
                   !=, goodix_milan_antifake_mean (&probe->antifake));
  g_assert_cmpint (goodix_milan_antifake_threshold (&fixture->antifake),
                   !=, goodix_milan_antifake_threshold (&probe->antifake));
  g_assert_cmpint (goodix_milan_antifake_pair_score (&fixture->antifake),
                   !=, goodix_milan_antifake_pair_score (&probe->antifake));

  unpack_test_template (fixture->template, unpacked);
  g_assert_cmpuint (unpacked->feature_count, ==, 1);
  feature_element = g_memdup2 (unpacked->feature_elements[0],
                               unpacked->feature_element_sizes[0]);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     feature_element, unpacked->feature_element_sizes[0],
                     &serialized_view), ==, 0);
  g_assert_cmpuint (serialized_view.record_count, >, 0);
  ((guint8 *) serialized_view.high_bitmap)[285] ^= 1;
  ((guint8 *) serialized_view.enhanced_bitmap)[285] ^= 1;
  ((guint8 *) serialized_view.inline_mask)[71] ^= 1;
  ((guint8 *) serialized_view.low_bitmap)[285] ^= 1;
  ((guint8 *) serialized_view.packed_records)[
    serialized_view.record_count * 32 - 1] ^= 1;
  for (size_t i = 0; i < G_N_ELEMENTS (probe_owned_fields); i++)
    {
      int32_t value =
        serialized_view.fields.tagged_values[probe_owned_fields[i].field];

      g_assert_cmpint (goodix_milan_template_patch_feature_scalar (
                         feature_element, unpacked->feature_element_sizes[0],
                         probe_owned_fields[i].tag,
                         value == 0 ? 1 : value - 1), ==, 0);
    }
  g_assert_cmpint (goodix_milan_template_patch_feature_scalar (
                     feature_element, unpacked->feature_element_sizes[0],
                     0xbe,
                     distinct_fixture_scalar (
                       serialized_view.fields.tagged_values[9], 1)), ==, 0);
  serialized_antifake = (GoodixMilanAntifakeBlob *) serialized_view.antifake;
  memcpy (serialized_antifake, &fixture->antifake, sizeof(*serialized_antifake));
  unpacked->feature_elements[0] = feature_element;
  template_size = g_bytes_get_size (fixture->template);
  packed = g_malloc (template_size);
  g_assert_cmpint (goodix_milan_template_pack (
                     unpacked->feature_elements,
                     unpacked->feature_element_sizes,
                     unpacked->feature_count, unpacked->relations,
                     unpacked->relation_count, &unpacked->metadata,
                     unpacked->tail_state, sizeof(unpacked->tail_state), packed,
                      template_size, &packed_size), ==, 0);
  g_assert_cmpuint (packed_size, ==, template_size);
  template_bytes = g_bytes_new_take (g_steal_pointer (&packed), packed_size);
  g_clear_pointer (&fixture->template, g_bytes_unref);
  fixture->template = template_bytes;
  return fixture;
}

static void
assert_antifake_append_ownership (const GoodixMilanAntifakeBlob *actual,
                                  const GoodixMilanAntifakeBlob *probe,
                                  const GoodixMilanAntifakeBlob *matched)
{
  static const size_t inherited_scalar_offsets[] = {
    GOODIX_MILAN_ANTIFAKE_TEXTURE_OFFSET,
    GOODIX_MILAN_ANTIFAKE_MEAN_OFFSET,
    GOODIX_MILAN_ANTIFAKE_THRESHOLD_OFFSET,
    GOODIX_MILAN_ANTIFAKE_PAIR_SCORE_OFFSET,
  };
  const guint8 *actual_data = goodix_milan_antifake_const_data (actual);
  const guint8 *probe_data = goodix_milan_antifake_const_data (probe);
  const guint8 *matched_data = goodix_milan_antifake_const_data (matched);
  size_t start = 0;

  for (size_t i = 0; i < G_N_ELEMENTS (inherited_scalar_offsets); i++)
    {
      size_t offset = inherited_scalar_offsets[i];

      g_assert_cmpmem (actual_data + start, offset - start,
                       probe_data + start, offset - start);
      start = offset + sizeof(int32_t);
    }
  g_assert_cmpmem (actual_data + start, GOODIX_MILAN_ANTIFAKE_SIZE - start,
                   probe_data + start, GOODIX_MILAN_ANTIFAKE_SIZE - start);
  g_assert_cmpint (actual_data[GOODIX_MILAN_ANTIFAKE_MASK_OFFSET],
                   ==, probe_data[GOODIX_MILAN_ANTIFAKE_MASK_OFFSET]);
  g_assert_cmpint (actual_data[GOODIX_MILAN_ANTIFAKE_MASK_OFFSET],
                   !=, matched_data[GOODIX_MILAN_ANTIFAKE_MASK_OFFSET]);
  g_assert_cmpint (goodix_milan_antifake_texture (actual),
                   ==, goodix_milan_antifake_texture (matched));
  g_assert_cmpint (goodix_milan_antifake_mean (actual),
                   ==, goodix_milan_antifake_mean (matched));
  g_assert_cmpint (goodix_milan_antifake_threshold (actual),
                   ==, goodix_milan_antifake_threshold (matched));
  g_assert_cmpint (goodix_milan_antifake_pair_score (actual),
                   ==, goodix_milan_antifake_pair_score (matched));
  g_assert_cmpint (goodix_milan_antifake_texture (actual),
                   !=, goodix_milan_antifake_texture (probe));
  g_assert_cmpint (goodix_milan_antifake_mean (actual),
                   !=, goodix_milan_antifake_mean (probe));
  g_assert_cmpint (goodix_milan_antifake_threshold (actual),
                   !=, goodix_milan_antifake_threshold (probe));
  g_assert_cmpint (goodix_milan_antifake_pair_score (actual),
                   !=, goodix_milan_antifake_pair_score (probe));
  g_assert_cmpint (goodix_milan_antifake_texture (matched),
                   !=, goodix_milan_antifake_texture (probe));
  g_assert_cmpint (goodix_milan_antifake_mean (matched),
                   !=, goodix_milan_antifake_mean (probe));
  g_assert_cmpint (goodix_milan_antifake_threshold (matched),
                   !=, goodix_milan_antifake_threshold (probe));
  g_assert_cmpint (goodix_milan_antifake_pair_score (matched),
                   !=, goodix_milan_antifake_pair_score (probe));
}

void
assert_generic_append_material (GBytes *probe,
                                GBytes *before,
                                GBytes *after)
{
  static const size_t probe_owned_fields[] = { 2, 3, 4, 8, 10 };
  static const int32_t appended_relation_values[7] = {
    0, 0x100, 0, 0, 0, 0x100, 0,
  };
  g_autofree GoodixMilanUnpackedTemplate *probe_template = g_new0 (
    GoodixMilanUnpackedTemplate, 1);
  g_autofree GoodixMilanUnpackedTemplate *before_template = g_new0 (
    GoodixMilanUnpackedTemplate, 1);
  g_autofree GoodixMilanUnpackedTemplate *after_template = g_new0 (
    GoodixMilanUnpackedTemplate, 1);
  GoodixMilanFeatureView probe_view;
  GoodixMilanFeatureView matched_view;
  GoodixMilanFeatureView inserted_view;
  const GoodixMilanTemplateRelation *appended_relation = NULL;
  size_t inserted_index;

  unpack_test_template (probe, probe_template);
  unpack_test_template (before, before_template);
  unpack_test_template (after, after_template);
  inserted_index = before_template->feature_count;
  g_assert_cmpuint (probe_template->feature_count, ==, 1);
  g_assert_cmpuint (after_template->feature_count, ==, inserted_index + 1);

  for (size_t i = 0; i < before_template->feature_count; i++)
    {
      g_assert_cmpuint (after_template->feature_element_sizes[i],
                        ==, before_template->feature_element_sizes[i]);
      g_assert_cmpmem (after_template->feature_elements[i],
                       after_template->feature_element_sizes[i],
                       before_template->feature_elements[i],
                       before_template->feature_element_sizes[i]);
    }
  g_assert_cmpuint (after_template->relation_count,
                    ==, before_template->relation_count + 1);
  for (size_t i = 0; i < before_template->relation_count; i++)
    {
      gboolean found = FALSE;

      for (size_t j = 0; j < after_template->relation_count; j++)
        if (after_template->relations[j].index ==
            before_template->relations[i].index)
          {
            found = TRUE;
            for (size_t value = 0;
                 value < G_N_ELEMENTS (before_template->relations[i].values);
                 value++)
              g_assert_cmpint (after_template->relations[j].values[value],
                               ==, before_template->relations[i].values[value]);
            break;
          }
      g_assert_true (found);
    }
  for (size_t i = 0; i < after_template->relation_count; i++)
    if (after_template->relations[i].index ==
        (int32_t) before_template->metadata.registration_count)
      {
        appended_relation = &after_template->relations[i];
        break;
      }
  g_assert_nonnull (appended_relation);
  g_assert_cmpint (appended_relation->index,
                   ==, (int32_t) before_template->metadata.registration_count);
  for (size_t i = 0; i < G_N_ELEMENTS (appended_relation_values); i++)
    g_assert_cmpint (appended_relation->values[i],
                     ==, appended_relation_values[i]);

  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     probe_template->feature_elements[0],
                     probe_template->feature_element_sizes[0],
                     &probe_view), ==, 0);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     before_template->feature_elements[0],
                     before_template->feature_element_sizes[0],
                     &matched_view), ==, 0);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     after_template->feature_elements[inserted_index],
                     after_template->feature_element_sizes[inserted_index],
                     &inserted_view), ==, 0);
  g_assert_cmpuint (inserted_view.record_count, ==, probe_view.record_count);
  g_assert_cmpuint (matched_view.record_count, ==, probe_view.record_count);
  g_assert_cmpmem (inserted_view.high_bitmap, 286, probe_view.high_bitmap, 286);
  g_assert_cmpint (memcmp (inserted_view.high_bitmap,
                           matched_view.high_bitmap, 286), !=, 0);
  g_assert_cmpmem (inserted_view.enhanced_bitmap, 286,
                   probe_view.enhanced_bitmap, 286);
  g_assert_cmpint (memcmp (inserted_view.enhanced_bitmap,
                           matched_view.enhanced_bitmap, 286), !=, 0);
  g_assert_cmpmem (inserted_view.inline_mask, 72, probe_view.inline_mask, 72);
  g_assert_cmpint (memcmp (inserted_view.inline_mask,
                           matched_view.inline_mask, 72), !=, 0);
  g_assert_cmpmem (inserted_view.low_bitmap, 286, probe_view.low_bitmap, 286);
  g_assert_cmpint (memcmp (inserted_view.low_bitmap,
                           matched_view.low_bitmap, 286), !=, 0);
  g_assert_cmpmem (inserted_view.packed_records, inserted_view.record_count * 32,
                   probe_view.packed_records, probe_view.record_count * 32);
  g_assert_cmpint (memcmp (inserted_view.packed_records,
                           matched_view.packed_records,
                           inserted_view.record_count * 32), !=, 0);
  for (size_t i = 0; i < G_N_ELEMENTS (probe_owned_fields); i++)
    {
      size_t field = probe_owned_fields[i];

      g_assert_cmpint (inserted_view.fields.tagged_values[field],
                       ==, probe_view.fields.tagged_values[field]);
      g_assert_cmpint (inserted_view.fields.tagged_values[field],
                       !=, matched_view.fields.tagged_values[field]);
    }
  g_assert_cmpint (inserted_view.fields.tagged_values[0],
                   ==, matched_view.fields.tagged_values[0]);
  g_assert_cmpint (inserted_view.fields.tagged_values[0],
                   !=, probe_view.fields.tagged_values[0]);
  g_assert_cmpint (inserted_view.fields.tagged_values[1],
                   ==, (int32_t) before_template->metadata.registration_count);
  g_assert_cmpint (inserted_view.fields.tagged_values[5], ==, 1);
  g_assert_cmpint (inserted_view.fields.tagged_values[6], ==, 0);
  g_assert_cmpint (inserted_view.fields.tagged_values[7],
                   ==, (int32_t) before_template->feature_count);
  g_assert_cmpint (inserted_view.fields.tagged_values[9],
                   ==, matched_view.fields.tagged_values[9]);
  g_assert_cmpint (inserted_view.fields.tagged_values[9],
                   !=, probe_view.fields.tagged_values[9]);
  assert_antifake_append_ownership (inserted_view.antifake,
                                    probe_view.antifake,
                                    matched_view.antifake);

  g_assert_cmpuint (after_template->metadata.registration_count,
                    ==, before_template->metadata.registration_count +
                        before_template->feature_count);
  for (size_t i = 0; i < before_template->feature_count; i++)
    g_assert_cmpuint (goodix_milan_template_read_u32 (
                        after_template->tail_state + i * 4),
                      ==, goodix_milan_template_read_u32 (
                            before_template->tail_state + i * 4));
  g_assert_cmpuint (goodix_milan_template_read_u32 (
                      after_template->tail_state + inserted_index * 4),
                    ==, inserted_index);
  g_assert_cmpuint (goodix_milan_template_read_u32 (
                      after_template->tail_state + 0x50c),
                    ==, goodix_milan_template_read_u32 (
                          before_template->tail_state + 0x50c));
  g_assert_cmpuint (goodix_milan_template_read_u32 (
                      after_template->tail_state + 0x510),
                    ==, goodix_milan_template_read_u32 (
                          before_template->tail_state + 0x510));
  g_assert_cmpuint (goodix_milan_template_read_u32 (
                      after_template->tail_state + 0x514),
                    ==, goodix_milan_template_read_u32 (
                          before_template->tail_state + 0x514) + 1);
}
