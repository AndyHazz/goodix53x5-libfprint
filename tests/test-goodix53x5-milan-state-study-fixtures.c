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

GBytes *
study_feature_element (guint    seed,
                       gboolean matchable,
                       gint32   active,
                       gint32   state,
                       gint32   residual,
                       gint32   ordinal,
                       gint32   marker)
{
  const gsize record_count = matchable ? 150 : 1;
  guint8 high[286];
  guint8 enhanced[286];
  guint8 inline_mask[72];
  guint8 low[286];
  g_autofree GoodixMilanFeatureRecord *records = g_new0 (
    GoodixMilanFeatureRecord, record_count);
  GoodixMilanAntifakeBlob antifake = { 0 };
  GoodixMilanFeatureTemplateFields fields = { 0 };
  g_autofree guint8 *packed = g_malloc (7950 + record_count * 32);
  gsize packed_size = 0;

  /* Exact uniform maps are rejected by overlap admission; this balanced
   * pattern supplies both zero and one agreement classes. */
  for (gsize i = 0; i < sizeof(high); i++)
    {
      high[i] = matchable ? 0xaa : synthetic_byte (seed, i);
      enhanced[i] = matchable ? 0xaa : synthetic_byte (seed + 1, i);
      low[i] = matchable ? 0xaa : synthetic_byte (seed + 2, i);
    }
  memset (inline_mask, matchable ? 0xff : 0, sizeof(inline_mask));
  for (gsize i = 0; i < record_count; i++)
    {
      records[i].foreground = 1;
      records[i].refined_x = matchable
                               ? (gint16) ((4 + (i % 15) * 6) * 0x100)
                               : (gint16) (0x1200 + seed * 0x100);
      records[i].refined_y = matchable
                               ? (gint16) ((4 + (i / 15) * 8) * 0x100)
                               : (gint16) (0x2200 + seed * 0x100);
      records[i].orientation = matchable
                                 ? (gint16) (((gint) (i % 16) - 8) * 0x100)
                                 : (gint16) (seed * 0x100);
      for (gsize byte = 0; byte < sizeof(records[i].payload); byte++)
        records[i].payload[byte] = matchable
                                     ? (guint8) (seed * 13 + i * 7 + byte * 3)
                                     : (guint8) (seed + byte);
      memset (records[i].payload + 24, 0, 4);
      memset (records[i].payload + 36, 0, 8);
    }
  fields.tagged_values[0] = active;
  fields.tagged_values[1] = ordinal == 0
                              ? 0
                              : 1 + ordinal * (ordinal - 1) / 2;
  fields.tagged_values[2] = 0;
  fields.tagged_values[3] = matchable ? 100 : 50;
  fields.tagged_values[4] = matchable ? 100 : 80;
  fields.tagged_values[5] = state;
  fields.tagged_values[6] = residual;
  fields.tagged_values[7] = ordinal;
  goodix_milan_antifake_set_calibration_scalar (&antifake, marker);

  g_assert_cmpint (goodix_milan_template_pack_feature_element (
                     high, enhanced, inline_mask, low, records, record_count,
                     &antifake, &fields, packed, 7950 + record_count * 32,
                     &packed_size), ==, 0);
  return g_bytes_new (packed, packed_size);
}

GoodixMatchInfo *
study_match_info_from_feature (GBytes  *feature,
                               gboolean matchable)
{
  GoodixMatchInfo *info = goodix_milan_match_info_new_empty ();
  const guint8 *feature_data;
  gsize feature_size;
  guint8 tail[0x520] = { 0 };
  g_autofree guint8 *packed = NULL;
  size_t packed_size = 0;
  GoodixMilanFeatureView view;

  feature_data = g_bytes_get_data (feature, &feature_size);
  packed = g_malloc (1433 + feature_size);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     feature_data, feature_size, &view), ==, 0);
  g_assert_cmpint (goodix_milan_template_pack_one_feature (
                     feature_data, feature_size, tail, sizeof(tail), packed,
                     1433 + feature_size, &packed_size), ==, 0);
  info->template = g_bytes_new_take (g_steal_pointer (&packed), packed_size);
  info->record_count = (gint) view.record_count;
  info->partition_count = view.fields.tagged_values[2];
  info->records = g_new0 (GoodixMilanFeatureRecord, view.record_count);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, view.record_count,
                     (gsize) info->partition_count, info->records,
                     view.record_count), ==, 0);
  memcpy (info->feature_bitmaps.high_bitmap, view.high_bitmap,
          sizeof(info->feature_bitmaps.high_bitmap));
  memcpy (info->feature_bitmaps.enhanced_bitmap, view.enhanced_bitmap,
          sizeof(info->feature_bitmaps.enhanced_bitmap));
  memcpy (info->feature_bitmaps.low_bitmap, view.low_bitmap,
          sizeof(info->feature_bitmaps.low_bitmap));
  memcpy (info->inline_mask, view.inline_mask, sizeof(info->inline_mask));
  memset (info->rescue_mask, matchable ? 0xff : 0,
          sizeof(info->rescue_mask));
  memcpy (&info->antifake, view.antifake, sizeof(info->antifake));
  info->extraction_metadata.quality = view.fields.tagged_values[3];
  info->extraction_metadata.coverage = view.fields.tagged_values[4];
  info->extraction_metadata.optional_c7 = view.fields.optional_c7;
  g_assert_true (goodix_milan_match_info_is_complete (info));
  return info;
}

GoodixMatchInfo *
study_match_info (guint    seed,
                  gboolean matchable,
                  gint32   marker)
{
  g_autoptr(GBytes) feature = study_feature_element (
    seed, matchable, 0, 0, 0, 0, marker);

  return study_match_info_from_feature (feature, matchable);
}

GBytes *
study_gallery (GoodixMilanStudyAction action,
               gboolean               matchable_enrolled)
{
  enum { N_FEATURES = GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT };
  GBytes *features[N_FEATURES] = { 0 };
  const guint8 *feature_data[N_FEATURES];
  gsize feature_sizes[N_FEATURES];
  GoodixMilanTemplateRelation relations[N_FEATURES - 1] = { 0 };
  GoodixMilanTemplateMetadata metadata = { 0 };
  guint8 tail[0x520] = { 0 };
  g_autofree guint8 *packed = NULL;
  gsize capacity = 1433 + G_N_ELEMENTS (relations) * 45;
  gsize packed_size = 0;
  GBytes *template_bytes;

  for (gsize i = 0; i < N_FEATURES; i++)
    {
      gint32 state = action == GOODIX_MILAN_STUDY_GEOMETRIC && i + 1 < N_FEATURES
                       ? 5 : 1;
      gboolean matchable = matchable_enrolled && i == 1;
      gint32 residual = i == 0 ? 0
                         : action == GOODIX_MILAN_STUDY_GEOMETRIC
                             ? 20 : (i == 1 ? 0 : 20);

      features[i] = study_feature_element (
        matchable ? 9 : (guint) i + 1, matchable, 1, state, residual,
        (gint32) i, 0);
      feature_data[i] = g_bytes_get_data (features[i], &feature_sizes[i]);
      capacity += feature_sizes[i];
      goodix_milan_template_write_u32 (tail + i * 4, (guint32) i);
      if (i != 0)
        {
          static const gint32 identity_relation[7] = {
            0, 0x100, 0, 0, 0, 0x100, 0,
          };

          relations[i - 1].index = 1 + (gint32) (i * (i - 1) / 2);
          memcpy (relations[i - 1].values, identity_relation,
                  sizeof(identity_relation));
        }
    }
  metadata.sensor_type = 12;
  metadata.maximum_features = N_FEATURES;
  metadata.registration_count = 1 + N_FEATURES * (N_FEATURES - 1) / 2;
  metadata.maximum_records = 150;
  metadata.queue_state = 0;
  metadata.queue_transaction_counter = 7;
  metadata.graph_reference_index = 0;
  metadata.graph_companion_f3 = -1;
  metadata.graph_companion_f4 = -1;
  metadata.graph_established = 1;

  packed = g_malloc (capacity);
  g_assert_cmpint (goodix_milan_template_pack (
                     feature_data, feature_sizes, N_FEATURES, relations,
                     G_N_ELEMENTS (relations), &metadata, tail, sizeof(tail),
                     packed, capacity, &packed_size), ==, 0);
  template_bytes = g_bytes_new_take (g_steal_pointer (&packed), packed_size);
  for (gsize i = 0; i < N_FEATURES; i++)
    g_bytes_unref (features[i]);
  return template_bytes;
}

GoodixMilanMatchResult
study_primary_result (gint32 retained_flag)
{
  GoodixMilanMatchResult result = {
    .matched_feature_index = 1,
    .score = 1,
    .match_transform = { 0x100, 0, 0, 0, 0x100, 0 },
    .relation = {
      .relation_count = 1,
      .relation_values = { 0, 0x100, 0, 0, 0, 0x100, 0 },
      .relation_valid = 1,
    },
    .retained_evidence_flag = retained_flag,
    .study_control.study_action_gate = 1,
  };

  return result;
}

GBytes *
ordered_match_feature (gint32 ordinal,
                       gint32 translation)
{
  g_autoptr(GBytes) base = study_feature_element (
    9, TRUE, ordinal != 0, ordinal != 0, ordinal == 2 ? 20 : 0,
    ordinal, ordinal * 111);
  GoodixMilanFeatureView view;
  GoodixMilanFeatureRecord records[150];
  gsize size;
  gsize packed_size = 0;
  const guint8 *data = g_bytes_get_data (base, &size);
  g_autofree guint8 *packed = g_malloc (size);

  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     data, size, &view), ==, 0);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, 150, 0, records, 150), ==, 0);
  for (gsize i = 0; i < G_N_ELEMENTS (records); i++)
    {
      /* Canonical packed angles; the four-pixel translation preserves the
       * balanced bitmap's period and keeps every record inside the image. */
      records[i].orientation = (gint16) ((i % 16) * 0x100);
      records[i].refined_x += translation * 0x100;
    }
  g_assert_cmpint (goodix_milan_template_pack_feature_element (
                     view.high_bitmap, view.enhanced_bitmap, view.inline_mask,
                     view.low_bitmap, records, 150, view.antifake, &view.fields,
                     packed, size, &packed_size), ==, 0);
  return g_bytes_new_take (g_steal_pointer (&packed), packed_size);
}
