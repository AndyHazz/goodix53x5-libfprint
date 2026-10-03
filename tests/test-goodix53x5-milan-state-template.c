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
#include "test-goodix53x5-milan-state-tests.h"

#include "drivers/goodix53x5/milan/milan.h"

typedef struct
{
  const gchar *name;
  gsize feature_count;
  gsize record_count;
  gsize relation_count;
  gboolean optional_c7;
  gboolean graph_established;
  guint64 lifecycle_mask;
} TemplateShape;

static GBytes *
synthetic_feature_element (guint    seed,
                           gsize    record_count,
                           gboolean optional_c7)
{
  guint8 high[286];
  guint8 enhanced[286];
  guint8 inline_mask[72];
  guint8 low[286];
  GoodixMilanFeatureRecord *records = g_new0 (
    GoodixMilanFeatureRecord, record_count);
  GoodixMilanAntifakeBlob antifake;
  GoodixMilanFeatureTemplateFields fields = { 0 };
  g_autofree guint8 *packed = g_malloc (7950 + record_count * 32);
  gsize packed_size = 0;

  for (gsize i = 0; i < sizeof(high); i++)
    {
      high[i] = synthetic_byte (seed, i);
      enhanced[i] = synthetic_byte (seed + 1, i);
      low[i] = synthetic_byte (seed + 2, i);
    }
  for (gsize i = 0; i < sizeof(inline_mask); i++)
    inline_mask[i] = synthetic_byte (seed + 3, i);
  for (gsize i = 0; i < sizeof(antifake); i++)
    ((guint8 *) &antifake)[i] = synthetic_byte (seed + 4, i);
  for (gsize record = 0; record < record_count; record++)
    {
      guint8 *bytes = (guint8 *) &records[record];

      for (gsize i = 0; i < sizeof(records[record]); i++)
        bytes[i] = synthetic_byte (seed + 5 + (guint) record, i);
      records[record].foreground = record % 2;
      records[record].refined_x = (gint16) ((0x1200 + record * 0x110) & ~0xf);
      records[record].refined_y = (gint16) ((0x2200 + record * 0x130) & ~0xf);
      records[record].orientation = (gint16) (((gint) record - 1) * 0x100);
    }
  for (gsize i = 0; i < G_N_ELEMENTS (fields.tagged_values); i++)
    fields.tagged_values[i] = (gint32) (seed * 100 + i * 7);
  fields.tagged_values[0] = 0;
  fields.optional_c7 = optional_c7 ? (gint32) (0x100 + seed) : 0;

  {
    g_autofree guint8 *high_before = g_memdup2 (high, sizeof(high));
    g_autofree guint8 *enhanced_before = g_memdup2 (enhanced, sizeof(enhanced));
    g_autofree guint8 *mask_before = g_memdup2 (inline_mask, sizeof(inline_mask));
    g_autofree guint8 *low_before = g_memdup2 (low, sizeof(low));
    g_autofree GoodixMilanFeatureRecord *records_before = g_memdup2 (
      records, record_count * sizeof(*records));
    g_autofree GoodixMilanAntifakeBlob *antifake_before = g_memdup2 (
      &antifake, sizeof(antifake));
    GoodixMilanFeatureTemplateFields fields_before = fields;

    g_assert_cmpint (goodix_milan_template_pack_feature_element (
                       high, enhanced, inline_mask, low, records, record_count,
                       &antifake, &fields, packed,
                       7950 + record_count * 32, &packed_size), ==, 0);
    g_assert_cmpmem (high, sizeof(high), high_before, sizeof(high));
    g_assert_cmpmem (enhanced, sizeof(enhanced), enhanced_before,
                     sizeof(enhanced));
    g_assert_cmpmem (inline_mask, sizeof(inline_mask), mask_before,
                     sizeof(inline_mask));
    g_assert_cmpmem (low, sizeof(low), low_before, sizeof(low));
    g_assert_cmpmem (records, record_count * sizeof(*records), records_before,
                     record_count * sizeof(*records));
    g_assert_cmpmem (&antifake, sizeof(antifake), antifake_before,
                     sizeof(antifake));
    g_assert_cmpmem (&fields, sizeof(fields), &fields_before, sizeof(fields));
  }
  g_free (records);
  return g_bytes_new (packed, packed_size);
}

static void
assert_feature_roundtrip (GBytes *feature,
                          gsize   partition_count)
{
  const guint8 *packed;
  gsize packed_size;
  GoodixMilanFeatureView view;
  g_autofree GoodixMilanFeatureRecord *records = NULL;
  g_autofree guint8 *repacked = NULL;
  gsize repacked_size = 0;

  packed = g_bytes_get_data (feature, &packed_size);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     packed, packed_size, &view), ==, 0);
  records = g_new0 (GoodixMilanFeatureRecord, view.record_count);
  repacked = g_malloc (packed_size);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, view.record_count, partition_count,
                     records, view.record_count), ==, 0);
  g_assert_cmpint (goodix_milan_template_pack_feature_element (
                     view.high_bitmap, view.enhanced_bitmap, view.inline_mask,
                     view.low_bitmap, records, view.record_count, view.antifake,
                     &view.fields, repacked, packed_size, &repacked_size), ==, 0);
  g_assert_cmpuint (repacked_size, ==, packed_size);
  g_assert_cmpmem (repacked, repacked_size, packed, packed_size);
}

void
test_template_state (void)
{
  static const TemplateShape shapes[] = {
    { "single-graphless", 1, 1, 0, FALSE, FALSE, UINT64_C (1) },
    { "multi-graph", 3, 4, 2, TRUE, TRUE, UINT64_C (5) },
  };

  for (gsize shape_index = 0; shape_index < G_N_ELEMENTS (shapes);
       shape_index++)
    {
      const TemplateShape *shape = &shapes[shape_index];
      GBytes *features[3] = { NULL };
      GBytes *feature_snapshots[3] = { NULL };
      const guint8 *feature_data[3] = { NULL };
      gsize feature_sizes[3] = { 0 };
      GoodixMilanTemplateRelation relations[2] = { 0 };
      GoodixMilanTemplateMetadata metadata = { 0 };
      guint8 tail[0x520];
      g_autofree guint8 *tail_before = NULL;
      g_autofree guint8 *packed = NULL;
      g_autofree guint8 *input_before = NULL;
      g_autofree guint8 *repacked = NULL;
      g_autofree guint8 *updated = NULL;
      g_autofree guint8 *updated_twice = NULL;
      g_autofree GoodixMilanUnpackedTemplate *unpacked = g_new0 (
        GoodixMilanUnpackedTemplate, 1);
      g_autofree GoodixMilanUnpackedTemplate *twice = g_new0 (
        GoodixMilanUnpackedTemplate, 1);
      gsize capacity;
      gsize packed_size = 0;
      gsize repacked_size = 0;
      gsize updated_size = 0;
      gsize updated_twice_size = 0;
      gsize rejected_size = 0;

      g_test_message ("template shape=%s", shape->name);
      for (gsize i = 0; i < shape->feature_count; i++)
        {
          features[i] = synthetic_feature_element (
            (guint) (shape_index * 10 + i + 1), shape->record_count,
            shape->optional_c7);
          feature_data[i] = g_bytes_get_data (features[i], &feature_sizes[i]);
          feature_snapshots[i] = g_bytes_new (feature_data[i], feature_sizes[i]);
          assert_feature_roundtrip (features[i], shape->record_count / 2);
        }
      for (gsize i = 0; i < shape->relation_count; i++)
        {
          static const gint32 identity_relation[7] = {
            205, 0x100, 0, 0, 0, 0x100, 0,
          };

          relations[i].index = (gint32) i + 1;
          memcpy (relations[i].values, identity_relation,
                  sizeof(identity_relation));
        }
      metadata.sensor_type = 12;
      metadata.maximum_features = GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT;
      metadata.registration_count = 7;
      metadata.maximum_records = 150;
      metadata.queue_state = 0;
      metadata.queue_transaction_counter = (guint32) (30 + shape_index);
      metadata.graph_reference_index = shape->graph_established ? 0 : -1;
      metadata.graph_companion_f3 = -1;
      metadata.graph_companion_f4 = -1;
      metadata.graph_established = shape->graph_established;
      for (gsize i = 0; i < sizeof(tail); i++)
        tail[i] = synthetic_byte ((guint) shape_index + 20, i);

      capacity = 1433 + shape->relation_count * 45;
      for (gsize i = 0; i < shape->feature_count; i++)
        capacity += feature_sizes[i];
      packed = g_malloc (capacity);
      repacked = g_malloc (capacity);
      updated = g_malloc (capacity);
      updated_twice = g_malloc (capacity);
      tail_before = g_memdup2 (tail, sizeof(tail));
      g_assert_cmpint (goodix_milan_template_pack (
                         feature_data, feature_sizes, shape->feature_count,
                         relations, shape->relation_count, &metadata, tail,
                         sizeof(tail), packed, capacity, &packed_size), ==, 0);
      g_assert_cmpuint (packed_size, ==, capacity);
      g_assert_cmpmem (tail, sizeof(tail), tail_before, sizeof(tail));
      for (gsize i = 0; i < shape->feature_count; i++)
        g_assert_true (feature_data[i] == g_bytes_get_data (features[i], NULL));

      input_before = g_memdup2 (packed, packed_size);
      g_assert_cmpint (goodix_milan_template_unpack (
                         packed, packed_size, unpacked), ==, 0);
      g_assert_cmpmem (packed, packed_size, input_before, packed_size);
      g_assert_cmpuint (unpacked->feature_count, ==, shape->feature_count);
      g_assert_cmpuint (unpacked->relation_count, ==, shape->relation_count);
      g_assert_cmpmem (&unpacked->metadata, sizeof(unpacked->metadata),
                       &metadata, sizeof(metadata));
      g_assert_cmpint (goodix_milan_template_pack (
                         unpacked->feature_elements,
                         unpacked->feature_element_sizes,
                         unpacked->feature_count, unpacked->relations,
                         unpacked->relation_count, &unpacked->metadata,
                         unpacked->tail_state, sizeof(unpacked->tail_state),
                         repacked, capacity, &repacked_size), ==, 0);
      g_assert_cmpuint (repacked_size, ==, packed_size);
      g_assert_cmpmem (repacked, repacked_size, packed, packed_size);

      g_assert_cmpint (goodix_milan_template_update_match_lifecycle (
                         packed, packed_size, 0, false, updated, capacity,
                         &updated_size), ==, 0);
      g_assert_cmpuint (updated_size, ==, packed_size);
      g_assert_cmpmem (updated, updated_size, packed, packed_size);
      g_assert_cmpmem (packed, packed_size, input_before, packed_size);
      g_assert_cmpint (goodix_milan_template_update_match_lifecycle (
                         packed, packed_size, shape->lifecycle_mask, false, updated,
                         capacity, &updated_size), ==, 0);
      g_assert_cmpint (goodix_milan_template_update_match_lifecycle (
                         updated, updated_size, shape->lifecycle_mask,
                         false, updated_twice, capacity, &updated_twice_size), ==, 0);
      g_assert_cmpuint (updated_size, ==, packed_size);
      g_assert_cmpuint (updated_twice_size, ==, packed_size);
      g_assert_cmpmem (packed, packed_size, input_before, packed_size);
      g_assert_cmpint (goodix_milan_template_update_match_lifecycle (
                         packed, packed_size,
                         UINT64_C (1) << shape->feature_count, false, repacked,
                         capacity, &rejected_size), ==, -1);
      g_assert_cmpmem (packed, packed_size, input_before, packed_size);
      memset (unpacked, 0, sizeof(*unpacked));
      g_assert_cmpint (goodix_milan_template_unpack (
                         updated, updated_size, unpacked), ==, 0);
      g_assert_cmpint (goodix_milan_template_unpack (
                         updated_twice, updated_twice_size, twice), ==, 0);
      for (gsize i = 0; i < shape->feature_count; i++)
        {
          GoodixMilanFeatureView before_view;
          GoodixMilanFeatureView after_view;
          gint increment = (gint) ((shape->lifecycle_mask >> i) & 1);

          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             feature_data[i], feature_sizes[i],
                             &before_view), ==, 0);
          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             unpacked->feature_elements[i],
                             unpacked->feature_element_sizes[i],
                             &after_view), ==, 0);
          g_assert_cmpint (after_view.fields.tagged_values[9], ==,
                           before_view.fields.tagged_values[9] + increment);
          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             twice->feature_elements[i],
                             twice->feature_element_sizes[i],
                             &after_view), ==, 0);
          g_assert_cmpint (after_view.fields.tagged_values[9], ==,
                           before_view.fields.tagged_values[9] + 2 * increment);
        }

      if (!shape->graph_established)
        {
          g_autofree guint8 *normalized = g_malloc (capacity);
          g_autofree guint8 *renormalized = g_malloc (capacity);
          gsize normalized_size = 0;
          gsize renormalized_size = 0;

          g_assert_cmpint (goodix_milan_template_normalize (
                             packed, packed_size, normalized, capacity,
                             &normalized_size), ==, 0);
          g_assert_cmpint (goodix_milan_template_normalize (
                             normalized, normalized_size, renormalized,
                             capacity, &renormalized_size), ==, 0);
          g_assert_cmpuint (normalized_size, ==, renormalized_size);
          g_assert_cmpmem (normalized, normalized_size, renormalized,
                           renormalized_size);
          g_assert_cmpmem (packed, packed_size, input_before, packed_size);
        }

      for (gsize i = 0; i < shape->feature_count; i++)
        {
          g_assert_true (g_bytes_equal (features[i], feature_snapshots[i]));
          g_bytes_unref (feature_snapshots[i]);
          g_bytes_unref (features[i]);
        }
    }
}
