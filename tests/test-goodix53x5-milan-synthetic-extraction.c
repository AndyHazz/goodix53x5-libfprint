/*
 * Goodix 53x5 driver for libfprint - generated Milan parity tests
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-synthetic-tests.h"
#include "test-goodix53x5-milan-synthetic-support.h"
#include "drivers/goodix53x5/milan/private.h"
#include "drivers/goodix53x5/milan/print.h"
#include "drivers/goodix53x5/milan/template/codec-private.h"

#include <string.h>

static const char feature_extraction_sha256[] =
  "9e437d34f92961cae27524c837599e06047a4ce958d6a813034b440063ef9c74";
static const char feature_template_sha256[] =
  "836ab209f8504f0b222f16567e5d7a8ba438da54ffe17df403501092cb6f85c0";
static const char feature_antifake_sha256[] =
  "5b2763131c54a5bfbeea4409278eaa7a6f23fd019cdc00f63c5fb35596ff74dc";

static void
test_negative_orientation_scaling (void)
{
  static const struct
  {
    uint8_t packed;
    int16_t expected;
  } cases[] = {
    { 0x81, -256 },
    { 0xff, -32512 },
  };

  for (size_t i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      uint8_t packed_record[32] = { 0 };
      GoodixMilanFeatureRecord record;

      packed_record[0] = cases[i].packed;
      g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                         packed_record, 1, 0, &record, 1), ==, 0);
      g_assert_cmpint (record.orientation, ==, cases[i].expected);
    }
}

void
test_generated_extraction (void)
{
  g_autofree GoodixMilanUnpackedTemplate *unpacked = g_new0 (
    GoodixMilanUnpackedTemplate, 1);
  GoodixMatchInfo *info = generate_match_info ();
  g_autoptr(GBytes) extracted = NULL;
  g_autoptr(GPtrArray) features = g_ptr_array_new_with_free_func (
    (GDestroyNotify) g_bytes_unref);
  g_autoptr(GBytes) combined = NULL;
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) print_payload = NULL;
  g_autoptr(GBytes) parsed = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree gchar *extracted_hash = NULL;
  g_autofree gchar *combined_hash = NULL;
  g_autofree gchar *antifake_hash = NULL;
  GoodixMilanFeatureView view;
  GoodixMilanPrintTemplateInfo print_info;
  guint32 schema;
  guint32 print_profile;
  guint32 sensor_type;
  guint32 antifake_mode;
  const gchar *boundary_policy;
  const uint8_t *bytes;
  gsize size;

  test_negative_orientation_scaling ();
  extracted = goodix_milan_match_serialize_template (info);
  bytes = g_bytes_get_data (extracted, &size);
  g_assert_cmpuint (size, >=, 1433);
  extracted_hash = sha256 (bytes, size);
  g_assert_cmpint (goodix_milan_template_unpack (bytes, size, unpacked), ==, 0);
  g_assert_cmpuint (unpacked->feature_count, ==, 1);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     unpacked->feature_elements[0],
                     unpacked->feature_element_sizes[0], &view), ==, 0);
  antifake_hash = sha256 (
    goodix_milan_antifake_const_data (view.antifake),
    GOODIX_MILAN_ANTIFAKE_DEFINED_MATERIAL_SIZE);
  g_ptr_array_add (features, g_bytes_ref (extracted));
  combined = goodix_milan_match_combine_templates (features);
  g_assert_nonnull (combined);
  bytes = g_bytes_get_data (combined, &size);
  combined_hash = sha256 (bytes, size);
  memset (unpacked, 0, sizeof(*unpacked));
  g_assert_cmpint (goodix_milan_template_unpack (bytes, size, unpacked), ==, 0);
  g_assert_cmpuint (unpacked->feature_count, ==, 1);
  g_assert_cmpuint (unpacked->relation_count, ==, 0);

  print_data = goodix_milan_print_build_data (combined, &error);
  g_assert_no_error (error);
  g_assert_nonnull (print_data);
  g_assert_true (g_variant_is_of_type (
    print_data, G_VARIANT_TYPE ("(uuuusay)")));
  g_variant_get (print_data, "(uuuu&s@ay)", &schema, &print_profile,
                 &sensor_type, &antifake_mode, &boundary_policy,
                 &print_payload);
  g_assert_true (schema == 4 && print_profile == 9 && sensor_type == 12 &&
                 antifake_mode == 1 &&
                 strcmp (boundary_policy, "canonical-zero-v1") == 0);
  g_assert_true (goodix_milan_print_parse_data (
    print_data, &parsed, &error));
  g_assert_no_error (error);
  g_assert_true (g_bytes_equal (combined, parsed));
  g_assert_true (goodix_milan_print_validate_template (
    parsed, &print_info, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (print_info.feature_count, ==, 1);
  g_assert_cmpuint (print_info.relation_count, ==, 0);

  g_assert_cmpstr (extracted_hash, ==, feature_extraction_sha256);
  g_assert_cmpstr (combined_hash, ==, feature_template_sha256);
  g_assert_cmpstr (antifake_hash, ==, feature_antifake_sha256);

  goodix_milan_match_free_info (info);
}
