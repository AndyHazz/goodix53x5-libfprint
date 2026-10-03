/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Frozen mathematical inputs and complete DLL-packed after-match expectations.
 */
#include "test-goodix53x5-milan-state-study-support.h"
#include "test-goodix53x5-milan-native-match-format.h"
#include <gio/gio.h>

static GBytes *
load (const char *name, const char *suffix, gsize expected_size)
{
  g_autofree gchar *filename = g_strconcat (name, suffix, ".bin.gz", NULL);
  g_autofree gchar *path = g_build_filename (NATIVE_MATCH_FIXTURES, filename, NULL);
  g_autofree gchar *compressed = NULL;
  g_autofree guint8 *raw = g_malloc (expected_size + 1);

  g_autoptr(GError) error = NULL;
  g_autoptr(GZlibDecompressor) decoder = g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP);
  gsize size, consumed = 0, produced = 0;
  GConverterResult result;

  if (!g_file_get_contents (path, &compressed, &size, &error))
    g_error ("%s: %s", filename, error->message);
  if (size == 0 || size > 4 * 1024 * 1024)
    g_error ("%s: invalid compressed size %zu", filename, size);
  do
    {
      gsize read = 0, written = 0;

      result = g_converter_convert (G_CONVERTER (decoder), compressed + consumed,
                                    size - consumed, raw + produced,
                                    expected_size + 1 - produced,
                                    G_CONVERTER_INPUT_AT_END, &read, &written, &error);
      if (result == G_CONVERTER_ERROR)
        g_error ("%s: gzip: %s", filename, error->message);
      consumed += read;
      produced += written;
      if (produced > expected_size || (read == 0 && written == 0 && result != G_CONVERTER_FINISHED))
        g_error ("%s: invalid decompressed length or incomplete gzip", filename);
    }
  while (result != G_CONVERTER_FINISHED);
  if (consumed != size || produced != expected_size)
    g_error ("%s: trailing data or wrong length: consumed=%zu/%zu raw=%zu/%zu",
             filename, consumed, size, produced, expected_size);
  return g_bytes_new_take (g_steal_pointer (&raw), produced);
}

static void
assert_bytes (const char *name, const char *boundary, GBytes *expected,
              const guint8 *actual, gsize size)
{
  gsize expected_size;
  const guint8 *native = g_bytes_get_data (expected, &expected_size);

  if (size != expected_size)
    g_error ("%s %s: length actual=%zu native=%zu", name, boundary, size, expected_size);
  for (gsize i = 0; i < size; i++)
    if (actual[i] != native[i])
      g_error ("%s %s: byte=%zu word=%zu actual=%02x native=%02x",
               name, boundary, i, i / 4, actual[i], native[i]);
}

static GoodixMatchInfo *
load_probe (const char *name)
{
  GoodixMatchInfo *info = goodix_milan_match_info_new_empty ();
  GoodixMilanUnpackedTemplate unpacked;
  GoodixMilanFeatureView view;

  info->template = load (name, "-probe", 14178);
  unpack_study_template (info->template, &unpacked);
  g_assert_cmpuint (unpacked.feature_count, ==, 1);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     unpacked.feature_elements[0], unpacked.feature_element_sizes[0], &view), ==, 0);
  g_assert_cmpuint (view.record_count, ==, 150);
  g_assert_cmpint (view.fields.tagged_values[2], ==, 0);
  info->record_count = view.record_count;
  info->partition_count = view.fields.tagged_values[2];
  info->records = g_new0 (GoodixMilanFeatureRecord, view.record_count);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, view.record_count, info->partition_count,
                     info->records, view.record_count), ==, 0);
  memcpy (info->feature_bitmaps.high_bitmap, view.high_bitmap, sizeof (info->feature_bitmaps.high_bitmap));
  memcpy (info->feature_bitmaps.enhanced_bitmap, view.enhanced_bitmap, sizeof (info->feature_bitmaps.enhanced_bitmap));
  memcpy (info->feature_bitmaps.low_bitmap, view.low_bitmap, sizeof (info->feature_bitmaps.low_bitmap));
  memcpy (info->inline_mask, view.inline_mask, sizeof (info->inline_mask));
  memset (info->rescue_mask, 0xff, sizeof (info->rescue_mask));
  memcpy (&info->antifake, view.antifake, sizeof (info->antifake));
  info->extraction_metadata.quality = view.fields.tagged_values[3];
  info->extraction_metadata.coverage = view.fields.tagged_values[4];
  info->extraction_metadata.optional_c7 = view.fields.optional_c7;
  g_assert_true (goodix_milan_match_info_is_complete (info));
  return info;
}

static void
test_case (gconstpointer user_data)
{
  const char *name = user_data;
  gsize gallery_size = g_str_has_prefix (name, "bitmap-") ? 327036 : 331804;

  g_autoptr(GBytes) gallery = load (name, "-gallery", gallery_size);
  g_autoptr(GBytes) expected = load (name, "-match", gallery_size);
  g_autoptr(GBytes) observation = load (name, "-observation", NATIVE_MATCH_OBSERVATION_SIZE);
  g_autoptr(GBytes) matched = NULL;
  GoodixMatchInfo *probe = load_probe (name);
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
  GoodixMilanMatchResult result;
  GoodixMilanPrintTemplateInfo admission;
  gsize size;
  const guint8 *data = g_bytes_get_data (gallery, &size);
  guint8 observed[NATIVE_MATCH_OBSERVATION_SIZE];
  gint32 words[NATIVE_MATCH_WORDS];

  g_assert_true (goodix_milan_print_validate_template (gallery, &admission, NULL));
  words[0] = goodix_milan_match_serialized_feature_result_queued (
    probe, data, size, &result, &matched, queue);
  g_assert_cmpint (words[0], ==, GOODIX_SIGFM_TEMPLATE_OK);
  g_assert_nonnull (matched);
  data = g_bytes_get_data (matched, &size);
  assert_bytes (name, "gallery", expected, data, size);
  words[1] = result.score;
  words[2] = result.matched_feature_index == SIZE_MAX ? -1 : (gint32) result.matched_feature_index;
  words[3] = result.relation.relation_count;
  memcpy (words + 4, result.match_transform, 6 * sizeof (gint32));
  memcpy (words + 10, result.relation.relation_values + 1, 6 * sizeof (gint32));
  G_STATIC_ASSERT (GOODIX_STUDY_QUEUE_CAPACITY == NATIVE_MATCH_QUEUE_SLOTS);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  for (gsize i = 0; i < NATIVE_MATCH_QUEUE_SLOTS; i++)
    words[16 + i] = queue->entries[i].rank;
  for (gsize i = 0; i < NATIVE_MATCH_WORDS; i++)
    native_match_put_u32 (observed + 4 * i, (guint32) words[i]);
  assert_bytes (name, "observation", observation, observed, sizeof (observed));
  goodix_milan_study_queue_free (queue);
  goodix_milan_match_free_info (probe);
}

int
main (int argc, char **argv)
{
  const char *names[] = { "bitmap-48", "bitmap-56", "order-1", "order-2" };

  g_test_init (&argc, &argv, NULL);
  for (gsize i = 0; i < G_N_ELEMENTS (names); i++)
    {
      g_autofree gchar *path = g_strconcat ("/milan/native-match/", names[i], NULL);

      g_test_add_data_func (path, names[i], test_case);
    }
  return g_test_run ();
}
