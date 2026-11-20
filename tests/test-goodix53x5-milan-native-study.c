/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Fixed mathematical inputs; full DLL-packed expectations, no algorithm seams.
 */
#include "test-goodix53x5-milan-state-study-support.h"

static GBytes *
load (const char *name)
{
  g_autofree gchar *path = g_build_filename (NATIVE_STUDY_FIXTURES, name, NULL);
  gchar *data;
  gsize size;

  g_autoptr(GError) error = NULL;

  if (!g_file_get_contents (path, &data, &size, &error))
    g_error ("%s: %s", name, error->message);
  return g_bytes_new_take (data, size);
}

/* Comparison deliberately does not decode, normalize or hash either output. */
static void
assert_native_bytes (const char *name, GBytes *actual)
{
  g_autoptr(GBytes) expected = load (name);
  gsize actual_size, expected_size;
  const guint8 *a, *e;

  g_assert_nonnull (actual);
  a = g_bytes_get_data (actual, &actual_size);
  e = g_bytes_get_data (expected, &expected_size);
  if (actual_size != expected_size)
    g_error ("%s: length actual=%zu native=%zu", name, actual_size, expected_size);
  for (gsize i = 0; i < expected_size; i++)
    if (a[i] != e[i])
      g_error ("%s: first differing offset %zu (0x%zx): actual=%02x native=%02x",
               name, i, i, a[i], e[i]);
}

/* Populate the production match-info owner from the frozen serialized probe.
 * No input packing or mathematical generation occurs during CI. */
static GoodixMatchInfo *
load_probe (void)
{
  GoodixMatchInfo *info = goodix_milan_match_info_new_empty ();
  GoodixMilanUnpackedTemplate unpacked;
  GoodixMilanFeatureView view;

  info->template = load ("probe.bin");
  unpack_study_template (info->template, &unpacked);
  g_assert_cmpuint (unpacked.feature_count, ==, 1);
  g_assert_cmpint (goodix_milan_template_parse_feature_element (
                     unpacked.feature_elements[0], unpacked.feature_element_sizes[0],
                     &view), ==, 0);
  g_assert_cmpuint (view.record_count, ==, 150);
  g_assert_cmpint (view.fields.tagged_values[2], ==, 0);
  info->record_count = view.record_count;
  info->partition_count = view.fields.tagged_values[2];
  info->records = g_new0 (GoodixMilanFeatureRecord, view.record_count);
  g_assert_cmpint (goodix_milan_feature_unpack_template_records (
                     view.packed_records, view.record_count, info->partition_count,
                     info->records, view.record_count), ==, 0);
  memcpy (info->feature_bitmaps.high_bitmap, view.high_bitmap,
          sizeof (info->feature_bitmaps.high_bitmap));
  memcpy (info->feature_bitmaps.enhanced_bitmap, view.enhanced_bitmap,
          sizeof (info->feature_bitmaps.enhanced_bitmap));
  memcpy (info->feature_bitmaps.low_bitmap, view.low_bitmap,
          sizeof (info->feature_bitmaps.low_bitmap));
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
  g_autofree gchar *gallery_name = g_strconcat (name, "-gallery.bin", NULL);
  g_autofree gchar *match_name = g_strconcat (name, "-match.bin", NULL);
  g_autofree gchar *study_name = g_strconcat (name, "-study.bin", NULL);

  g_autoptr(GBytes) gallery = load (gallery_name);
  g_autoptr(GBytes) matched = NULL;
  g_autoptr(GBytes) studied = NULL;
  GoodixMatchInfo *probe = load_probe ();
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 7);
  GoodixMilanPrintTemplateInfo admission;
  GoodixMilanMatchResult result;
  GoodixMilanStudyAction action;
  GoodixMilanUnpackedTemplate after;
  gsize size;
  const guint8 *data = g_bytes_get_data (gallery, &size);

  g_assert_true (goodix_milan_print_validate_template (gallery, &admission, NULL));
  g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                     probe, data, size, &result, &matched, queue), ==, GOODIX_SIGFM_TEMPLATE_OK);
  assert_native_bytes (match_name, matched);
  g_assert_cmpint (result.score, ==, 100);
  g_assert_cmpuint (result.matched_feature_index, ==, 2);
  g_assert_cmpint (result.retained_evidence_flag, ==, 1);
  g_assert_cmpint (result.study_control.study_action_gate, ==, 1);
  g_assert_cmpint (result.study_control.study_finalization_gate, ==, 1);
  g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  data = g_bytes_get_data (matched, &size);
  g_assert_cmpint (goodix_milan_match_study_feature_queued (
                     probe, data, size, &result, TRUE, queue, &studied, &action), ==,
                   GOODIX_SIGFM_TEMPLATE_OK);
  assert_native_bytes (study_name, studied);
  g_assert_cmpint (action, ==, GOODIX_MILAN_STUDY_REPLACE);
  unpack_study_template (studied, &after);
  g_assert_cmpuint (goodix_milan_template_read_u32 (after.tail_state), ==,
                    g_str_equal (name, "tie") ? 1 : 3);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
  goodix_milan_study_queue_free (queue);
  goodix_milan_match_free_info (probe);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_data_func ("/milan/native-study/coverage", "coverage", test_case);
  g_test_add_data_func ("/milan/native-study/tie", "tie", test_case);
  return g_test_run ();
}
