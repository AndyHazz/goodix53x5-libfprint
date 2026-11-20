/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Explicit synthetic-only exporter. Never reads inputs or computes expectations.
 */
#include "test-goodix53x5-milan-state-study-support.h"

static void
save (const char *directory, const char *name, GBytes *bytes)
{
  g_autofree gchar *path = g_build_filename (directory, name, NULL);
  gsize size;
  const char *data = g_bytes_get_data (bytes, &size);

  g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_set_contents (path, data, size, NULL));
}

int
main (int argc, char **argv)
{
  if (argc != 2 || !g_file_test (argv[1], G_FILE_TEST_IS_DIR))
    return 2;
  g_autoptr(GBytes) feature = study_candidate_feature (0, 100);
  GoodixMatchInfo *probe = study_match_info_from_feature (feature, TRUE);

  save (argv[1], "probe.bin", probe->template);
  goodix_milan_match_free_info (probe);
  for (guint tie = 0; tie < 2; tie++)
    {
      g_autoptr(GBytes) base = study_gallery (GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
      g_autoptr(GBytes) first = study_candidate_feature (1, 70);
      g_autoptr(GBytes) second = study_candidate_feature (2, 100);
      g_autoptr(GBytes) third = study_candidate_feature (3, tie ? 70 : 69);
      GoodixMilanUnpackedTemplate before;
      g_autofree guint8 *packed = g_malloc (GOODIX_MILAN_TEMPLATE_MAX_SIZE);
      gsize size;

      unpack_study_template (base, &before);
      before.feature_elements[1] = g_bytes_get_data (first, &before.feature_element_sizes[1]);
      before.feature_elements[2] = g_bytes_get_data (second, &before.feature_element_sizes[2]);
      before.feature_elements[3] = g_bytes_get_data (third, &before.feature_element_sizes[3]);
      before.relations[1].values[3] = -0x400;
      goodix_milan_template_write_u32 (before.tail_state, 2);
      goodix_milan_template_write_u32 (before.tail_state + 8, 0);
      g_assert_cmpint (goodix_milan_template_pack (
                         before.feature_elements, before.feature_element_sizes,
                         before.feature_count, before.relations, before.relation_count,
                         &before.metadata, before.tail_state, sizeof (before.tail_state),
                         packed, GOODIX_MILAN_TEMPLATE_MAX_SIZE, &size), ==, 0);
      g_autoptr(GBytes) gallery = g_bytes_new_take (g_steal_pointer (&packed), size);

      save (argv[1], tie ? "tie-gallery.bin" : "coverage-gallery.bin", gallery);
    }
  return 0;
}
