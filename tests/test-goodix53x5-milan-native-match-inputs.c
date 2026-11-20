/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Mathematical serialized inputs only; never executes a matcher or reads data.
 * Reuses the state-bitmap and state-match-order case construction.
 */
#include "test-goodix53x5-milan-state-study-support.h"

static GBytes *
bitmap_probe (gsize changed_bytes)
{
  g_autoptr(GBytes) base = ordered_match_feature (0, 0);
  GoodixMilanFeatureView view;
  GoodixMilanFeatureRecord records[150];
  guint8 high[286], enhanced[286], low[286];
  gsize size, packed_size;
  const guint8 *data = g_bytes_get_data (base, &size);
  g_autofree guint8 *packed = g_malloc (size);

  g_assert_cmpuint (changed_bytes, <=, sizeof (high));
  g_assert_cmpint (goodix_milan_template_parse_feature_element (data, size, &view), ==, 0);
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
gallery_input (gboolean ordered, gboolean reverse)
{
  g_autoptr(GBytes) base = study_gallery (GOODIX_MILAN_STUDY_REPLACE_NO_RELATION, TRUE);
  g_autoptr(GBytes) first = ordered_match_feature (1, 0);
  g_autoptr(GBytes) translated = ordered_match_feature (2, 4);
  GoodixMilanUnpackedTemplate before;
  g_autofree guint8 *packed = g_malloc (GOODIX_MILAN_TEMPLATE_MAX_SIZE);
  gsize size;

  unpack_study_template (base, &before);
  before.feature_elements[1] = g_bytes_get_data (first, &before.feature_element_sizes[1]);
  if (ordered)
    {
      before.feature_elements[2] = g_bytes_get_data (translated, &before.feature_element_sizes[2]);
      before.relations[1].values[3] = -0x400;
      goodix_milan_template_write_u32 (before.tail_state + 4, reverse ? 2 : 1);
      goodix_milan_template_write_u32 (before.tail_state + 8, reverse ? 1 : 2);
    }
  g_assert_cmpint (goodix_milan_template_pack (
                     before.feature_elements, before.feature_element_sizes,
                     before.feature_count, before.relations, before.relation_count,
                     &before.metadata, before.tail_state, sizeof (before.tail_state),
                     packed, GOODIX_MILAN_TEMPLATE_MAX_SIZE, &size), ==, 0);
  return g_bytes_new_take (g_steal_pointer (&packed), size);
}

static void
save (const char *directory, const char *name, const char *suffix, GBytes *bytes)
{
  g_autofree gchar *filename = g_strconcat (name, suffix, NULL);
  g_autofree gchar *path = g_build_filename (directory, filename, NULL);
  gsize size;
  const char *data = g_bytes_get_data (bytes, &size);

  g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_set_contents (path, data, size, NULL));
}

int
main (int argc, char **argv)
{
  const char *names[] = { "bitmap-48", "bitmap-56", "order-1", "order-2" };

  if (argc != 2 || !g_file_test (argv[1], G_FILE_TEST_IS_DIR))
    return 2;
  for (guint c = 0; c < G_N_ELEMENTS (names); c++)
    {
      g_autoptr(GBytes) feature = c < 2 ? bitmap_probe (48 + c * 8) : ordered_match_feature (0, 0);
      g_autoptr(GBytes) gallery = gallery_input (c >= 2, c == 3);
      GoodixMatchInfo *probe = study_match_info_from_feature (feature, TRUE);

      g_assert_true (goodix_milan_print_validate_template (gallery, NULL, NULL));
      save (argv[1], names[c], "-probe.bin", probe->template);
      save (argv[1], names[c], "-gallery.bin", gallery);
      goodix_milan_match_free_info (probe);
    }
  return 0;
}
