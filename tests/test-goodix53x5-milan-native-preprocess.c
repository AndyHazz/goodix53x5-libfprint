/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Frozen mathematical inputs and complete DLL-observed per-call projections.
 */
#include <glib.h>
#include <string.h>
#include "drivers/goodix53x5/milan/preprocess/state.h"
#include "test-goodix53x5-milan-native-preprocess-format.h"

static GBytes *
load (const char *case_name, const char *kind, gsize required_size)
{
  g_autofree gchar *name = g_strdup_printf ("%s-%s.bin", case_name, kind);
  g_autofree gchar *path = g_build_filename (NATIVE_PREPROCESS_FIXTURES, name, NULL);

  g_autoptr(GError) error = NULL;
  gchar *data;
  gsize size;

  if (!g_file_get_contents (path, &data, &size, &error))
    g_error ("%s: %s", name, error->message);
  if (size != required_size)
    g_error ("%s: expected exactly %zu bytes, got %zu (truncation/trailing bytes)",
             name, required_size, size);
  return g_bytes_new_take (data, size);
}

static void
compare_field (const char *name, unsigned int call, const char *field,
               const uint8_t *actual, const uint8_t *expected, size_t size,
               size_t record_offset)
{
  for (size_t i = 0; i < size; i++)
    if (actual[i] != expected[i])
      g_error ("%s call=%u field=%s byte=%zu record-offset=%zu: actual=%02x native=%02x",
               name, call, field, i, record_offset + i, actual[i], expected[i]);
}

static void
test_case (gconstpointer user_data)
{
  const char *name = user_data;
  gboolean natural = g_str_equal (name, "natural");
  unsigned int calls = natural ? 24 : 22;
  size_t record_size = natural ? NP_NATURAL_RECORD_BYTES : NP_TEMPORAL_RECORD_BYTES;

  g_autoptr(GBytes) input = load (name, "input", NP_INPUT_BYTES + (natural ? 0 : NP_PIXELS));
  g_autoptr(GBytes) expected = load (name, "output", calls * record_size);
  const uint8_t *input_data = g_bytes_get_data (input, NULL);
  const uint8_t *expected_data = g_bytes_get_data (expected, NULL);
  g_autofree GoodixMilanPreprocessState *state = g_new0 (GoodixMilanPreprocessState, 1);
  GoodixMilanProfileState profile = { 0 };
  uint16_t frames[3][NP_PIXELS];

  for (unsigned int frame = 0; frame < 3; frame++)
    for (size_t i = 0; i < NP_PIXELS; i++)
      frames[frame][i] = np_read16 (input_data + frame * NP_FRAME_BYTES + 2 * i);
  goodix_milan_preprocess_reset (state);
  for (unsigned int call = 1; call <= calls; call++)
    {
      uint16_t live[NP_PIXELS];
      uint8_t pixels[NP_PIXELS] = { 0 };
      uint8_t record[NP_NATURAL_RECORD_BYTES];
      int first = 0, second = 0;
      int32_t status;

      memcpy (live, frames[call >= (natural ? 23 : 22) ? 2 : 1], sizeof (live));
      if (natural)
        {
          status = goodix_milan_preprocess (state, &profile, frames[0], live,
                                            GOODIX_MILAN_PURPOSE_IDENTIFY, pixels,
                                            &first, &second);
        }
      else
        {
          uint16_t difference[NP_PIXELS];
          uint8_t contrast[NP_PIXELS];
          size_t active = 0;

          /* The frozen normalized input is the same classifier boundary on both
           * sides. Only caller sample_count is supplied; history remains live. */
          state->sample_count = call;
          for (size_t i = 0; i < NP_PIXELS; i++)
            difference[i] = frames[0][i] - live[i];
          g_assert_cmpint (goodix_milan_profile9_build_contrast_mask (
                             live, frames[0], 88, 108, contrast, &active), ==, 0);
          compare_field (name, call, "input contrast", contrast,
                         input_data + NP_INPUT_BYTES, NP_PIXELS, 0);
          g_assert_cmpuint (active, ==, NP_PIXELS);
          status = goodix_milan_profile9_build_broken_mask (
            state, difference, frames[0], live, contrast, 88, 108, pixels,
            NULL, &first, &second);
        }
      np_write32 (record, (uint32_t) status);
      np_write32 (record + 4, (uint32_t) first);
      np_write32 (record + 8, (uint32_t) second);
      record[12] = state->extraction_auxiliary.primary_histogram_state;
      record[13] = 0; /* Ordinary exported entry selector, fixed by this protocol. */
      record[14] = state->extraction_auxiliary.promoted_secondary_histogram_state;
      memcpy (record + 15, pixels, NP_PIXELS);
      size_t offset = 15 + NP_PIXELS;
      if (natural)
        {
          np_write32 (record + offset, state->sample_count);
          offset += 4;
        }
      np_write32 (record + offset, state->profile9_history_count);
      offset += 4;
      np_write_words (record + offset, state->profile9_history_reference);
      offset += NP_FRAME_BYTES;
      memcpy (record + offset, state->profile9_reference_age, NP_PIXELS);
      offset += NP_PIXELS;
      g_assert_cmpuint (offset, ==, record_size);

      /* Compare every field and byte before the independent behavioral checks. */
      const uint8_t *gold = expected_data + (call - 1) * record_size;
      compare_field (name, call, "status", record, gold, 4, 0);
      compare_field (name, call, natural ? "quality" : "mode", record + 4, gold + 4, 4, 4);
      compare_field (name, call, natural ? "coverage" : "apply", record + 8, gold + 8, 4, 8);
      compare_field (name, call, "auxiliary", record + 12, gold + 12, 3, 12);
      compare_field (name, call, natural ? "processed" : "broken mask",
                     record + 15, gold + 15, NP_PIXELS, 15);
      offset = 15 + NP_PIXELS;
      if (natural)
        {
          compare_field (name, call, "sample count", record + offset, gold + offset, 4, offset);
          offset += 4;
        }
      compare_field (name, call, "history count", record + offset, gold + offset, 4, offset);
      offset += 4;
      compare_field (name, call, "history reference", record + offset, gold + offset, NP_FRAME_BYTES, offset);
      offset += NP_FRAME_BYTES;
      compare_field (name, call, "reference ages", record + offset, gold + offset, NP_PIXELS, offset);

      g_assert_cmpuint (state->profile9_history_count, ==, call);
      for (size_t i = 0; i < NP_PIXELS; i++)
        g_assert_cmpuint (state->profile9_reference_age[i], ==, call);
      if (natural)
        {
          g_assert_cmpint (status, ==, call <= 4 ? 0 : GOODIX_MILAN_PREPROCESS_RETRY);
          g_assert_cmpuint (state->sample_count, ==, call <= 4 ? call : call <= 22 ? 4 : call - 18);
          g_assert_cmpint (first, ==, call >= 5 && call <= 22 ? 93 : 100);
          g_assert_cmpint (second, ==, 100);
        }
      else
        {
          gboolean target = g_str_equal (name, "temporal-800");
          gboolean retry = target ? call < 22 : call >= 21;
          size_t severe = 0;

          g_assert_cmpint (status, ==, retry ? GOODIX_MILAN_PREPROCESS_RETRY_CLASSIFICATION : 0);
          g_assert_cmpint (first, ==, retry ? 9 : 6);
          g_assert_cmpint (second, ==, target || call >= 21);
          for (size_t i = 0; i < NP_PIXELS; i++)
            severe += pixels[i] == 3;
          g_assert_cmpuint (severe, ==, target ? (call == 22 ? 267 : 1419) : (call >= 21 ? 3024 : 0));
        }
    }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_data_func ("/milan/native-preprocess/natural", "natural", test_case);
  g_test_add_data_func ("/milan/native-preprocess/temporal-800", "temporal-800", test_case);
  g_test_add_data_func ("/milan/native-preprocess/temporal-0", "temporal-0", test_case);
  return g_test_run ();
}
