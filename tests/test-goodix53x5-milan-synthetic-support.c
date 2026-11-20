/*
 * Goodix 53x5 driver for libfprint - generated Milan parity tests
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-synthetic-support.h"

#define PIXELS GOODIX_MILAN_SENSOR_PIXELS

gchar *
sha256 (const void *data,
        gsize       size)
{
  return g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, size);
}

static void
generate_feature_frames (uint16_t *setup,
                         uint16_t *live)
{
  for (int row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
    for (int column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
      {
        size_t index = (size_t) row * GOODIX_MILAN_SENSOR_COLUMNS + column;
        uint16_t baseline = (uint16_t) (
          0x0700 + row * 3 + column * 2 +
          (((row * 7) ^ (column * 13)) & 0x3f));
        uint16_t delta;

        setup[index] = baseline;
        int wrapped = (column * 8 + row * 8) % 80;
        int first_cut = (column - 32) * (column - 32) +
                        (row - 28) * (row - 28);
        int second_cut = (column - 72) * (column - 72) +
                         (row - 55) * (row - 55);

        delta = wrapped < 40 ? 300 : 1200;
        if (first_cut < 36 || second_cut < 49)
          delta = 1200;
        /* Avoid an all-sharp synthetic score distribution. */
        if (ABS (row - 44) <= 4 && ABS (column - 54) <= 4)
          setup[index] = (uint16_t) (
            baseline - delta + 800 +
            (4 - MAX (ABS (row - 44), ABS (column - 54))) * 80);
        live[index] = (uint16_t) (baseline - delta);
      }
}

GoodixMatchInfo *
generate_match_info (void)
{
  g_autofree GoodixMilanPreprocessState *state = g_new0 (
    GoodixMilanPreprocessState, 1);
  GoodixMilanProfileState profile = { 0 };
  g_autofree uint16_t *setup = g_new (uint16_t, PIXELS);
  g_autofree uint16_t *live = g_new (uint16_t, PIXELS);
  g_autofree uint8_t *processed = g_new (uint8_t, PIXELS);
  GoodixMatchInfo *info = NULL;
  int quality = -1;
  int coverage = -1;

  generate_feature_frames (setup, live);
  goodix_milan_preprocess_reset (state);
  g_assert_cmpint (goodix_milan_preprocess (
                     state, &profile, setup, live,
                     GOODIX_MILAN_PURPOSE_ENROLL, processed, &quality,
                     &coverage), ==, 0);
  g_assert_cmpint (quality, ==, 100);
  g_assert_cmpint (coverage, ==, 100);
  g_assert_cmpint (goodix_milan_match_extract_native_result (
                     processed, state, live, 0, 0, 0, 12, &info), ==,
                   GOODIX_MILAN_EXTRACTION_OK);
  g_assert_true (goodix_milan_match_info_is_complete (info));
  g_assert_cmpint (goodix_milan_match_keypoints_count (info), ==, 150);
  return info;
}
