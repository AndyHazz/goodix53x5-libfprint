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

#define PIXELS GOODIX_MILAN_SENSOR_PIXELS

void
test_mature_temporal_classification (void)
{
  /* Approved 2.0.310.900 type-12 classifier (0x1800508a0), with publication
   * through 0x18006b290. These are normalized classifier inputs, not raw scans:
   * setup - 7095 is raw12, live < 3800, and copied outer columns are fixed
   * points. Only caller sample_count is supplied; classifiers produce history.
   * The flat final frame removes primary edges but retains temporal classes. */
  static const struct
  {
    int         band;
    const char *classes_sha256;
    const char *history_sha256;
  } cases[] = {
    { 800,
      "547b2a90cc48863e57b557b684747953645767efd5feee64ab0c46d5011a1960",
      "31d60cb7a8bbe246043e012f64fa6b1a5fa5fbd65a3e35ee58b82ed27f2e0081" },
    { 0,
      "8b3c5643c7754c0fe5295f12241a7078310d1a305bc2d077d4bccd1e76c150a1",
      "f629b02ddd2020e50f1054500c0dc699f5cbd7300cb2c8354e971741ceaaea4c" },
  };

  for (size_t sequence = 0; sequence < G_N_ELEMENTS (cases); sequence++)
    {
      g_autofree GoodixMilanPreprocessState *state = g_new0 (
        GoodixMilanPreprocessState, 1);
      g_autofree uint16_t *setup = g_new (uint16_t, PIXELS);
      g_autofree uint16_t *live = g_new (uint16_t, PIXELS);
      g_autofree uint16_t *difference = g_new (uint16_t, PIXELS);
      g_autofree uint8_t *contrast = g_new (uint8_t, PIXELS);
      g_autofree uint8_t *classes = g_new (uint8_t, PIXELS);
      g_autofree uint8_t *broken = g_new (uint8_t, PIXELS);
      g_autofree gchar *digest = NULL;
      gboolean target = cases[sequence].band != 0;

      goodix_milan_preprocess_reset (state);
      for (int row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
        for (int column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
          {
            size_t i = row * GOODIX_MILAN_SENSOR_COLUMNS + column;
            int x = CLAMP (column, 1, GOODIX_MILAN_SENSOR_COLUMNS - 2);

            difference[i] = 5095 + (x % 18) * 40 +
                            (row >= GOODIX_MILAN_SENSOR_ROWS / 2 ?
                             cases[sequence].band : 0);
            live[i] = 3500;
            setup[i] = live[i] + difference[i];
          }

      for (unsigned int call = 1; call <= 22; call++)
        {
          gboolean final = call == 22;
          gboolean retry = target ? !final : call >= 21;
          size_t active = 0;
          int mode = -1;
          int apply = -1;

          if (final)
            {
              for (size_t i = 0; i < PIXELS; i++)
                {
                  difference[i] = 6395;
                  live[i] = setup[i] - difference[i];
                }
            }
          g_assert_cmpint (goodix_milan_profile9_build_contrast_mask (
                             live, setup, GOODIX_MILAN_SENSOR_ROWS,
                             GOODIX_MILAN_SENSOR_COLUMNS, contrast, &active), ==, 0);
          g_assert_cmpuint (active, ==, PIXELS);
          state->sample_count = call;
          g_test_message ("temporal band=%d frame=%u", cases[sequence].band, call);
          g_assert_cmpint (goodix_milan_profile9_build_broken_mask (
                             state, difference, setup, live, contrast,
                             GOODIX_MILAN_SENSOR_ROWS, GOODIX_MILAN_SENSOR_COLUMNS,
                             broken, classes, &mode, &apply), ==,
                           retry ? GOODIX_MILAN_PREPROCESS_RETRY_CLASSIFICATION : 0);
          g_assert_cmpint (mode, ==, retry ? 9 : 6);
          g_assert_cmpint (apply, ==, target || call >= 21);
          g_assert_cmpuint (state->profile9_history_count, ==, call);
          g_assert_cmpuint (state->profile9_history_mask_threshold, ==, 60);
          g_assert_cmpuint (state->profile9_history_mask_average, ==, 100);
          g_assert_cmpuint (state->extraction_auxiliary.primary_histogram_state,
                            ==, final ? 0 : 2);
          g_assert_cmpuint (
            state->extraction_auxiliary.promoted_secondary_histogram_state,
            ==, target ? (call == 21 ? 2 : 1) : (final ? 0 : 1));
          g_assert_cmpuint (state->profile9_class_counts.profile9_class1_count,
                            ==, final ? 0 : (target ? 76 : (call == 21 ? 160 : 520)));
          g_assert_cmpuint (state->profile9_class_counts.profile9_class2_count, ==, 0);
          g_assert_cmpuint (state->profile9_class_counts.profile9_class3_count,
                            ==, target ? (final ? 267 : 1419) : (call >= 21 ? 3024 : 0));
          for (size_t i = 0; i < PIXELS; i++)
            {
              g_assert_cmpuint (contrast[i], ==, 1);
              g_assert_cmpuint (state->profile9_reference_age[i], ==, call);
              g_assert_cmpuint (classes[i], <=, 3);
              g_assert_cmpuint (broken[i], ==, classes[i] == 3 ? 3 : 0);
            }
        }

      /* Hash only defined planes, never struct padding or native addresses. */
      digest = sha256 (classes, PIXELS);
      g_assert_cmpstr (digest, ==, cases[sequence].classes_sha256);
      for (size_t i = 0; i < PIXELS; i++)
        difference[i] = GUINT16_TO_LE (state->profile9_history_reference[i]);
      g_clear_pointer (&digest, g_free);
      digest = sha256 (difference, PIXELS * sizeof (*difference));
      g_assert_cmpstr (digest, ==, cases[sequence].history_sha256);
    }
}
