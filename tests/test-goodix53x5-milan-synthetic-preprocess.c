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
#include "drivers/goodix53x5/device/base.h"
#include "drivers/goodix53x5/milan/preprocess/gain.h"

#include <string.h>

#define PIXELS GOODIX_MILAN_SENSOR_PIXELS

static const char classification_retry_sha256[] =
  "d698e50cd02121c7645d57a9d9de155667ca1d3df42d8cec62abba4cfdf17e85";
static const char post_render_retry_sha256[] =
  "448ecc968b50d65c49667381450c20374a62d9ab3da27bf9e97035826324ed07";

static void
assert_chip_subtype_mapping (void)
{
  guint16 subtype = 0;

  g_assert_true (goodix_milan_runtime_subtype_for_chip (
    GOODIX_MILAN_PROFILE9_CHIP_FAMILY_PREFIX, &subtype));
  g_assert_cmpuint (subtype, ==, GOODIX_MILAN_VALIDATED_SUBTYPE);
  g_assert_false (goodix_milan_runtime_subtype_for_chip (0x00220800,
                                                          &subtype));
}

static void
generate_classification_retry_frames (uint16_t *setup,
                                      uint16_t *live)
{
  size_t interior = 0;

  memset (setup, 0, PIXELS * sizeof(*setup));
  memset (live, 0, PIXELS * sizeof(*live));
  for (int row = 2; row < 86; row++)
    for (int column = 2; column < 106; column++, interior++)
      {
        size_t index = (size_t) row * GOODIX_MILAN_SENSOR_COLUMNS + column;

        if (interior < 7426)
          setup[index] = 1000;
        if (interior < 1311)
          live[index] = 1000;
      }
}

void
test_preprocess_classification_retry (void)
{
  assert_chip_subtype_mapping ();

  g_autofree GoodixMilanPreprocessState *state = g_new0 (
    GoodixMilanPreprocessState, 1);
  GoodixMilanProfileState profile = { 0 };
  g_autofree uint16_t *setup = g_new (uint16_t, PIXELS);
  g_autofree uint16_t *live = g_new (uint16_t, PIXELS);
  g_autofree uint8_t *processed = g_new (uint8_t, PIXELS);
  g_autofree gchar *digest = NULL;
  int quality = -1;
  int coverage = -1;
  int status;

  generate_classification_retry_frames (setup, live);
  goodix_milan_preprocess_reset (state);
  status = goodix_milan_preprocess (
    state, &profile, setup, live, GOODIX_MILAN_PURPOSE_IDENTIFY, processed,
    &quality, &coverage);
  digest = sha256 (processed, PIXELS);
  g_test_message (
    "classification-retry status=%d quality=%d coverage=%d selected=%d "
    "samples=%u stable=%u update=%u auxiliary=%u history=%u/%u "
    "classes=%u/%u/%u/%u "
    "primary-valid=%d hash=%s",
    status, quality, coverage, state->selected_refined, state->sample_count,
    state->stable_count, state->update_state, state->auxiliary_sample_count,
    state->profile9_history_count, state->profile9_history_update_count,
    PIXELS - state->profile9_class_counts.profile9_class1_count -
      state->profile9_class_counts.profile9_class2_count -
      state->profile9_class_counts.profile9_class3_count,
    state->profile9_class_counts.profile9_class1_count,
    state->profile9_class_counts.profile9_class2_count,
    state->profile9_class_counts.profile9_class3_count,
    state->primary_contrast_valid, digest);

  g_assert_cmpint (status, ==, GOODIX_MILAN_PREPROCESS_RETRY_CLASSIFICATION);
  g_assert_cmpint (quality, ==, 0);
  g_assert_cmpint (coverage, ==, 12);
  g_assert_cmpint (state->selected_refined, ==, 1);
  g_assert_cmpuint (state->sample_count, ==, 1);
  g_assert_cmpuint (state->stable_count, ==, 0);
  g_assert_cmpuint (state->update_state, ==, 1);
  g_assert_cmpuint (state->auxiliary_sample_count, ==, 1);
  g_assert_cmpuint (state->profile9_history_count, ==, 0);
  g_assert_cmpuint (state->profile9_history_update_count, ==, 0);
  g_assert_cmpuint (state->profile9_history_mask_threshold, ==, 60);
  g_assert_cmpuint (state->profile9_history_mask_average, ==, 0);
  g_assert_cmpuint (state->profile9_class_counts.profile9_class1_count, ==, 0);
  g_assert_cmpuint (state->profile9_class_counts.profile9_class2_count, ==, 0);
  g_assert_cmpuint (state->profile9_class_counts.profile9_class3_count, ==,
                    7180);
  g_assert_cmpuint (PIXELS -
                      state->profile9_class_counts.profile9_class1_count -
                      state->profile9_class_counts.profile9_class2_count -
                      state->profile9_class_counts.profile9_class3_count,
                    ==, 2324);
  g_assert_cmpint (state->primary_contrast_valid, ==, 1);
  g_assert_cmpint (state->post_render.primary_metric, ==, 97);
  g_assert_cmpint (state->post_render.fallback_metric, ==, 200);
  g_assert_cmpint (state->post_render.disagreement, ==, 13);
  g_assert_cmpint (state->post_render.component_score, ==, 96);
  g_assert_cmpint (state->post_render.component_flag, ==, 0);
  g_assert_cmpint (state->post_render.quality_gate, ==, 1);
  g_assert_cmpint (state->post_render.update_applied, ==, 0);
  g_assert_cmpint (state->post_render.status,
                   ==, GOODIX_MILAN_PREPROCESS_RETRY);
  g_assert_cmpuint (state->extraction_auxiliary.primary_histogram_state, ==, 0);
  g_assert_cmpuint (
    state->extraction_auxiliary.promoted_secondary_histogram_state, ==, 0);
  g_assert_cmpuint (state->application_gain_initialized, ==, 1);
  g_assert_cmpstr (digest, ==, classification_retry_sha256);
}

void
test_preprocess_post_render_retry (void)
{
  g_autofree GoodixMilanPreprocessState *state = g_new0 (
    GoodixMilanPreprocessState, 1);
  GoodixMilanProfileState profile = { 0 };
  g_autofree uint16_t *setup = g_new (uint16_t, PIXELS);
  g_autofree uint16_t *live = g_new (uint16_t, PIXELS);
  g_autofree uint8_t *processed = g_new (uint8_t, PIXELS);
  g_autofree gchar *digest = NULL;
  int quality = -1;
  int coverage = -1;
  int status;

  for (int row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
    for (int column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
      {
        size_t index = (size_t) row * GOODIX_MILAN_SENSOR_COLUMNS + column;
        uint16_t base = (uint16_t) (2600 + row * 2 + column);

        setup[index] = base;
        live[index] = (uint16_t) (base - (column % 2 == 0 ? 20 : 40));
      }

  goodix_milan_preprocess_reset (state);
  status = goodix_milan_preprocess (
    state, &profile, setup, live, GOODIX_MILAN_PURPOSE_IDENTIFY, processed,
    &quality, &coverage);
  digest = sha256 (processed, PIXELS);
  g_test_message ("post-render hash=%s", digest);

  g_assert_cmpint (status, ==, GOODIX_MILAN_PREPROCESS_RETRY);
  g_assert_cmpint (quality, ==, 0);
  g_assert_cmpint (coverage, ==, 18);
  g_assert_cmpint (state->post_render.primary_metric, ==, 120);
  g_assert_cmpint (state->post_render.fallback_metric, ==, 200);
  g_assert_cmpint (state->post_render.disagreement, ==, 100);
  g_assert_cmpint (state->post_render.component_score, ==, 0);
  g_assert_cmpint (state->post_render.component_flag, ==, 1);
  g_assert_cmpint (state->post_render.quality_gate, ==, 1);
  g_assert_cmpint (state->post_render.update_applied, ==, 1);
  g_assert_cmpint (state->post_render.status,
                   ==, GOODIX_MILAN_PREPROCESS_RETRY);
  g_assert_cmpuint (state->sample_count, ==, 1);
  g_assert_cmpstr (digest, ==, post_render_retry_sha256);

  /* Native 0x18006c510 restores only sample_count after its nested update.
   * Retried scans retain auxiliary adaptation and temporal stability; the
   * third scan crosses 0x180064170's stable_count > 3 update cutoff. */
  g_assert_cmpuint (state->auxiliary_sample_count, ==, 2);
  g_assert_cmpuint (state->stable_count, ==, 1);
  for (unsigned int retry = 0; retry < 2; retry++)
    {
      g_assert_cmpint (goodix_milan_preprocess (
                         state, &profile, setup, live,
                         GOODIX_MILAN_PURPOSE_IDENTIFY, processed,
                         &quality, &coverage), ==, GOODIX_MILAN_PREPROCESS_RETRY);
      g_assert_cmpint (quality, ==, 0);
      g_assert_cmpint (coverage, ==, 18);
      g_assert_cmpuint (state->sample_count, ==, 2);
      g_assert_cmpuint (state->auxiliary_sample_count, ==, 4);
      g_assert_cmpuint (state->stable_count, ==, retry == 0 ? 3 : 5);
      g_clear_pointer (&digest, g_free);
      digest = sha256 (processed, PIXELS);
      g_assert_cmpstr (digest, ==, post_render_retry_sha256);
    }

  /* Keep the same setup and retained state. This admitted patterned image
   * consumes the retry history rather than silently starting fresh. */
  for (int row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
    for (int column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
      {
        size_t index = (size_t) row * GOODIX_MILAN_SENSOR_COLUMNS + column;

        live[index] = setup[index] -
                      ((column * 8 + row * 8) % 80 < 40 ? 300 : 1200);
      }
  g_assert_cmpint (goodix_milan_preprocess (
                     state, &profile, setup, live,
                     GOODIX_MILAN_PURPOSE_IDENTIFY, processed,
                     &quality, &coverage), ==, 0);
  g_assert_cmpint (quality, ==, 100);
  g_assert_cmpint (coverage, ==, 100);
  g_assert_cmpuint (state->sample_count, ==, 2);
  g_assert_cmpuint (state->auxiliary_sample_count, ==, 4);
  g_assert_cmpuint (state->stable_count, ==, 5);
  g_clear_pointer (&digest, g_free);
  digest = sha256 (processed, PIXELS);
  /* Approved 2.0.310.900 DLL, exported preprocessing of this sequence. */
  g_assert_cmpstr (digest, ==,
                   "be89e134886a20c573846bfdb7b0f41b9eb6bcb27be73b247ccb5a9774550a5c");
}

void
test_gain_tail (void)
{
  uint32_t ready = 0;

  goodix_milan_profile9_update_gain_ready (0, 5, &ready);
  g_assert_cmpuint (ready, ==, 0);
  goodix_milan_profile9_update_gain_ready (0, 6, &ready);
  g_assert_cmpuint (ready, ==, 1);
  goodix_milan_profile9_update_gain_ready (14, 0, &ready);
  g_assert_cmpuint (ready, ==, 1);
  goodix_milan_profile9_update_gain_ready (15, 0, &ready);
  g_assert_cmpuint (ready, ==, 0);

  g_assert_cmpuint (
    goodix_milan_profile9_combine_gain (7001, 9001, 8102, 0), ==, 7607);
  g_assert_cmpuint (
    goodix_milan_profile9_combine_gain (7001, 9001, 8102, 1), ==, 7692);
  g_assert_cmpuint (
    goodix_milan_profile9_combine_gain (0x2000, 9001, 8102, 0), ==, 8902);
}
