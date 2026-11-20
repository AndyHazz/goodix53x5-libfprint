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
#include "drivers/goodix53x5/milan/match/selection.h"
#include "drivers/goodix53x5/milan/study/policy.h"

#include <glib.h>

typedef struct
{
  const char *name;
  int32_t candidate_flag;
  int32_t metric1;
  int32_t metric4;
  int32_t metric5;
  int32_t metric9;
  int32_t initial_sum;
  int32_t initial_count;
  int32_t winner5;
  int32_t winner1;
  int32_t winner9;
  int expected_status;
  int32_t expected_sum;
  int32_t expected_count;
  int32_t expected_winner5;
  int32_t expected_winner1;
  int32_t expected_winner9;
  int expected_replaced;
  int32_t expected_term;
} SelectionCase;

void
test_selection_rows (void)
{
  static const int32_t identity[6] = { 256, 0, 0, 0, 256, 0 };
  static const SelectionCase cases[] = {
    { "positive", 0, 10, 208, 196, 10, 0, 0, 0, 0, 0,
      1, 61, 1, 196, 10, 10, 1, 61 },
    { "metric4-boundary", 0, 10, 207, 196, 10, 5, 1, 300, 20, 30,
      0, 5, 1, 300, 20, 30, 0, 0 },
    { "metric5-boundary", 0, 10, 208, 195, 10, 5, 1, 300, 20, 30,
      0, 5, 1, 300, 20, 30, 0, 0 },
    { "winner", 0, 10, 210, 200, 30, 5, 1, 199, 20, 30,
      1, 66, 2, 200, 10, 30, 1, 61 },
    { "tie", 0, 10, 210, 200, 30, 5, 1, 200, 10, 30,
      1, 66, 2, 200, 10, 30, 0, 61 },
    { "positive-wrap", 1, 8388607, 0, 0, 0, 2147483640, 1, 0, 0, 0,
      1, -2096353099, 2, 0, 8388607, 0, 1, 51130557 },
    { "negative-wrap", 1, 8388608, 0, 0, 0, 0, INT32_MAX, 0, 0, 0,
      1, -51130562, INT32_MIN, 0, 8388608, 0, 1, -51130562 },
  };

  for (size_t i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      const SelectionCase *test = &cases[i];
      GoodixMilanMatchSelection selection;
      GoodixMilanMatchContributionEvent event;
      int32_t metrics[GOODIX_MILAN_MATCH_SELECTION_METRICS] = { 0 };
      int status;

      goodix_milan_match_selection_reset (&selection);
      selection.q8_sum = test->initial_sum;
      selection.q8_contributor_count = test->initial_count;
      selection.winner_valid = test->initial_count != 0;
      selection.winner_metrics[5] = test->winner5;
      selection.winner_metrics[1] = test->winner1;
      selection.winner_metrics[9] = test->winner9;
      metrics[1] = test->metric1;
      metrics[4] = test->metric4;
      metrics[5] = test->metric5;
      metrics[9] = test->metric9;

      status = goodix_milan_match_selection_contribute (
        &selection, metrics, identity, 2, 0, 0, test->candidate_flag, &event);
      g_test_message ("selection row=%s", test->name);
      g_assert_cmpint (status, ==, test->expected_status);
      g_assert_cmpint (selection.q8_sum, ==, test->expected_sum);
      g_assert_cmpint (selection.q8_contributor_count,
                       ==, test->expected_count);
      g_assert_cmpint (selection.winner_metrics[5],
                       ==, test->expected_winner5);
      g_assert_cmpint (selection.winner_metrics[1],
                       ==, test->expected_winner1);
      g_assert_cmpint (selection.winner_metrics[9],
                       ==, test->expected_winner9);
      g_assert_cmpint (event.winner_replaced, ==, test->expected_replaced);
      g_assert_cmpint (event.q8_term, ==, test->expected_term);
    }

  {
    GoodixMilanMatchSelection selection;
    GoodixMilanMatchContributionEvent event;
    int32_t metrics[GOODIX_MILAN_MATCH_SELECTION_METRICS] = { 0 };

    goodix_milan_match_selection_reset (&selection);
    selection.q8_sum = 21474837;
    selection.q8_contributor_count = 1;
    selection.selected_numerator = 10;
    selection.latched_score = 99;
    metrics[1] = 9;
    g_assert_cmpint (goodix_milan_match_selection_admit (
                       &selection, metrics, identity, 0, 0, 0, 1, &event),
                     ==, 1);
    g_assert_cmpint (selection.latched_score, ==, -8388608);
  }
}

void
test_study_policy_actions (void)
{
  static const struct
  {
    const char *name;
    int32_t action_gate;
    size_t maximum_features;
    int32_t matched_residual;
    int32_t retained_flag;
    GoodixMilanStudyActionCode expected_action;
    size_t expected_index;
    int expected_primary;
  } cases[] = {
    { "none", 0, 3, 0, 0, GOODIX_MILAN_STUDY_ACTION_NONE, SIZE_MAX, 0 },
    { "append", 1, 4, 20, 0, GOODIX_MILAN_STUDY_ACTION_APPEND, 3, 0 },
    { "replace-no-relation", 1, 3, 0, 0,
      GOODIX_MILAN_STUDY_ACTION_REPLACE_NO_RELATION, 1, 1 },
    { "geometric", 1, 3, 20, 1,
      GOODIX_MILAN_STUDY_ACTION_GEOMETRIC, 2, 0 },
    { "replace", 1, 3, 0, 1,
      GOODIX_MILAN_STUDY_ACTION_REPLACE, 1, 1 },
  };

  for (size_t i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      GoodixMilanStudyPolicyInput input = {
        .action_gate = cases[i].action_gate,
        .mode_enabled = 1,
        .replacement_enabled = 1,
        .probe_quality = 100,
        .probe_coverage = 100,
        .feature_count = 3,
        .maximum_features = cases[i].maximum_features,
        .matched_feature_index = 1,
        .reference_feature_index = 0,
        .retained_flag = cases[i].retained_flag,
        .primary_transform_area = GOODIX_MILAN_STUDY_MASK_SIZE,
      };
      GoodixMilanStudyPolicyResult result;

      for (size_t feature = 0; feature < input.feature_count; feature++)
        {
          input.features[feature].active = 1;
          input.features[feature].quality = 50;
          input.features[feature].coverage = 80;
          input.features[feature].residual = 20;
          input.features[feature].uncovered_probe_residual = 0;
          input.features[feature].geometric_overlap_area =
            feature == 2 ? 1945 : 1602;
          input.features[feature].geometric_overlap_percent =
            input.features[feature].geometric_overlap_area * 100 /
            GOODIX_MILAN_STUDY_MASK_SIZE;
        }
      input.features[input.matched_feature_index].residual =
        cases[i].matched_residual;

      g_test_message ("study policy row=%s", cases[i].name);
      g_assert_cmpint (goodix_milan_study_policy_select (&input, &result),
                       ==, 0);
      g_assert_cmpint (result.action, ==, cases[i].expected_action);
      g_assert_cmpuint (result.selected_feature_index,
                        ==, cases[i].expected_index);
      g_assert_cmpint (result.primary_candidate,
                       ==, cases[i].expected_primary);
    }
}
