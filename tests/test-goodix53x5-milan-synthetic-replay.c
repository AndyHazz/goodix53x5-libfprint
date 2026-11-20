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
#include "test-goodix53x5-milan-synthetic-replay-support.h"
#include "drivers/goodix53x5/milan/match/info-private.h"
#include "drivers/goodix53x5/milan/print.h"
#include "drivers/goodix53x5/milan/study/queue.h"

void
test_generated_production_replay (void)
{
  GoodixMatchInfo *info = generate_match_info ();
  GoodixMatchInfo *matched_info = make_distinct_append_fixture (info);
  g_autoptr(GBytes) extracted = goodix_milan_match_serialize_template (info);
  g_autoptr(GBytes) matched_extracted = goodix_milan_match_serialize_template (
    matched_info);
  g_autoptr(GPtrArray) features = g_ptr_array_new_with_free_func (
    (GDestroyNotify) g_bytes_unref);
  g_autoptr(GBytes) combined = NULL;
  g_autoptr(GBytes) first_after_match = NULL;
  g_autoptr(GBytes) first_append_update = NULL;
  GoodixMilanPrintTemplateInfo combined_info;
  g_autoptr(GError) error = NULL;

  g_assert_nonnull (extracted);
  g_assert_nonnull (matched_extracted);
  /* Keep this matcher fixture on native's queue-ineligible high-class arm. */
  info->extraction_metadata.optional_c7 = 0x400;
  g_ptr_array_add (features, g_bytes_ref (matched_extracted));
  g_ptr_array_add (features, g_bytes_ref (extracted));
  goodix_milan_match_free_info (matched_info);
  combined = goodix_milan_match_combine_templates (features);
  g_assert_nonnull (combined);
  g_assert_true (goodix_milan_print_validate_template (
    combined, &combined_info, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (combined_info.feature_count, ==, 2);
  g_assert_cmpuint (combined_info.maximum_features,
                    ==, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT);
  g_assert_cmpuint (combined_info.registration_count, ==, 2);
  g_assert_cmpuint (combined_info.relation_count, ==, 1);
  g_assert_cmpuint (combined_info.graph_established, ==, 1);
  g_assert_cmpint (combined_info.graph_reference_index, ==, 0);

  for (size_t iteration = 0; iteration < 2; iteration++)
    {
      GoodixStudyQueue *match_queue = goodix_milan_study_queue_new (
        combined_info.queue_state, combined_info.queue_transaction_counter);
      GoodixMilanMatchResult result;
      g_autoptr(GBytes) after_match = NULL;
      g_autoptr(GBytes) negative_update = NULL;
      GoodixMilanPrintTemplateInfo after_match_info;
      const guint8 *combined_data;
      const guint8 *after_match_data;
      gsize combined_size;
      gsize after_match_size;
      GoodixMilanStudyAction negative_action = GOODIX_MILAN_STUDY_APPEND;

      g_assert_nonnull (match_queue);
      g_assert_true (goodix_milan_study_queue_validate (match_queue));
      combined_data = g_bytes_get_data (combined, &combined_size);
      g_assert_cmpint (goodix_milan_match_serialized_feature_result_queued (
                         info, combined_data, combined_size, &result,
                         &after_match, match_queue), ==,
                       GOODIX_SIGFM_TEMPLATE_OK);
      g_assert_nonnull (after_match);
      g_assert_cmpint (result.score, ==, 0);
      g_assert_cmpuint (result.matched_feature_index, ==, SIZE_MAX);
      for (size_t i = 0; i < G_N_ELEMENTS (result.match_transform); i++)
        g_assert_cmpint (result.match_transform[i],
                         ==, i == 0 || i == 4 ? 0x100 : 0);
      g_assert_cmpint (result.relation.relation_count, ==, 0);
      g_assert_cmpint (result.relation.relation_valid, ==, 0);
      g_assert_cmpuint (result.direct_positive_feature_mask, ==, 0);
      g_assert_cmpuint (result.contributor_feature_mask, ==, 0);
      g_assert_cmpuint (result.lifecycle_update_feature_mask, ==, 0);
      g_assert_cmpuint (result.retained_evidence_count, ==, 0);
      g_assert_cmpint (result.retained_evidence_flag, ==, 0);
      g_assert_cmpint (result.study_control.study_finalization_gate, ==, 0);
      g_assert_cmpint (result.study_control.study_action_gate, ==, 0);
      g_assert_cmpint (result.study_control.queue_candidate_eligible, ==, 0);
      g_assert_true (goodix_milan_study_queue_validate (match_queue));
      g_assert_cmpuint (goodix_milan_study_queue_occupied (match_queue), ==, 0);
      g_assert_true (goodix_milan_print_validate_template (
        after_match, &after_match_info, &error));
      g_assert_no_error (error);
      g_assert_cmpuint (after_match_info.feature_count,
                        ==, combined_info.feature_count);
      g_assert_cmpuint (after_match_info.relation_count,
                         ==, combined_info.relation_count);

      after_match_data = g_bytes_get_data (after_match, &after_match_size);
      g_assert_cmpint (goodix_milan_match_study_feature_queued (
                         info, after_match_data, after_match_size, &result,
                         TRUE, match_queue, &negative_update,
                         &negative_action), ==,
                       GOODIX_SIGFM_TEMPLATE_INVALID);
      g_assert_null (negative_update);
      g_assert_cmpint (negative_action, ==, GOODIX_MILAN_STUDY_NONE);
      g_assert_true (goodix_milan_study_queue_validate (match_queue));
      g_assert_cmpuint (goodix_milan_study_queue_occupied (match_queue), ==, 0);
      goodix_milan_study_queue_free (match_queue);

      /* Independent generic action-0 transient subcase. With no retained
       * evidence the identity relation is not consumed, but keeps the
       * publication coherent and fully defined. */
      {
        GoodixStudyQueue *action0_queue = goodix_milan_study_queue_new (
          after_match_info.queue_state,
          after_match_info.queue_transaction_counter);
        GoodixMilanMatchResult generic_action0_result = {
          .matched_feature_index = SIZE_MAX,
          .score = 1,
          .match_transform = { 0x100, 0, 0, 0, 0x100, 0 },
          .relation = {
            .relation_count = 0,
            .relation_values = { 0, 0x100, 0, 0, 0, 0x100, 0 },
            .relation_valid = 0,
          },
          .study_control.study_finalization_gate = 1,
          .study_control.study_action_gate = 1,
        };
        GoodixMilanStudyAction action0_action = GOODIX_MILAN_STUDY_APPEND;
        g_autoptr(GBytes) action0_update = NULL;

        g_assert_nonnull (action0_queue);
        g_assert_cmpint (goodix_milan_match_study_feature_queued (
                           info, after_match_data, after_match_size,
                           &generic_action0_result, TRUE, action0_queue,
                           &action0_update, &action0_action), ==,
                         GOODIX_SIGFM_TEMPLATE_OK);
        g_assert_null (action0_update);
        g_assert_cmpint (action0_action, ==, GOODIX_MILAN_STUDY_NONE);
        g_assert_true (goodix_milan_study_queue_validate (action0_queue));
        g_assert_cmpuint (action0_queue->enabled_state, ==, 0);
        g_assert_cmpuint (action0_queue->transaction_counter,
                          ==, after_match_info.queue_transaction_counter);
        g_assert_cmpuint (goodix_milan_study_queue_allocated (action0_queue),
                          ==, GOODIX_STUDY_QUEUE_CAPACITY);
        g_assert_cmpuint (goodix_milan_study_queue_occupied (action0_queue), ==, 1);
        goodix_milan_study_queue_free (action0_queue);
      }

      /* Independent generic action-1 append API subcase, not a matcher
       * result handoff. */
      {
        GoodixStudyQueue *append_queue = goodix_milan_study_queue_new (
          after_match_info.queue_state,
          after_match_info.queue_transaction_counter);
        GoodixMilanMatchResult generic_append_result = {
          .matched_feature_index = 0,
          .score = 1,
          .match_transform = { 0x100, 0, 0, 0, 0x100, 0 },
          .relation = {
            .relation_count = 150,
            .relation_values = { 0, 0x100, 0, 0, 0, 0x100, 0 },
            .relation_valid = 1,
          },
          .study_control.study_action_gate = 1,
        };
        GoodixMilanStudyAction append_action = GOODIX_MILAN_STUDY_NONE;
        g_autoptr(GBytes) append_update = NULL;
        GoodixMilanPrintTemplateInfo after_study_info;

        g_assert_nonnull (append_queue);
        g_assert_cmpint (goodix_milan_match_study_feature_queued (
                           info, after_match_data, after_match_size,
                           &generic_append_result, TRUE, append_queue,
                           &append_update, &append_action), ==,
                         GOODIX_SIGFM_TEMPLATE_OK);
        g_assert_true (goodix_milan_study_queue_validate (append_queue));
        g_assert_cmpuint (goodix_milan_study_queue_occupied (append_queue), ==, 0);
        g_assert_nonnull (append_update);
        g_assert_cmpint (append_action, ==, GOODIX_MILAN_STUDY_APPEND);
        g_assert_true (goodix_milan_print_validate_template (
          append_update, &after_study_info, &error));
        g_assert_no_error (error);
        g_assert_cmpuint (after_study_info.feature_count,
                          ==, combined_info.feature_count + 1);
        g_assert_cmpuint (after_study_info.maximum_features,
                          ==, combined_info.maximum_features);
        g_assert_cmpuint (after_study_info.queue_state,
                          ==, combined_info.queue_state);
        g_assert_cmpuint (after_study_info.queue_transaction_counter,
                          ==, combined_info.queue_transaction_counter);
        assert_generic_append_material (extracted, after_match, append_update);
        if (iteration == 0)
          first_append_update = g_bytes_ref (append_update);
        else
          g_assert_true (g_bytes_equal (append_update, first_append_update));
        goodix_milan_study_queue_free (append_queue);
      }

      if (iteration == 0)
        first_after_match = g_bytes_ref (after_match);
      else
        g_assert_true (g_bytes_equal (after_match, first_after_match));
      g_test_message (
        "generated replay iteration=%zu score=%d generic-action0-queue=1 "
        "generic-append-action=%d",
        iteration, result.score, GOODIX_MILAN_STUDY_APPEND);
    }

  goodix_milan_match_free_info (info);
}
