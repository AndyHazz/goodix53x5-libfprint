/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-state-support.h"
#include "test-goodix53x5-milan-state-tests.h"

#include "drivers/goodix53x5/milan/match/info-private.h"

static GoodixMatchInfo *
synthetic_match_info (guint seed)
{
  GoodixMatchInfo *info = goodix_milan_match_info_new_empty ();
  guint8 template_data[19];

  for (gsize i = 0; i < sizeof(template_data); i++)
    template_data[i] = synthetic_byte (seed, i);
  info->template = g_bytes_new (template_data, sizeof(template_data));
  info->record_count = 3;
  info->partition_count = seed % (info->record_count + 1);
  info->records = g_new0 (GoodixMilanFeatureRecord, info->record_count);
  for (gsize i = 0; i < sizeof(info->feature_bitmaps); i++)
    ((guint8 *) &info->feature_bitmaps)[i] = synthetic_byte (seed + 1, i);
  for (gsize i = 0; i < sizeof(info->inline_mask); i++)
    info->inline_mask[i] = synthetic_byte (seed + 2, i);
  for (gsize i = 0; i < sizeof(info->rescue_mask); i++)
    info->rescue_mask[i] = synthetic_byte (seed + 3, i);
  for (gsize i = 0; i < sizeof(info->antifake); i++)
    ((guint8 *) &info->antifake)[i] = synthetic_byte (seed + 4, i);
  for (gint record = 0; record < info->record_count; record++)
    {
      guint8 *bytes = (guint8 *) &info->records[record];

      for (gsize i = 0; i < sizeof(info->records[record]); i++)
        bytes[i] = synthetic_byte (seed + 5 + (guint) record, i);
      info->records[record].foreground = record < info->partition_count ? 0 : 1;
      info->records[record].refined_x = (gint16) ((0x100 + record * 0x20) & ~0xf);
      info->records[record].refined_y = (gint16) ((0x200 + seed * 0x10) & ~0xf);
      info->records[record].orientation = (gint16) ((record - 1) * 0x100);
      memset (info->records[record].payload + 24, 0, 4);
      memset (info->records[record].payload + 36, 0, 8);
    }
  info->extraction_metadata.quality = 40 + (gint) seed;
  info->extraction_metadata.coverage = 60 + (gint) seed;
  info->extraction_metadata.optional_c7 = (gint32) seed;
  g_assert_true (goodix_milan_match_info_is_complete (info));
  return info;
}

static void
assert_match_info_equal (const GoodixMatchInfo *actual,
                         const GoodixMatchInfo *expected)
{
  g_assert_true (goodix_milan_match_info_is_complete (actual));
  g_assert_true (g_bytes_equal (actual->template, expected->template));
  g_assert_cmpint (actual->record_count, ==, expected->record_count);
  g_assert_cmpint (actual->partition_count, ==, expected->partition_count);
  g_assert_cmpmem (&actual->feature_bitmaps, sizeof(actual->feature_bitmaps),
                   &expected->feature_bitmaps, sizeof(expected->feature_bitmaps));
  g_assert_cmpmem (actual->inline_mask, sizeof(actual->inline_mask),
                   expected->inline_mask, sizeof(expected->inline_mask));
  g_assert_cmpmem (actual->rescue_mask, sizeof(actual->rescue_mask),
                   expected->rescue_mask, sizeof(expected->rescue_mask));
  g_assert_cmpmem (&actual->antifake, sizeof(actual->antifake),
                   &expected->antifake, sizeof(expected->antifake));
  g_assert_cmpmem (actual->records,
                   (gsize) actual->record_count * sizeof(*actual->records),
                   expected->records,
                   (gsize) expected->record_count * sizeof(*expected->records));
  g_assert_cmpmem (&actual->extraction_metadata,
                   sizeof(actual->extraction_metadata),
                   &expected->extraction_metadata,
                   sizeof(expected->extraction_metadata));
}

typedef struct
{
  guint incoming_seed;
  guint newest_seed;
  gint metric;
  guint calls;
} MetricPlan;

static gboolean
planned_metric (const GoodixMatchInfo *incoming,
                const GoodixMatchInfo *newest,
                gint                  *metric,
                gpointer               user_data)
{
  MetricPlan *plan = user_data;

  g_assert_cmpint (incoming->extraction_metadata.optional_c7, ==,
                   (gint32) plan->incoming_seed);
  g_assert_cmpint (newest->extraction_metadata.optional_c7, ==,
                   (gint32) plan->newest_seed);
  *metric = plan->metric;
  plan->calls++;
  return TRUE;
}

void
test_queue_lifecycle (void)
{
  g_autofree GoodixStudyQueue *invalid = goodix_milan_study_queue_new (2, 0);
  GoodixStudyQueue *disabled = goodix_milan_study_queue_new (1, 17);
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 17);
  GoodixMatchInfo *incoming = synthetic_match_info (0);
  GoodixMatchInfo *snapshot = goodix_milan_match_info_new_empty ();
  GoodixMatchInfo *incomplete = goodix_milan_match_info_new_empty ();
  MetricPlan metric = { 0 };

  g_assert_null (invalid);
  g_assert_true (goodix_milan_study_queue_validate (disabled));
  g_assert_cmpuint (goodix_milan_study_queue_allocated (disabled), ==, 0);
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     disabled, incoming, NULL, NULL), ==,
                   GOODIX_STUDY_QUEUE_DISABLED);
  goodix_milan_study_queue_disable (disabled);
  g_assert_true (goodix_milan_study_queue_validate (disabled));
  goodix_milan_study_queue_free (disabled);

  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==,
                    GOODIX_STUDY_QUEUE_CAPACITY);
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, incomplete, NULL, NULL), ==,
                   GOODIX_STUDY_QUEUE_INVALID);
  goodix_milan_match_free_info (incomplete);
  queue->entries[0].rank = 0;
  g_assert_false (goodix_milan_study_queue_validate (queue));
  queue->entries[0].rank = -1;
  g_assert_true (goodix_milan_study_queue_validate (queue));

  g_assert_true (goodix_milan_match_info_copy (snapshot, incoming));
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, incoming, NULL, NULL), ==,
                   GOODIX_STUDY_QUEUE_ENQUEUED);
  assert_match_info_equal (incoming, snapshot);
  assert_match_info_equal (queue_entry_at_rank (queue, 0), snapshot);
  incoming->feature_bitmaps.high_bitmap[0] ^= 0xff;
  g_assert_cmpuint (queue_entry_at_rank (queue, 0)->feature_bitmaps.high_bitmap[0],
                    ==, snapshot->feature_bitmaps.high_bitmap[0]);
  goodix_milan_match_free_info (incoming);
  goodix_milan_match_free_info (snapshot);

  incoming = synthetic_match_info (1);
  metric = (MetricPlan) { 1, 0, 191, 0 };
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, incoming, planned_metric, &metric), ==,
                   GOODIX_STUDY_QUEUE_DUPLICATE);
  g_assert_cmpuint (metric.calls, ==, 1);
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 1);
  metric.metric = 190;
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, incoming, planned_metric, &metric), ==,
                   GOODIX_STUDY_QUEUE_ENQUEUED);
  g_assert_cmpuint (metric.calls, ==, 2);
  goodix_milan_match_free_info (incoming);

  for (guint seed = 2; seed < GOODIX_STUDY_QUEUE_CAPACITY; seed++)
    {
      incoming = synthetic_match_info (seed);
      metric = (MetricPlan) { seed, seed - 1, 0, 0 };
      g_assert_cmpint (goodix_milan_study_queue_enqueue (
                         queue, incoming, planned_metric, &metric), ==,
                       GOODIX_STUDY_QUEUE_ENQUEUED);
      g_assert_cmpuint (metric.calls, ==, 1);
      goodix_milan_match_free_info (incoming);
    }
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==,
                    GOODIX_STUDY_QUEUE_CAPACITY);
  for (guint rank = 0; rank < GOODIX_STUDY_QUEUE_CAPACITY; rank++)
    g_assert_cmpint (queue_entry_at_rank (queue, (gint) rank)
                       ->extraction_metadata.optional_c7, ==, (gint) rank);

  incoming = synthetic_match_info (GOODIX_STUDY_QUEUE_CAPACITY);
  metric = (MetricPlan) {
    GOODIX_STUDY_QUEUE_CAPACITY, GOODIX_STUDY_QUEUE_CAPACITY - 1, 0, 0
  };
  g_assert_cmpint (goodix_milan_study_queue_enqueue (
                     queue, incoming, planned_metric, &metric), ==,
                   GOODIX_STUDY_QUEUE_ENQUEUED);
  goodix_milan_match_free_info (incoming);
  for (guint rank = 0; rank < GOODIX_STUDY_QUEUE_CAPACITY; rank++)
    g_assert_cmpint (queue_entry_at_rank (queue, (gint) rank)
                       ->extraction_metadata.optional_c7, ==, (gint) rank + 1);

  goodix_milan_study_queue_disable (queue);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_cmpuint (goodix_milan_study_queue_allocated (queue), ==, 0);
  goodix_milan_study_queue_disable (queue);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  goodix_milan_study_queue_free (queue);
}

typedef struct
{
  guint seed;
  gsize triggering_index;
  gboolean succeed;
  gsize selected_index;
} FollowupStep;

typedef struct
{
  const FollowupStep *steps;
  gsize step_count;
  gsize next_step;
} FollowupPlan;

static gboolean
planned_followup (GoodixMatchInfo *queued,
                  gsize            physical_slot,
                  gsize            triggering_index,
                  gsize           *selected_index,
                  gpointer         user_data)
{
  FollowupPlan *plan = user_data;
  const FollowupStep *step;

  g_assert_cmpuint (physical_slot, <, GOODIX_STUDY_QUEUE_CAPACITY);
  g_assert_cmpuint (plan->next_step, <, plan->step_count);
  step = &plan->steps[plan->next_step++];
  g_assert_cmpint (queued->extraction_metadata.optional_c7, ==,
                   (gint32) step->seed);
  g_assert_cmpuint (triggering_index, ==, step->triggering_index);
  *selected_index = step->selected_index;
  return step->succeed;
}

static GoodixStudyQueue *
queue_with_seeds (const guint *seeds,
                  gsize        seed_count)
{
  GoodixStudyQueue *queue = goodix_milan_study_queue_new (0, 9);

  for (gsize i = 0; i < seed_count; i++)
    {
      GoodixMatchInfo *info = synthetic_match_info (seeds[i]);
      MetricPlan metric = { seeds[i], i == 0 ? 0 : seeds[i - 1], 0, 0 };

      g_assert_cmpint (goodix_milan_study_queue_enqueue (
                         queue, info, i == 0 ? NULL : planned_metric,
                         i == 0 ? NULL : &metric), ==,
                       GOODIX_STUDY_QUEUE_ENQUEUED);
      goodix_milan_match_free_info (info);
    }
  return queue;
}

void
test_queue_process (void)
{
  static const guint seeds[] = { 1, 2, 3 };
  static const FollowupStep success_steps[] = {
    { 1, 50, TRUE, SIZE_MAX },
    { 2, 50, TRUE, 60 },
    { 3, 50, TRUE, 50 },
    { 1, 60, TRUE, 61 },
  };
  static const FollowupStep failure_steps[] = {
    { 7, 5, FALSE, SIZE_MAX },
  };
  GoodixStudyQueue *queue = queue_with_seeds (seeds, G_N_ELEMENTS (seeds));
  FollowupPlan plan = { success_steps, G_N_ELEMENTS (success_steps), 0 };
  gboolean mutated = FALSE;

  g_assert_true (goodix_milan_study_queue_process (
    queue, 50, planned_followup, &plan, &mutated));
  g_assert_true (mutated);
  g_assert_cmpuint (plan.next_step, ==, plan.step_count);
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 0);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  goodix_milan_study_queue_free (queue);

  {
    static const guint failure_seed[] = { 7 };

    queue = queue_with_seeds (failure_seed, G_N_ELEMENTS (failure_seed));
  }
  plan = (FollowupPlan) {
    failure_steps, G_N_ELEMENTS (failure_steps), 0
  };
  mutated = TRUE;
  g_assert_false (goodix_milan_study_queue_process (
    queue, 5, planned_followup, &plan, &mutated));
  g_assert_false (mutated);
  g_assert_cmpuint (goodix_milan_study_queue_occupied (queue), ==, 1);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  goodix_milan_study_queue_free (queue);

  queue = goodix_milan_study_queue_new (1, 9);
  plan = (FollowupPlan) { NULL, 0, 0 };
  mutated = TRUE;
  g_assert_false (goodix_milan_study_queue_process (
    queue, 5, planned_followup, &plan, &mutated));
  g_assert_false (mutated);
  g_assert_true (goodix_milan_study_queue_validate (queue));
  goodix_milan_study_queue_free (queue);
}
