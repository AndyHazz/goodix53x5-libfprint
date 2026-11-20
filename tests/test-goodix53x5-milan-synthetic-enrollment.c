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
#include "drivers/goodix53x5/milan/print.h"
#include "drivers/goodix53x5/milan/template/codec-private.h"

void
test_generated_enrollment_prefix_lifecycle (void)
{
  enum { ENROLLMENT_PREFIX_COUNT = 12 };
  static const size_t complete_prefixes[] = { 1, 2, 12 };
  GoodixMatchInfo *info = generate_match_info ();
  g_autoptr(GBytes) extracted = goodix_milan_match_serialize_template (info);
  g_autoptr(GPtrArray) sources = g_ptr_array_new_with_free_func (
    (GDestroyNotify) g_bytes_unref);
  g_autoptr(GBytes) final_prefix = NULL;
  const guint8 *source_data;
  gsize source_size;

  g_assert_nonnull (extracted);
  source_data = g_bytes_get_data (extracted, &source_size);
  for (size_t i = 0; i < ENROLLMENT_PREFIX_COUNT; i++)
    g_ptr_array_add (sources, g_bytes_new (source_data, source_size));

  for (size_t stage_index = 0;
       stage_index < G_N_ELEMENTS (complete_prefixes); stage_index++)
    {
      size_t prefix = complete_prefixes[stage_index];
      g_autoptr(GPtrArray) stage = g_ptr_array_new_with_free_func (
        (GDestroyNotify) g_bytes_unref);
      g_autoptr(GBytes) combined = NULL;
      GoodixMilanPrintTemplateInfo print_info;
      g_autoptr(GError) error = NULL;
      size_t expected_registration_count = 1 + prefix * (prefix - 1) / 2;

      for (size_t i = 0; i < prefix; i++)
        g_ptr_array_add (stage, g_bytes_ref (g_ptr_array_index (sources, i)));
      combined = goodix_milan_match_combine_templates (stage);
      g_assert_nonnull (combined);
      g_assert_true (goodix_milan_print_validate_template (
        combined, &print_info, &error));
      g_assert_no_error (error);
      g_assert_cmpuint (print_info.feature_count, ==, prefix);
      g_assert_cmpuint (print_info.maximum_features,
                        ==, GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT);
      g_assert_cmpuint (print_info.registration_count,
                        ==, expected_registration_count);
      g_assert_cmpuint (print_info.relation_count,
                        ==, prefix == 1 ? 0 : prefix - 1);
      g_assert_cmpuint (print_info.graph_established,
                        ==, prefix == 1 ? 0 : 1);
      g_assert_cmpint (print_info.graph_reference_index,
                       ==, prefix == 1 ? -1 : 0);
      g_assert_cmpuint (print_info.queue_state, ==, 0);
      g_assert_cmpuint (print_info.queue_transaction_counter, ==, 0);
      for (size_t i = 0; i < sources->len; i++)
        g_assert_true (g_bytes_equal (g_ptr_array_index (sources, i),
                                      extracted));
      if (prefix == ENROLLMENT_PREFIX_COUNT)
        final_prefix = g_bytes_ref (combined);
    }

  {
    g_autoptr(GPtrArray) fresh = g_ptr_array_new_with_free_func (
      (GDestroyNotify) g_bytes_unref);
    g_autoptr(GBytes) recombined = NULL;

    for (size_t i = 0; i < sources->len; i++)
      g_ptr_array_add (fresh, g_bytes_ref (g_ptr_array_index (sources, i)));
    recombined = goodix_milan_match_combine_templates (fresh);
    g_assert_nonnull (recombined);
    g_assert_true (g_bytes_equal (recombined, final_prefix));
  }

  goodix_milan_match_free_info (info);
}

void
test_generated_enrollment_retry_continuation (void)
{
  static const struct
  {
    GoodixMilanEnrollmentAttemptStatus status;
    guint                              count;
    guint                              reject_detail;
    guint                              bad_count;
  } attempts[] = {
    { GOODIX_MILAN_ENROLLMENT_ACCEPTED, 1, 0, 0 },
    { GOODIX_MILAN_ENROLLMENT_ACCEPTED, 2, 0, 0 },
    { GOODIX_MILAN_ENROLLMENT_ACCEPTED, 3, 0, 0 },
    { GOODIX_MILAN_ENROLLMENT_RETRY_CENTER, 3, 2, 1 },
    { GOODIX_MILAN_ENROLLMENT_RETRY_CENTER, 3, 4, 2 },
    { GOODIX_MILAN_ENROLLMENT_RETRY_CENTER, 3, 1, 3 },
    { GOODIX_MILAN_ENROLLMENT_ACCEPTED, 4, 0, 3 },
    { GOODIX_MILAN_ENROLLMENT_ACCEPTED, 5, 0, 3 },
  };
  GoodixMatchInfo *info = generate_match_info ();
  g_autoptr(GBytes) extracted = goodix_milan_match_serialize_template (info);
  g_autoptr(GoodixMilanEnrollmentTransaction) transaction =
    goodix_milan_enrollment_transaction_new ();
  g_autoptr(GBytes) previous = NULL;
  guint bad_record_count = 0;
  guint bad_continue_count = 0;

  /* Native 2.0.310.900: 180042c30 gives metric 0x64000064 initially,
   * then 0x100 for this generated feature. 18002d4b0/180032990 roll back
   * the fourth scan until three consecutive retries suppress deletion.
   * Native stage/deletion execution also preserves the rejected order slot.
   * This exercises the transaction, not combine-only self-enrollment, and
   * carries its actual retained state and counters through every attempt. */
  for (guint attempt = 0; attempt < G_N_ELEMENTS (attempts); attempt++)
    {
      GoodixMilanEnrollmentResult result;
      GoodixMilanPrintTemplateInfo print_info;
      GoodixMilanUnpackedTemplate unpacked;
      g_autoptr(GBytes) published = NULL;
      g_autoptr(GError) error = NULL;
      gsize size;
      const guint8 *data;
      guint count = attempts[attempt].count;
      guint order_count = attempts[attempt].reject_detail ? count + 1 : count;

      g_test_message ("enrollment attempt %u", attempt + 1);
      g_assert_cmpint (goodix_milan_enrollment_transaction_attempt (
                         &transaction, extracted, &bad_record_count,
                         &bad_continue_count, &result), ==,
                       attempts[attempt].status);
      g_assert_cmpuint (result.pre_insertion_accepted_count, ==,
                        attempt ? attempts[attempt - 1].count : 0);
      g_assert_cmpint (result.overlap, ==, attempt ? 100 : 0);
      g_assert_cmpint (result.previous_overlap, ==, attempt ? 100 : 0);
      g_assert_cmpuint (result.reject_detail, ==, attempts[attempt].reject_detail);
      g_assert_cmpuint (bad_record_count, ==, attempts[attempt].bad_count);
      g_assert_cmpuint (bad_continue_count, ==, attempts[attempt].bad_count);
      g_assert_cmpuint (goodix_milan_enrollment_transaction_count (transaction),
                        ==, count);
      published = goodix_milan_enrollment_transaction_publish (transaction);
      g_assert_nonnull (published);
      g_assert_true (goodix_milan_print_validate_template (
                       published, &print_info, &error));
      g_assert_no_error (error);
      g_assert_cmpuint (print_info.feature_count, ==, count);
      g_assert_cmpuint (print_info.registration_count, ==,
                        1 + count * (count - 1) / 2);
      g_assert_cmpuint (print_info.relation_count, ==, count - 1);
      g_assert_cmpuint (print_info.graph_established, ==, count > 1);
      g_assert_cmpint (print_info.graph_reference_index, ==, count > 1 ? 0 : -1);
      g_assert_cmpuint (print_info.queue_state, ==, 0);
      g_assert_cmpuint (print_info.queue_transaction_counter, ==, 0);
      data = g_bytes_get_data (published, &size);
      g_assert_cmpint (goodix_milan_template_unpack (data, size, &unpacked), ==, 0);
      g_assert_cmpint (unpacked.metadata.graph_companion_f3, ==, -1);
      g_assert_cmpint (unpacked.metadata.graph_companion_f4, ==, -1);
      for (guint feature = 0; feature < count; feature++)
        {
          GoodixMilanFeatureView view;

          g_assert_cmpint (goodix_milan_template_parse_feature_element (
                             unpacked.feature_elements[feature],
                             unpacked.feature_element_sizes[feature], &view), ==, 0);
          g_assert_cmpuint (view.record_count, ==, 150);
          g_assert_cmpint (view.fields.tagged_values[0], ==, count > 1);
          g_assert_cmpint (view.fields.tagged_values[1], ==,
                           feature ? 1 + feature * (feature - 1) / 2 : 0);
          g_assert_cmpint (view.fields.tagged_values[5], ==, 0);
          g_assert_cmpint (view.fields.tagged_values[6], ==, 0);
          g_assert_cmpint (view.fields.tagged_values[7], ==, feature);
        }
      for (guint slot = 0; slot < GOODIX_MILAN_PROFILE9_ACTIVE_FEATURE_LIMIT; slot++)
        g_assert_cmpuint (goodix_milan_template_read_u32 (
                            unpacked.tail_state + slot * 4), ==,
                          slot < order_count ? slot : G_MAXUINT32);

      if (attempts[attempt].reject_detail)
        {
          GoodixMilanUnpackedTemplate before;

          data = g_bytes_get_data (previous, &size);
          g_assert_cmpint (goodix_milan_template_unpack (data, size, &before), ==, 0);
          for (guint feature = 0; feature < count; feature++)
            g_assert_cmpmem (unpacked.feature_elements[feature],
                             unpacked.feature_element_sizes[feature],
                             before.feature_elements[feature],
                             before.feature_element_sizes[feature]);
          for (guint relation = 0; relation < count - 1; relation++)
            {
              g_assert_cmpint (unpacked.relations[relation].index, ==,
                               before.relations[relation].index);
              g_assert_cmpmem (unpacked.relations[relation].values,
                               sizeof (unpacked.relations[relation].values),
                               before.relations[relation].values,
                               sizeof (before.relations[relation].values));
            }
        }
      g_clear_pointer (&previous, g_bytes_unref);
      previous = g_steal_pointer (&published);
    }
  goodix_milan_match_free_info (info);
}
