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

#include <glib.h>

int
main (int argc,
      char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix53x5/milan/preprocess-classification-retry",
                    test_preprocess_classification_retry);
  g_test_add_func ("/goodix53x5/milan/preprocess-post-render-retry",
                   test_preprocess_post_render_retry);
  g_test_add_func ("/goodix53x5/milan/mature-temporal-classification",
                   test_mature_temporal_classification);
  g_test_add_func ("/goodix53x5/milan/selection", test_selection_rows);
  g_test_add_func ("/goodix53x5/milan/gain-tail", test_gain_tail);
  g_test_add_func ("/goodix53x5/milan/generated-extraction",
                    test_generated_extraction);
  g_test_add_func ("/goodix53x5/milan/study-policy-actions",
                    test_study_policy_actions);
  g_test_add_func ("/goodix53x5/milan/generated-enrollment-prefix-lifecycle",
                    test_generated_enrollment_prefix_lifecycle);
  g_test_add_func ("/goodix53x5/milan/generated-enrollment-retry-continuation",
                    test_generated_enrollment_retry_continuation);
  g_test_add_func ("/goodix53x5/milan/generated-production-replay",
                    test_generated_production_replay);
  return g_test_run ();
}
