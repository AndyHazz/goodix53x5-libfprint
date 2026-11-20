/*
 * Goodix 53x5 driver for libfprint - current Milan runtime contracts
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-runtime-support.h"

int
main (int    argc,
      char **argv)
{
  gint status;

  g_test_init (&argc, &argv, NULL);
  g_mutex_init (&plan.mutex);
  g_cond_init (&plan.condition);
  const char *cleanup_names[] = {
    "update-clean", "update-cleanup-failure", "no-update-clean", "no-update-cleanup-failure",
    "no-match-clean", "no-match-cleanup-failure", "earlier-error", "missing-result",
    "cancelled-result", "removed-result",
  };
  for (guint i = 0; i < G_N_ELEMENTS (cleanup_names); i++)
    {
      g_autofree char *name = g_strdup_printf ("/goodix53x5/milan/runtime/cleanup/%s", cleanup_names[i]);
      g_test_add_data_func (name, GUINT_TO_POINTER (i), test_auth_cleanup_results);
    }
  g_test_add_func ("/goodix53x5/milan/runtime/auth-gallery-outcomes",
                   test_auth_gallery_outcomes);
  g_test_add_func ("/goodix53x5/milan/runtime/auth-publication-contracts",
                   test_auth_publication_contracts);
  g_test_add_func ("/goodix53x5/milan/runtime/malformed-current-print",
                   test_malformed_current_print);
  g_test_add_func ("/goodix53x5/milan/runtime/cancellation-no-publication",
                   test_cancellation_no_publication);
  g_test_add_func ("/goodix53x5/milan/runtime/enrollment-combine-retry",
                   test_enrollment_combine_retry);
  g_test_add_func ("/goodix53x5/milan/runtime/complete-enrollment-after-retry",
                   test_complete_enrollment_after_combine_retry);
  g_test_add_func ("/goodix53x5/milan/runtime/stale-result-guards",
                   test_stale_result_guards);
  status = g_test_run ();
  g_cond_clear (&plan.condition);
  g_mutex_clear (&plan.mutex);
  return status;
}
