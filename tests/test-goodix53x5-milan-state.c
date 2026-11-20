/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <glib.h>

#include "test-goodix53x5-milan-state-tests.h"

int
main (int argc,
      char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix53x5/milan/state/queue-lifecycle",
                   test_queue_lifecycle);
  g_test_add_func ("/goodix53x5/milan/state/queue-process",
                   test_queue_process);
  g_test_add_func ("/goodix53x5/milan/state/template", test_template_state);
  g_test_add_func ("/goodix53x5/milan/state/study-actions",
                   test_study_actions);
  g_test_add_func ("/goodix53x5/milan/state/queued-study-action",
                   test_queued_study_action);
  g_test_add_func ("/goodix53x5/milan/state/production-match-study-handoff",
                   test_production_match_study_handoff);
  g_test_add_func ("/goodix53x5/milan/state/production-match-order-lifecycle",
                   test_production_match_order_lifecycle);
  g_test_add_func ("/goodix53x5/milan/state/production-match-bitmap-decision",
                   test_production_match_bitmap_decision);
  g_test_add_func ("/goodix53x5/milan/state/production-study-competing-candidates",
                   test_production_study_competing_candidates);
  return g_test_run ();
}
