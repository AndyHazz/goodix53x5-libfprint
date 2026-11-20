/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef TEST_GOODIX53X5_MILAN_STATE_TESTS_H
#define TEST_GOODIX53X5_MILAN_STATE_TESTS_H


void
test_queue_lifecycle (void);

void
test_queue_process (void);

void
test_study_actions (void);

void
test_queued_study_action (void);

void
test_production_match_study_handoff (void);

void
test_production_match_order_lifecycle (void);

void
test_production_study_competing_candidates (void);

void
test_production_match_bitmap_decision (void);

void
test_template_state (void);

#endif /* TEST_GOODIX53X5_MILAN_STATE_TESTS_H */
