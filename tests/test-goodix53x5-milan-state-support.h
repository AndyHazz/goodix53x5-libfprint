/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef TEST_GOODIX53X5_MILAN_STATE_SUPPORT_H
#define TEST_GOODIX53X5_MILAN_STATE_SUPPORT_H

#include "drivers/goodix53x5/milan/study/queue.h"

guint8
synthetic_byte (guint seed,
                gsize index);

const GoodixMatchInfo *
queue_entry_at_rank (const GoodixStudyQueue *queue,
                     gint rank);

#endif /* TEST_GOODIX53X5_MILAN_STATE_SUPPORT_H */
