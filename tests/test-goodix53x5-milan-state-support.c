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

guint8
synthetic_byte (guint seed,
                gsize index)
{
  return (guint8) ((seed * 37U + index * 19U + (index >> 2)) & 0xffU);
}

const GoodixMatchInfo *
queue_entry_at_rank (const GoodixStudyQueue *queue,
                     gint rank)
{
  for (gsize slot = 0; slot < GOODIX_STUDY_QUEUE_CAPACITY; slot++)
    if (queue->entries[slot].rank == rank)
      return queue->entries[slot].info;
  return NULL;
}
