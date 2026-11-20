/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Fixed synthetic fixture wire format. Encoding only, no algorithm decisions.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define NP_PIXELS 9504
#define NP_FRAME_BYTES (2 * NP_PIXELS)
#define NP_INPUT_BYTES (3 * NP_FRAME_BYTES)
#define NP_NATURAL_RECORD_BYTES (4 * NP_PIXELS + 23)
#define NP_TEMPORAL_RECORD_BYTES (4 * NP_PIXELS + 19)

static inline uint16_t
np_read16 (const uint8_t *p)
{
  return (uint16_t) p[0] | (uint16_t) p[1] << 8;
}

static inline void
np_write32 (uint8_t *p, uint32_t value)
{
  for (unsigned int i = 0; i < 4; i++)
    p[i] = (uint8_t) (value >> (8 * i));
}

static inline void
np_write_words (uint8_t *p, const uint16_t *words)
{
  for (size_t i = 0; i < NP_PIXELS; i++)
    {
      p[2 * i] = (uint8_t) words[i];
      p[2 * i + 1] = (uint8_t) (words[i] >> 8);
    }
}
