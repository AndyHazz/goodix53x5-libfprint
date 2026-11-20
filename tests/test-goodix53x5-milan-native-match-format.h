/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef GOODIX_NATIVE_MATCH_FORMAT_H
#define GOODIX_NATIVE_MATCH_FORMAT_H

#include <stdint.h>

/* Fixed little-endian observation projection, not native memory/struct layout:
 * status, score, physical winner (-1 absent), relation count,
 * direct affine[6], routed affine[6], physical queue ranks[20].
 * The complete gallery is a separate unmodified DLL-packed artifact.
 */
#define NATIVE_MATCH_QUEUE_SLOTS 20
#define NATIVE_MATCH_WORDS (16 + NATIVE_MATCH_QUEUE_SLOTS)
#define NATIVE_MATCH_OBSERVATION_SIZE (4 * NATIVE_MATCH_WORDS)

static inline void
native_match_put_u32 (uint8_t *p, uint32_t value)
{
  for (unsigned int i = 0; i < 4; i++)
    p[i] = (uint8_t) (value >> (8 * i));
}

#endif
