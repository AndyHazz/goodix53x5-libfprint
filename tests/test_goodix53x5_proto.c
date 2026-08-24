/*
 * Host-side unit tests for goodix53x5 proto checksum validation.
 *
 * Compiles the real drivers/goodix53x5/goodix53x5-proto.c translation unit
 * against tests/shim (see tests/shim/drivers_api.h), so only glib is needed.
 *
 * Regression coverage for the 0x88 trailer handling: the additive checksum
 * must still be honored, and a corrupted checksummed message whose trailing
 * byte happens to be 0x88 must be rejected rather than accepted as a
 * "handshake" marker.
 *
 * Build and run from the repo root:
 *
 *   gcc -std=gnu99 -Wall -o /tmp/test_goodix_proto tests/test_goodix53x5_proto.c \
 *     drivers/goodix53x5/goodix53x5-proto.c -Itests/shim -Idrivers/goodix53x5 \
 *     $(pkg-config --cflags --libs glib-2.0)
 *   /tmp/test_goodix_proto
 */

#include "goodix53x5-proto.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
      if (!(cond))                                                             \
        {                                                                      \
          printf ("  FAIL: %s\n", msg);                                        \
          failures++;                                                          \
        }                                                                      \
      else                                                                     \
        {                                                                      \
          printf ("  ok:   %s\n", msg);                                        \
        }                                                                      \
  } while (0)

static guint8
compute_checksum (const guint8 *data, gsize len /* including trailer slot */)
{
  guint sum = 0;

  for (gsize i = 0; i < len - 1; i++)
    sum += data[i];

  return (0xAA - sum) & 0xFF;
}

int
main (void)
{
  /* A realistic short message: cmd + size(2) + payload + checksum.
   * cmd_byte 0x40 = category 4, so the additive checksum is authoritative. */
  guint8 msg[] = { 0x40, 0x03, 0x00, 0x11, 0x22, 0x00 };
  gsize msg_len = sizeof (msg);

  msg[msg_len - 1] = compute_checksum (msg, msg_len);
  CHECK (goodix_proto_validate_checksum (msg, msg_len),
         "valid additive checksum accepted");

  /* The regression case: a checksummed message corrupted so that its
   * (now-wrong) trailer byte is exactly the handshake marker 0x88 must NOT
   * be waved through by the marker check. Payload byte 0xEE makes the
   * additive checksum of this frame 0x57, not 0x88. */
  msg[3] = 0xEE;
  msg[msg_len - 1] = 0x88;
  CHECK (!goodix_proto_validate_checksum (msg, msg_len),
         "corrupted message with 0x88 trailer rejected");


  /* Handshake traffic (category 0x1, e.g. cmd_byte 0x10) carries a literal
   * 0x88 trailer and must still be accepted. */
  {
    guint8 hs[] = { 0x10, 0x02, 0x00, 0xAA, 0xBB, 0x88 };

    CHECK (goodix_proto_validate_checksum (hs, sizeof (hs)),
           "handshake-category message with 0x88 trailer accepted");
  }

  /* A checksummed message that also ends in 0x88: valid under both
   * interpretations, accepted either way. */
  {
    guint8 both[] = { 0x40, 0x03, 0x00, 0x00, 0x00, 0x00 };
    gsize both_len = sizeof (both);

    both[3] = 0xDF;             /* makes (0xAA - sum) == 0x88 exactly */
    both[both_len - 1] = compute_checksum (both, both_len);
    CHECK (both[both_len - 1] == 0x88,
           "test setup: computed checksum equals 0x88 marker value");
    CHECK (goodix_proto_validate_checksum (both, both_len),
           "message valid under both interpretations accepted");
  }

  /* Too-short messages are invalid regardless of trailer. */
  {
    guint8 short_msg[] = { 0x01, 0x02, 0x88 };

    CHECK (!goodix_proto_validate_checksum (short_msg, sizeof (short_msg)),
           "message shorter than header+checksum rejected");
  }

  if (failures == 0)
    printf ("\nALL TESTS PASSED\n");
  else
    printf ("\n%d test(s) FAILED\n", failures);

  return failures ? 1 : 0;
}
