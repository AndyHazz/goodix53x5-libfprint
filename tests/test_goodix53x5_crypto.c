// Host-side unit tests for the goodix53x5 GEA/GTLS decrypt path.
//
// These do NOT need the sensor, and they compile the real
// drivers/goodix53x5/goodix53x5-crypto.c translation unit - tests/shim provides
// a stand-in for libfprint's internal drivers_api.h so no configured libfprint
// tree is required (see tests/shim/drivers_api.h).
//
// Scope: memory safety of goodix_crypto_gea_decrypt() for device-controlled
// lengths, and the length validation in
// goodix_crypto_gtls_decrypt_sensor_data(). The GEA stream cipher works on
// 16-bit words; the payload length comes from the device reply, so an odd
// length must neither read nor write past the caller's buffers. See issue #21.
//
// Build and run from the repo root:
//
//   gcc -std=gnu99 -o /tmp/test_goodix_crypto tests/test_goodix53x5_crypto.c
//     drivers/goodix53x5/goodix53x5-crypto.c -Itests/shim -Idrivers/goodix53x5
//     $(pkg-config --cflags --libs glib-2.0) -lcrypto
//   /tmp/test_goodix_crypto
//
// (join those continuation lines into one command)

#include "goodix53x5-crypto.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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

/* The tests below deliberately drive rejection paths that fp_warn(); swallow
 * the log output so a passing run stays quiet. */
static GLogWriterOutput
silence_logs (GLogLevelFlags log_level, const GLogField *fields,
              gsize n_fields, gpointer user_data)
{
  (void) log_level; (void) fields; (void) n_fields; (void) user_data;
  return G_LOG_WRITER_HANDLED;
}

static const guint8 test_key[16] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Captured from the pre-fix implementation, which was already correct for even
 * lengths. Hardening the odd-length case must not change the even-length
 * keystream - every real capture depends on it. */
static const guint8 golden_in[16] = {
  0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2B, 0x32,
  0x39, 0x40, 0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A
};
static const guint8 golden_out[16] = {
  0x97, 0xCC, 0x5E, 0x4D, 0xAB, 0x57, 0x9A, 0xC9,
  0x7F, 0x07, 0xD1, 0x76, 0x4B, 0x21, 0x97, 0x83
};

static void
test_even_length_keystream_unchanged (void)
{
  guint8 out[16];

  goodix_crypto_gea_decrypt (test_key, golden_in, sizeof (golden_in), out);
  CHECK (memcmp (out, golden_out, sizeof (golden_out)) == 0,
         "even length decrypts to the same bytes as before");
}

/* The output buffer the driver allocates is exactly in_len bytes
 * (g_malloc (gea_data_len)), so writing out[in_len] is a heap overflow. Place a
 * canary immediately after the in_len-sized region and check it survives. */
static void
test_odd_length_does_not_write_past_out (void)
{
  const gsize in_len = 15; /* odd: the last 16-bit word is a lone byte */
  guint8 in[15];
  guint8 out[16];

  for (gsize i = 0; i < in_len; i++)
    in[i] = (guint8) (i * 11 + 3);

  out[in_len] = 0xA5;
  goodix_crypto_gea_decrypt (test_key, in, in_len, out);

  CHECK (out[in_len] == 0xA5,
         "odd length does not write past out[in_len - 1]");
}

/* Companion to the write check: the loop also reads in[i + 1] unconditionally.
 * Put the input flush against the end of a mapped page with the next page
 * unmapped, so an over-read faults. Runs in a child process because the
 * failure mode is SIGSEGV. */
static void
test_odd_length_does_not_read_past_in (void)
{
  const gsize in_len = 15;
  pid_t pid = fork ();

  if (pid == 0)
    {
      const long page = sysconf (_SC_PAGESIZE);
      guint8 *region = mmap (NULL, 2 * page, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      guint8 *in, out[32];

      if (region == MAP_FAILED || mprotect (region + page, page, PROT_NONE) != 0)
        _exit (2);

      /* Last in_len bytes of the first page; in[in_len] is the guard page. */
      in = region + page - in_len;
      for (gsize i = 0; i < in_len; i++)
        in[i] = (guint8) (i * 11 + 3);

      goodix_crypto_gea_decrypt (test_key, in, in_len, out);
      _exit (0);
    }

  if (pid < 0)
    {
      printf ("  FAIL: could not fork for the over-read probe\n");
      failures++;
      return;
    }

  int status = 0;
  waitpid (pid, &status, 0);

  if (WIFEXITED (status) && WEXITSTATUS (status) == 2)
    {
      printf ("  FAIL: over-read probe could not set up its guard page\n");
      failures++;
      return;
    }

  CHECK (WIFEXITED (status) && WEXITSTATUS (status) == 0,
         "odd length does not read past in[in_len - 1]");
}

/* --- Frame-level tests for goodix_crypto_gtls_decrypt_sensor_data() --- */

/* Encode a u32 in the device's custom byte order (the inverse of
 * goodix_crypto_decode_u32). */
static void
encode_u32 (guint8 *out, guint32 v)
{
  out[0] = (v >> 8) & 0xFF;
  out[1] = v & 0xFF;
  out[2] = (v >> 24) & 0xFF;
  out[3] = (v >> 16) & 0xFF;
}

/* Build a well-formed sensor-data frame whose GEA payload is exactly
 * gea_data_len bytes, so the parity of that length is under test.
 *
 *   [type(4)][msg_len(4)][5 stripped][gea_data][crc(4)][hmac(32)]
 *
 * gea_len is kept under 0x3A7 so the reassembly loop's block 0 passes the whole
 * payload through and no AES-CBC block is involved. The CRC and HMAC are
 * computed with the driver's own primitives, so the frame passes every
 * integrity check ahead of the GEA decrypt - exactly the position a spoofed
 * sensor is in, since the PSK is all-zero and client_random goes out in
 * cleartext. */
static guint8 *
build_frame (GoodixGtlsCtx *ctx, gsize gea_data_len, gsize *frame_len)
{
  const gsize gea_len = 5 + gea_data_len + 4;
  const gsize len = 8 + gea_len + 0x20;
  guint8 *frame = g_malloc0 (len);
  guint8 *gea = frame + 8;
  guint8 *hmac_input = g_malloc (4 + gea_len);
  guint32 counter = ctx->hmac_server_counter;

  g_assert (gea_len <= 0x3A7);

  frame[0] = 0x01; frame[1] = 0xAA; /* data_type 0xAA01, little endian */
  frame[4] = len & 0xFF;
  frame[5] = (len >> 8) & 0xFF;
  frame[6] = (len >> 16) & 0xFF;
  frame[7] = (len >> 24) & 0xFF;

  for (gsize i = 0; i < 5 + gea_data_len; i++)
    gea[i] = (guint8) (i * 13 + 5);

  encode_u32 (gea + 5 + gea_data_len,
              goodix_crypto_crc32_mpeg2 (gea + 5, gea_data_len));

  hmac_input[0] = counter & 0xFF;
  hmac_input[1] = (counter >> 8) & 0xFF;
  hmac_input[2] = (counter >> 16) & 0xFF;
  hmac_input[3] = (counter >> 24) & 0xFF;
  memcpy (hmac_input + 4, gea, gea_len);
  goodix_crypto_hmac_sha256 (ctx->hmac_key, 32, hmac_input, 4 + gea_len,
                             frame + 8 + gea_len);
  g_free (hmac_input);

  *frame_len = len;
  return frame;
}

static void
init_test_ctx (GoodixGtlsCtx *ctx)
{
  guint8 psk[GOODIX_PSK_LEN] = { 0 };

  goodix_crypto_gtls_init (ctx, psk);
  memcpy (ctx->symmetric_key, test_key, sizeof (test_key));
  memset (ctx->hmac_key, 0x5A, sizeof (ctx->hmac_key));
}

static void
test_even_gea_payload_still_decrypts (void)
{
  GoodixGtlsCtx ctx;
  gsize frame_len = 0, out_len = 0;
  guint8 *frame, *decrypted;

  init_test_ctx (&ctx);
  frame = build_frame (&ctx, 64, &frame_len);
  decrypted = goodix_crypto_gtls_decrypt_sensor_data (&ctx, frame, frame_len,
                                                      &out_len);

  CHECK (decrypted != NULL, "even GEA payload length is accepted");
  CHECK (out_len == 64, "even GEA payload reports its full length");

  g_free (decrypted);
  g_free (frame);
}

static void
test_odd_gea_payload_is_rejected (void)
{
  GoodixGtlsCtx ctx;
  gsize frame_len = 0, out_len = 0;
  guint8 *frame, *decrypted;

  init_test_ctx (&ctx);
  frame = build_frame (&ctx, 65, &frame_len);
  decrypted = goodix_crypto_gtls_decrypt_sensor_data (&ctx, frame, frame_len,
                                                      &out_len);

  CHECK (decrypted == NULL, "odd GEA payload length is rejected");

  g_free (decrypted);
  g_free (frame);
}

int
main (void)
{
  g_log_set_writer_func (silence_logs, NULL, NULL);

  test_even_length_keystream_unchanged ();
  test_odd_length_does_not_write_past_out ();
  test_odd_length_does_not_read_past_in ();
  test_even_gea_payload_still_decrypts ();
  test_odd_gea_payload_is_rejected ();

  if (failures == 0)
    {
      printf ("\nALL TESTS PASSED\n");
      return 0;
    }
  printf ("\n%d TEST(S) FAILED\n", failures);
  return 1;
}
