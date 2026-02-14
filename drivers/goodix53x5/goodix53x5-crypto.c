/*
 * Goodix 53x5 driver for libfprint — Crypto layer
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "goodix53x5.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* CRC32-MPEG2 lookup table */
static const guint32 crc32_mpeg2_table[256] = {
  0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9,
  0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
  0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61,
  0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
  0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9,
  0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75,
  0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011,
  0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
  0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
  0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5,
  0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81,
  0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
  0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49,
  0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
  0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1,
  0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
  0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE,
  0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072,
  0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
  0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
  0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE,
  0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02,
  0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066,
  0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
  0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E,
  0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692,
  0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6,
  0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
  0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
  0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2,
  0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686,
  0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
  0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637,
  0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
  0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F,
  0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
  0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47,
  0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B,
  0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
  0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
  0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7,
  0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
  0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F,
  0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
  0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7,
  0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B,
  0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F,
  0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
  0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
  0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C,
  0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8,
  0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
  0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30,
  0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
  0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088,
  0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
  0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0,
  0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C,
  0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
  0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
  0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0,
  0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C,
  0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668,
  0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
};

/**
 * goodix_crypto_crc32_mpeg2:
 *
 * Compute CRC32-MPEG2 checksum.
 */
guint32
goodix_crypto_crc32_mpeg2 (const guint8 *data,
                           gsize         len)
{
  guint32 crc = 0xFFFFFFFF;

  for (gsize i = 0; i < len; i++)
    crc = (crc << 8) ^ crc32_mpeg2_table[((crc >> 24) ^ data[i]) & 0xFF];

  return crc;
}

/**
 * goodix_crypto_decode_u32:
 *
 * Decode a 4-byte value with the custom byte order used by the device.
 * data[0]*0x100 + data[1] + data[2]*0x1000000 + data[3]*0x10000
 */
guint32
goodix_crypto_decode_u32 (const guint8 *data)
{
  return (guint32) data[0] * 0x100 +
         (guint32) data[1] +
         (guint32) data[2] * 0x1000000 +
         (guint32) data[3] * 0x10000;
}

/**
 * goodix_crypto_hmac_sha256:
 *
 * Compute HMAC-SHA256 using GLib's GHmac.
 * Output is always 32 bytes.
 */
void
goodix_crypto_hmac_sha256 (const guint8 *key,
                           gsize         key_len,
                           const guint8 *data,
                           gsize         data_len,
                           guint8       *out)
{
  g_autoptr(GHmac) hmac = g_hmac_new (G_CHECKSUM_SHA256, key, key_len);
  gsize digest_len = 32;

  g_hmac_update (hmac, data, data_len);
  g_hmac_get_digest (hmac, out, &digest_len);
}

/**
 * goodix_crypto_aes_cbc_decrypt:
 *
 * AES-128-CBC decryption using OpenSSL EVP.
 * No padding (input must be a multiple of 16 bytes).
 */
void
goodix_crypto_aes_cbc_decrypt (const guint8 *key,
                               const guint8 *iv,
                               const guint8 *in,
                               gsize         in_len,
                               guint8       *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int out_len = 0, final_len = 0;

  EVP_DecryptInit_ex (ctx, EVP_aes_128_cbc (), NULL, key, iv);
  EVP_CIPHER_CTX_set_padding (ctx, 0);
  EVP_DecryptUpdate (ctx, out, &out_len, in, (int) in_len);
  EVP_DecryptFinal_ex (ctx, out + out_len, &final_len);
  EVP_CIPHER_CTX_free (ctx);
}

/**
 * goodix_crypto_derive_session_key:
 *
 * TLS 1.0-style PRF: HMAC-SHA256 based P_hash.
 * seed = "master secret" + random_data
 * A(0) = seed, A(i) = HMAC(psk, A(i-1))
 * output = HMAC(psk, A(1)+seed) + HMAC(psk, A(2)+seed) + ...
 */
void
goodix_crypto_derive_session_key (const guint8 *psk,
                                  gsize         psk_len,
                                  const guint8 *random_data,
                                  gsize         random_len,
                                  guint8       *out_key,
                                  gsize         key_len)
{
  const gchar *label = "master secret";
  gsize label_len = strlen (label);
  gsize seed_len = label_len + random_len;
  g_autofree guint8 *seed = g_malloc (seed_len);
  guint8 a_val[32];  /* A(i) */
  guint8 hmac_out[32];
  gsize offset = 0;

  memcpy (seed, label, label_len);
  memcpy (seed + label_len, random_data, random_len);

  /* A(0) = seed; first iteration: A(1) = HMAC(psk, seed) */
  goodix_crypto_hmac_sha256 (psk, psk_len, seed, seed_len, a_val);

  while (offset < key_len)
    {
      /* HMAC(psk, A(i) + seed) */
      gsize concat_len = 32 + seed_len;
      g_autofree guint8 *concat = g_malloc (concat_len);

      memcpy (concat, a_val, 32);
      memcpy (concat + 32, seed, seed_len);
      goodix_crypto_hmac_sha256 (psk, psk_len, concat, concat_len, hmac_out);

      gsize copy_len = MIN (32, key_len - offset);
      memcpy (out_key + offset, hmac_out, copy_len);
      offset += copy_len;

      /* A(i+1) = HMAC(psk, A(i)) */
      goodix_crypto_hmac_sha256 (psk, psk_len, a_val, 32, a_val);
    }
}

/**
 * goodix_crypto_gea_decrypt:
 *
 * GEA stream cipher decryption (LFSR-based, ported from Python).
 * key4 points to 4 bytes of key material.
 * Processes data in 2-byte units (little-endian).
 */
void
goodix_crypto_gea_decrypt (const guint8 *key4,
                           const guint8 *in,
                           gsize         in_len,
                           guint8       *out)
{
  guint32 key = (guint32) key4[0] |
                ((guint32) key4[1] << 8) |
                ((guint32) key4[2] << 16) |
                ((guint32) key4[3] << 24);
  guint32 uVar3, uVar2;
  guint16 uVar1, input_element, stream_val;

  for (gsize i = 0; i < in_len; i += 2)
    {
      uVar3 = (key >> 1 ^ key) & 0xFFFFFFFF;
      uVar2 = (((((((
                       ((key >> 0xF & 0x2000) | (key & 0x1000000)) >> 1 |
                        (key & 0x20000)) >>
                       2 |
                      (key & 0x1000)) >>
                     3 |
                    ((key >> 7 ^ key) & 0x80000)) >>
                   1 |
                  ((key >> 0xF ^ key) & 0x4000)) >>
                 2 |
                (key & 0x2000)) >>
               2 |
              (uVar3 & 0x40) | (key & 0x20)) >>
             1 |
            ((key >> 9 ^ key << 8) & 0x800) |
            ((key >> 0x14 ^ key * 2) & 4) |
            ((key * 8 ^ key >> 0x10) & 0x4000) |
            ((key >> 2 ^ key >> 0x10) & 0x80) |
            ((key << 6 ^ key >> 7) & 0x100) |
            ((key & 0x100) << 7));
      uVar2 = uVar2 & 0xFFFFFFFF;
      uVar1 = key & 0xFFFF;
      key = ((key ^ (uVar3 >> 0x14 ^ key) >> 10) << 0x1F |
             key >> 1) &
            0xFFFFFFFF;

      input_element = (guint16) in[i] | ((guint16) in[i + 1] << 8);
      stream_val = (guint16) (((uVar2 >> 8) & 0xFFFF) +
                              ((uVar2 & 0xFF) | (uVar1 & 1)) * 0x100);
      guint16 decrypted = input_element ^ stream_val;
      out[i] = decrypted & 0xFF;
      out[i + 1] = (decrypted >> 8) & 0xFF;
    }
}

/**
 * goodix_crypto_gtls_init:
 *
 * Initialize GTLS context with PSK.
 */
void
goodix_crypto_gtls_init (GoodixGtlsCtx *ctx,
                         const guint8   *psk)
{
  memset (ctx, 0, sizeof (GoodixGtlsCtx));
  memcpy (ctx->psk, psk, GOODIX_PSK_LEN);
  ctx->state = 0;
}

/**
 * goodix_crypto_gtls_derive_keys:
 *
 * Given client_random and server_random are set, derive all session keys.
 * Returns TRUE on success.
 */
gboolean
goodix_crypto_gtls_derive_keys (GoodixGtlsCtx *ctx)
{
  guint8 random_data[64];
  guint8 session_key[GOODIX_SESSION_KEY_LEN];

  memcpy (random_data, ctx->client_random, 32);
  memcpy (random_data + 32, ctx->server_random, 32);

  goodix_crypto_derive_session_key (ctx->psk, GOODIX_PSK_LEN,
                                    random_data, 64,
                                    session_key, GOODIX_SESSION_KEY_LEN);

  memcpy (ctx->symmetric_key, session_key, 16);
  memcpy (ctx->symmetric_iv, session_key + 16, 16);
  memcpy (ctx->hmac_key, session_key + 32, 32);
  ctx->hmac_client_counter_init =
    (guint16) session_key[64] | ((guint16) session_key[65] << 8);
  ctx->hmac_server_counter_init =
    (guint16) session_key[66] | ((guint16) session_key[67] << 8);

  return TRUE;
}

/**
 * goodix_crypto_gtls_verify_identity:
 *
 * Compute client identity and compare with server identity.
 * client_identity = HMAC-SHA256(hmac_key, client_random + server_random)
 * Returns TRUE if they match.
 */
gboolean
goodix_crypto_gtls_verify_identity (GoodixGtlsCtx *ctx)
{
  guint8 data[64];

  memcpy (data, ctx->client_random, 32);
  memcpy (data + 32, ctx->server_random, 32);

  goodix_crypto_hmac_sha256 (ctx->hmac_key, 32, data, 64,
                             ctx->client_identity);

  return memcmp (ctx->client_identity, ctx->server_identity, 32) == 0;
}

/**
 * goodix_crypto_gtls_decrypt_sensor_data:
 *
 * Decrypt sensor data received from the device.
 * The encrypted message format:
 *   [data_type(4 LE)][msg_length(4 LE)][encrypted_payload][hmac(32)]
 *
 * The encrypted payload is processed in 15 blocks:
 *   - Even blocks (0,2,4,...,14): pass through (GEA encrypted)
 *   - Odd blocks (1,3,...,13): AES-CBC decrypt first
 * Block sizes: block 0 = 0x3A7, blocks 1-13 = 0x3F0, block 14 = remainder
 *
 * After reassembly:
 *   1. Verify HMAC over last 0x400 bytes
 *   2. Strip first 5 bytes
 *   3. Verify CRC32-MPEG2 over data (excl. last 4 bytes)
 *   4. GEA decrypt using first 4 bytes of symmetric_key
 *
 * Returns newly allocated decrypted data, or NULL on error.
 */
guint8 *
goodix_crypto_gtls_decrypt_sensor_data (GoodixGtlsCtx *ctx,
                                        const guint8   *encrypted,
                                        gsize           encrypted_len,
                                        gsize          *out_len)
{
  guint32 data_type, msg_length;
  const guint8 *encrypted_payload;
  gsize encrypted_payload_len;
  const guint8 *payload_hmac;
  guint8 *gea_encrypted = NULL;
  gsize gea_len = 0;
  guint8 computed_hmac[32];
  guint8 hmac_data_prefix[4];
  guint32 msg_gea_crc, computed_crc;
  guint8 *decrypted = NULL;

  if (encrypted_len < 8 + 0x20)
    {
      fp_warn ("Encrypted data too short: %zu", encrypted_len);
      return NULL;
    }

  data_type = encrypted[0] | ((guint32) encrypted[1] << 8) |
              ((guint32) encrypted[2] << 16) | ((guint32) encrypted[3] << 24);

  if (data_type != 0xAA01)
    {
      fp_warn ("Unexpected sensor data type: 0x%x", data_type);
      return NULL;
    }

  msg_length = encrypted[4] | ((guint32) encrypted[5] << 8) |
               ((guint32) encrypted[6] << 16) | ((guint32) encrypted[7] << 24);

  if (msg_length != (guint32) encrypted_len)
    {
      fp_warn ("Sensor data length mismatch: %u != %zu",
               msg_length, encrypted_len);
      return NULL;
    }

  encrypted_payload = encrypted + 8;
  encrypted_payload_len = encrypted_len - 8 - 0x20;
  payload_hmac = encrypted + encrypted_len - 0x20;

  /* Process 15 blocks: alternating passthrough/AES-CBC */
  gea_encrypted = g_malloc (encrypted_payload_len);

  const guint8 *ep = encrypted_payload;
  gsize ep_remaining = encrypted_payload_len;

  for (int block = 0; block < 15; block++)
    {
      gsize block_size;

      if (block % 2 == 0)
        {
          /* Pass-through block */
          if (block == 0)
            block_size = MIN (0x3A7, ep_remaining);
          else if (block == 14)
            block_size = ep_remaining;
          else
            block_size = MIN (0x3F0, ep_remaining);

          memcpy (gea_encrypted + gea_len, ep, block_size);
          gea_len += block_size;
          ep += block_size;
          ep_remaining -= block_size;
        }
      else
        {
          /* AES-CBC decrypt block */
          block_size = MIN (0x3F0, ep_remaining);

          goodix_crypto_aes_cbc_decrypt (ctx->symmetric_key,
                                         ctx->symmetric_iv,
                                         ep, block_size,
                                         gea_encrypted + gea_len);
          gea_len += block_size;
          ep += block_size;
          ep_remaining -= block_size;
        }
    }

  /* Verify HMAC over last 0x400 bytes of gea_encrypted */
  hmac_data_prefix[0] = ctx->hmac_server_counter & 0xFF;
  hmac_data_prefix[1] = (ctx->hmac_server_counter >> 8) & 0xFF;
  hmac_data_prefix[2] = (ctx->hmac_server_counter >> 16) & 0xFF;
  hmac_data_prefix[3] = (ctx->hmac_server_counter >> 24) & 0xFF;

  {
    gsize hmac_data_len = 4 + MIN (0x400, gea_len);
    g_autofree guint8 *hmac_data_buf = g_malloc (hmac_data_len);

    memcpy (hmac_data_buf, hmac_data_prefix, 4);
    if (gea_len >= 0x400)
      memcpy (hmac_data_buf + 4, gea_encrypted + gea_len - 0x400, 0x400);
    else
      memcpy (hmac_data_buf + 4, gea_encrypted, gea_len);

    goodix_crypto_hmac_sha256 (ctx->hmac_key, 32,
                               hmac_data_buf, hmac_data_len,
                               computed_hmac);
  }

  if (memcmp (computed_hmac, payload_hmac, 32) != 0)
    {
      fp_warn ("HMAC verification failed");
      g_free (gea_encrypted);
      return NULL;
    }

  fp_dbg ("Encrypted payload HMAC verified");
  ctx->hmac_server_counter = (ctx->hmac_server_counter + 1) & 0xFFFFFFFF;

  /* Strip first 5 bytes */
  if (gea_len < 5 + 4)
    {
      fp_warn ("GEA payload too short: %zu", gea_len);
      g_free (gea_encrypted);
      return NULL;
    }

  guint8 *gea_data = gea_encrypted + 5;
  gsize gea_data_len = gea_len - 5;

  /* Extract and verify CRC */
  msg_gea_crc = goodix_crypto_decode_u32 (gea_data + gea_data_len - 4);
  gea_data_len -= 4;

  computed_crc = goodix_crypto_crc32_mpeg2 (gea_data, gea_data_len);
  if (computed_crc != msg_gea_crc)
    {
      fp_warn ("CRC check failed: computed 0x%08x, expected 0x%08x",
               computed_crc, msg_gea_crc);
      g_free (gea_encrypted);
      return NULL;
    }
  fp_dbg ("GEA data CRC verified");

  /* GEA decrypt */
  decrypted = g_malloc (gea_data_len);
  goodix_crypto_gea_decrypt (ctx->symmetric_key, gea_data, gea_data_len,
                             decrypted);

  *out_len = gea_data_len;
  g_free (gea_encrypted);
  return decrypted;
}
