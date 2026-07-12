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

#pragma once

#include <glib.h>

/* All-zero PSK (32 bytes) */
#define GOODIX_PSK_LEN 32

/* GTLS session key material size */
#define GOODIX_SESSION_KEY_LEN 0x44

/* --- GTLS context --- */
typedef struct
{
  gint    state;
  guint8  client_random[32];
  guint8  server_random[32];
  guint8  client_identity[32];
  guint8  server_identity[32];
  guint8  symmetric_key[16];
  guint8  symmetric_iv[16];
  guint8  hmac_key[32];
  guint16 hmac_client_counter_init;
  guint16 hmac_server_counter_init;
  guint32 hmac_client_counter;
  guint32 hmac_server_counter;
  guint8  psk[GOODIX_PSK_LEN];
} GoodixGtlsCtx;

void     goodix_crypto_gtls_init (GoodixGtlsCtx *ctx,
                                  const guint8   *psk);

gboolean goodix_crypto_gtls_derive_keys (GoodixGtlsCtx *ctx);

gboolean goodix_crypto_gtls_verify_identity (GoodixGtlsCtx *ctx);

guint8  *goodix_crypto_gtls_decrypt_sensor_data (GoodixGtlsCtx *ctx,
                                                  const guint8  *encrypted,
                                                  gsize          encrypted_len,
                                                  gsize         *out_len);

void     goodix_crypto_derive_session_key (const guint8 *psk,
                                           gsize         psk_len,
                                           const guint8 *random_data,
                                           gsize         random_len,
                                           guint8       *out_key,
                                           gsize         key_len);

void     goodix_crypto_gea_decrypt (const guint8 *key4,
                                    const guint8 *in,
                                    gsize         in_len,
                                    guint8       *out);

guint32  goodix_crypto_crc32_mpeg2 (const guint8 *data,
                                    gsize         len);

guint32  goodix_crypto_decode_u32 (const guint8 *data);

void     goodix_crypto_aes_cbc_decrypt (const guint8 *key,
                                        const guint8 *iv,
                                        const guint8 *in,
                                        gsize         in_len,
                                        guint8       *out);

void     goodix_crypto_hmac_sha256 (const guint8 *key,
                                    gsize         key_len,
                                    const guint8 *data,
                                    gsize         data_len,
                                    guint8       *out);
