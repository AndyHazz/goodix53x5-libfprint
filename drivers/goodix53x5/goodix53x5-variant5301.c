/*
 * Goodix 53x5 driver for libfprint — 27c6:5301 variant
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
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
#include "goodix53x5-private.h"
#include "goodix53x5-calibration.h"
#include "goodix53x5-variant5301.h"

#include <string.h>

/* Host configuration template for chip 0x2202 (108x88), variant index 0 of
 * the four templates in the 5301 Windows driver. The trailing checksum is
 * recomputed after patching, as the Windows host does. */
static const guint8 default_config_5301[256] = {
  0x08, 0x11, 0x54, 0x65, 0x24, 0x89, 0x24, 0xad,
  0x1c, 0xc9, 0x1c, 0xe5, 0x04, 0xe9, 0x04, 0xed,
  0x13, 0xba, 0x00, 0x01, 0x00, 0xca, 0x00, 0x07,
  0x00, 0x84, 0x00, 0x80, 0x81, 0x86, 0x00, 0x80,
  0x8c, 0x88, 0x00, 0x80, 0x97, 0x8a, 0x00, 0x80,
  0xb0, 0x8c, 0x00, 0x80, 0x86, 0x8e, 0x00, 0x80,
  0x8c, 0x90, 0x00, 0x80, 0xa0, 0x92, 0x00, 0x80,
  0xb3, 0x94, 0x00, 0x80, 0x84, 0x96, 0x00, 0x80,
  0x88, 0x98, 0x00, 0x80, 0xa0, 0x9a, 0x00, 0x80,
  0xb8, 0x56, 0x00, 0x08, 0x28, 0x58, 0x00, 0x48,
  0x00, 0x70, 0x00, 0x01, 0x00, 0x72, 0x00, 0x78,
  0x56, 0x74, 0x00, 0x34, 0x12, 0x26, 0x00, 0x00,
  0x12, 0xd0, 0x00, 0x00, 0x00, 0x20, 0x01, 0x02,
  0x04, 0x20, 0x00, 0x10, 0x40, 0x22, 0x00, 0x01,
  0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01,
  0x04, 0x5c, 0x00, 0x80, 0x00, 0x28, 0x02, 0x00,
  0x00, 0x2a, 0x02, 0x00, 0x00, 0x82, 0x00, 0x80,
  0x15, 0x20, 0x01, 0x82, 0x04, 0x20, 0x00, 0x10,
  0x40, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
  0x00, 0x80, 0x00, 0x01, 0x04, 0x5c, 0x00, 0x00,
  0x01, 0x28, 0x02, 0x00, 0x00, 0x2a, 0x02, 0x00,
  0x00, 0x82, 0x00, 0x80, 0x15, 0x20, 0x01, 0x08,
  0x04, 0x22, 0x00, 0x10, 0x08, 0x80, 0x00, 0x01,
  0x00, 0x5c, 0x00, 0x80, 0x00, 0x28, 0x02, 0x00,
  0x00, 0x2a, 0x02, 0x00, 0x00, 0x82, 0x00, 0x80,
  0x15, 0x20, 0x01, 0x08, 0x04, 0x5c, 0x00, 0x80,
  0x00, 0x50, 0x00, 0x01, 0x05, 0x52, 0x00, 0x08,
  0x00, 0x54, 0x00, 0x10, 0x01, 0x28, 0x02, 0x00,
  0x00, 0x2a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#define TCODE_TAG      0x5C
#define DELTA_DOWN_TAG 0x82

gboolean
goodix_is_5301 (FpDevice *dev)
{
  return fpi_device_get_driver_data (dev) == GOODIX_VARIANT_5301;
}

/* ========================================================================
 * OTP
 * ======================================================================== */

/**
 * goodix_5301_verify_otp:
 *
 * The 5301 Windows driver stores its OTP checksum at byte 30 (not 25) and
 * computes it over bytes 0..19 plus a variant-dependent selection of bytes
 * 26..31, then applies a structure check. Ported from milanFusb.dll
 * VA 0x18000ebc4 (checksum) and 0x18000eaec (structure).
 */
gboolean
goodix_5301_verify_otp (const guint8 *otp,
                        gsize         otp_len)
{
  guint8 data[25];
  guint8 checked[32];
  gboolean blank;
  gboolean checksum_ok = FALSE;
  guint sum = 0;
  guint selector;

  if (otp_len < 32)
    return FALSE;

  blank = TRUE;
  for (int i = 8; i < 18; i++)
    if (otp[i] != 0)
      blank = FALSE;
  if (otp[30] != 0)
    blank = FALSE;
  if (blank)
    checksum_ok = TRUE;

  for (int i = 0; i < 20; i++)
    sum += otp[i];
  if (((sum + otp[29] + otp[31]) & 0xFF) == otp[30])
    checksum_ok = TRUE;

  memcpy (data, otp, 20);
  data[20] = otp[29];
  data[21] = otp[31];
  if (goodix_device_compute_otp_hash (data, 22) == otp[30])
    checksum_ok = TRUE;

  if (otp[28] == 0xC0)
    {
      data[20] = otp[28];
      data[21] = otp[29];
      data[22] = otp[31];
      if (goodix_device_compute_otp_hash (data, 23) == otp[30])
        checksum_ok = TRUE;
    }
  else
    {
      memcpy (data + 20, otp + 26, 4);
      data[24] = otp[31];
      if (goodix_device_compute_otp_hash (data, 25) == otp[30])
        checksum_ok = TRUE;
    }

  if (!checksum_ok)
    {
      fp_warn ("5301 OTP checksum mismatch");
      return FALSE;
    }

  memcpy (checked, otp, 32);
  if (blank)
    memset (checked + 26, 0, 3);
  selector = (checked[8] >> 6) + 4 * (checked[9] & 0x03);
  if (checked[20] != 0 && checked[21] != 0)
    return TRUE;
  if ((checked[8] & 0x3E) == 0x20 && selector < 4)
    return TRUE;
  for (int i = 8; i < 18; i++)
    if (checked[i] != 0)
      goto structure_failed;
  for (int i = 20; i < 29; i++)
    if (checked[i] != 0)
      goto structure_failed;
  if (checked[30] == 0)
    return TRUE;

structure_failed:
  fp_warn ("5301 OTP structure check failed");
  return FALSE;
}

/**
 * goodix_5301_parse_otp:
 *
 * Ported from the host configuration builder at VA 0x180011290. OTP byte 22
 * must be nonzero and byte 23 its complement; the high nibble of byte 22
 * gives tcode and the low nibble delta-down. Otherwise the template values
 * (tcode 0x80, delta-down 0x15) stay in place, as in the Windows driver.
 *
 * The 5301 firmware ignores the DAC fields of the image request and the
 * 53x5 FDT thresholds are not part of its config, so delta_up and delta_fdt
 * follow the 53x5 ratios to keep the shared FDT code well-defined.
 */
void
goodix_5301_parse_otp (const guint8      *otp,
                       gsize              otp_len,
                       GoodixCalibParams *params)
{
  guint16 tcode = 0x80;
  guint16 delta_down = 0x15;

  memset (params, 0, sizeof (GoodixCalibParams));

  if (otp_len >= 32 && otp[22] != 0 && ((otp[22] + otp[23]) & 0xFF) == 0xFF)
    {
      guint32 quotient;

      tcode = (((otp[22] >> 4) + 1) << 4) & 0xFFFF;
      quotient = ((((otp[22] & 0x0F) + 2) * 0x6400) / tcode) & 0xFFFF;
      delta_down = (quotient / 3) >> 4;
    }
  else
    {
      fp_warn ("5301 OTP calibration bytes invalid; using template defaults");
    }

  params->tcode = tcode;
  params->delta_down = delta_down;
  params->delta_up = delta_down > 2 ? delta_down - 2 : 1;
  params->delta_fdt = MAX (delta_down * 3 / 5, 1);
  params->delta_img = 0xC8;
  params->delta_nav = 0x28;

  fp_dbg ("5301 calibration: tcode=0x%x delta_down=0x%x delta_up=0x%x delta_fdt=0x%x",
          params->tcode, params->delta_down, params->delta_up, params->delta_fdt);
}

/* ========================================================================
 * Configuration
 * ======================================================================== */

const guint8 *
goodix_5301_get_default_config (gsize *out_len)
{
  *out_len = sizeof (default_config_5301);
  return default_config_5301;
}

/**
 * goodix_5301_patch_config:
 *
 * The Windows host patches exactly two entries: tcode in section 4
 * (VA 0x18000237c) and the high byte of delta-down in section 2
 * (VA 0x1800022cc), then recomputes the checksum.
 */
void
goodix_5301_patch_config (guint8                  *config,
                          gsize                    config_len,
                          const GoodixCalibParams *params)
{
  goodix_device_replace_config_value (config, config_len, 4, TCODE_TAG,
                                      params->tcode);
  goodix_device_replace_config_value (config, config_len, 2, DELTA_DOWN_TAG,
                                      (params->delta_down << 8) | 0x80);
  goodix_device_fix_config_checksum (config, config_len);
}

/* ========================================================================
 * Image payload
 * ======================================================================== */

static guint32
crc32_mpeg2 (const guint8 *data,
             gsize         len)
{
  guint32 crc = 0xFFFFFFFF;

  for (gsize i = 0; i < len; i++)
    {
      crc ^= (guint32) data[i] << 24;
      for (int bit = 0; bit < 8; bit++)
        crc = (crc & 0x80000000) ? (crc << 1) ^ 0x04C11DB7 : crc << 1;
    }

  return crc;
}

/* 32-bit generator at milanFusb.dll VA 0x18000ed24; each step yields one
 * 16-bit XOR word for the next two payload bytes. */
static guint16
windows_next_word (guint32 *state_io)
{
  guint32 state = *state_io;
  guint32 right1 = state >> 1;
  guint32 right7 = state >> 7;
  guint32 xor1 = right1 ^ state;
  guint32 right15 = state >> 15;
  guint32 value;

  value = ((right15 & 0x2000) | (state & 0x1000000)) >> 1;
  value |= state & 0x20000;
  value = (value >> 2) | (state & 0x1000);
  value = (value >> 3) | ((right7 ^ state) & 0x80000);
  value = (value >> 1) | ((right15 ^ state) & 0x4000);
  value = (value >> 2) | (state & 0x2000);
  value = (value >> 1) | (((state >> 14) ^ state) & 0x200);
  value = (value >> 1) | (xor1 & 0x40);
  value |= state & 0x20;
  value = (value >> 1) | (((state >> 16) ^ (state << 3)) & 0x4000);
  value |= ((state >> 9) ^ (state << 8)) & 0x800;
  value |= ((state >> 20) ^ (state << 1)) & 0x4;
  value |= ((state << 6) ^ right7) & 0x100;
  value |= (state & 0x100) << 7;
  value |= state & 1;

  *state_io = ((((xor1 >> 30) ^ ((state >> 10) & 0xFF) ^ (state & 0xFF)) << 31) |
               right1);

  return (guint16) (((value >> 8) & 0xFF) | ((value & 0xFF) << 8));
}

guint8 *
goodix_5301_unwrap_image (const guint8 *payload,
                          gsize         payload_len,
                          gsize        *out_len)
{
  const guint8 *data;
  const guint8 *trailer;
  guint32 stored, computed, state = 0x12345678;
  guint8 *out;

  if (payload_len != GOODIX_5301_IMAGE_PAYLOAD)
    {
      fp_warn ("5301 image payload has %zu bytes, expected %d",
               payload_len, GOODIX_5301_IMAGE_PAYLOAD);
      return NULL;
    }

  data = payload + GOODIX_5301_IMAGE_HEADER;
  trailer = payload + payload_len - GOODIX_5301_IMAGE_TRAILER;
  stored = ((guint32) trailer[2] << 24) | ((guint32) trailer[3] << 16) |
           ((guint32) trailer[0] << 8) | trailer[1];
  computed = crc32_mpeg2 (data, GOODIX_SENSOR_RAW12_BYTES);
  if (computed != stored)
    {
      fp_warn ("5301 image CRC mismatch");
      return NULL;
    }

  out = g_memdup2 (data, GOODIX_SENSOR_RAW12_BYTES);
  for (gsize i = 0; i + 1 < GOODIX_SENSOR_RAW12_BYTES; i += 2)
    {
      guint16 word = windows_next_word (&state);

      out[i] ^= word & 0xFF;
      out[i + 1] ^= word >> 8;
    }

  *out_len = GOODIX_SENSOR_RAW12_BYTES;
  return out;
}
