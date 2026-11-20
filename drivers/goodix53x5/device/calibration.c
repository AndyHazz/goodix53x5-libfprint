/*
 * Goodix 53x5 driver for libfprint — OTP, config, and FDT base math
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
#include "driver-private.h"
#include "device/calibration.h"

#include <stdlib.h>
#include <string.h>

/* usbinterface.dll 007c84/0115a4: the first pass includes the border; only the
 * second pass selects interior pixels. Keep signed differences/group means
 * separate from the unsigned selected sum and mean. */
static gboolean
goodix_dynamic_dac_mean (const guint16 *live,
                         const guint16 *reference,
                         guint16        reg,
                         guint32       *mean)
{
  guint32 high_sum = 0, low_sum = 0;
  gint32 high_count = 0, low_count = 0;
  guint32 selected_sum = 0, selected_count = 0, nonzero = 0;
  const guint32 interior = (GOODIX_SENSOR_HEIGHT - 2) * (GOODIX_SENSOR_WIDTH - 2);
  /* Native writes only the low word of a later dword mask input. Use zero for
   * its unwritten upper word, retaining the defined register bias in both the
   * positive counter and the no-high-group threshold. */
  guint32 positive = reg;
  gint32 threshold = reg;

  for (guint i = 0; i < GOODIX_SENSOR_PIXELS; i++)
    {
      gint32 sample = (gint16) live[i];
      gint32 base = (gint16) reference[i];
      gint32 difference = base - sample;

      if (difference > 3800)
        {
          high_sum += (guint32) difference;
          high_count++;
        }
      else
        {
          low_sum += (guint32) difference;
          low_count++;
        }
      positive += sample > base;
    }

  if (high_count)
    {
      gint32 high_mean = (gint32) high_sum / high_count;
      gint32 low_mean = low_count ? (gint32) low_sum / low_count : 0;

      threshold = 3800 - (high_mean - low_mean) / 4;
    }

  for (guint row = 1; row < GOODIX_SENSOR_HEIGHT - 1; row++)
    for (guint column = 1; column < GOODIX_SENSOR_WIDTH - 1; column++)
      {
        guint i = row * GOODIX_SENSOR_WIDTH + column;
        gint32 sample = (gint16) live[i];
        gint32 base = (gint16) reference[i];

        nonzero += sample != 0;
        if (sample <= 3800 ||
            (base - sample >= threshold && threshold != 0 &&
             ((gint32) (positive * 10u) <= GOODIX_SENSOR_PIXELS || sample <= base)))
          {
            selected_sum += (guint32) sample;
            selected_count++;
          }
      }

  /* Native rounds the divisions to binary32 before the binary64 comparisons. */
  if ((double) ((float) nonzero / (float) interior) > 0.95 &&
      (double) ((float) selected_count / (float) interior) <= 0.4)
    return FALSE;

  *mean = selected_count ? selected_sum / selected_count : 0;
  return TRUE;
}

static guint16
goodix_dynamic_dac_step (guint16  reg,
                         guint16  default_dac,
                         guint16  tcode,
                         guint32  mean,
                         gboolean correction)
{
  gboolean upward = mean > 2000;
  guint32 delta = upward ? mean - 2000u : 2000u - mean;
  guint16 temperature = (guint16) ((tcode ? tcode : 128) << 4);
  double scaled = ((double) (guint64) delta * 0.25) / ((double) temperature * 0.283);
  /* CVTTSD2SI returns INT_MIN for an invalid conversion; its low word is zero.
   * The verified OTP domain always supplies a nonzero denominator. */
  guint16 step = scaled >= 0.0 && scaled < 2147483648.0 ? (guint16) (gint32) scaled : 0;
  guint32 field = reg & 0x1ff0;
  guint16 candidate;

  if (step == 0)
    step = 1;

  if (upward)
    {
      guint32 ceiling = 16u * ((guint32) default_dac + 30u);

      candidate = field + 16u * step > ceiling ? ceiling : reg + 16u * step;
    }
  else
    {
      /* Middle correction compares D-5+step, but still caps at D-4. This
       * asymmetry can alternate around the floor; it is not a common clamp. */
      gint32 floor_test = (gint32) (16u * ((guint32) default_dac -
                                           (correction ? 5u : 4u) + step));

      candidate = (gint32) field < floor_test ?
                  16u * default_dac - 64u : reg - 16u * step;
    }

  return reg ^ ((candidate ^ reg) & 0x1ff0);
}

void
goodix_device_adjust_dac (GoodixDynamicDacState *state,
                          GoodixCalibParams     *params,
                          const guint16         *live,
                          const guint16         *reference)
{
  guint16 reg = (guint16) (params->dac_h << 4) | 8;
  guint32 mean;
  gboolean correction = FALSE;

  if (!goodix_dynamic_dac_mean (live, reference, reg, &mean))
    goto out;

  if (mean > 3200 || mean < 1500)
    {
      guint16 *streak = mean > 3200 ? &state->high : &state->low;
      guint16 *opposite = mean > 3200 ? &state->low : &state->high;
      guint16 was_active = state->active;

      if (*opposite < 3)
        *opposite = 0;
      else
        was_active = state->active = 0;
      if (*streak < 3)
        (*streak)++;
      if (*streak < 3)
        goto out;
      *opposite = 0;
      if (was_active == 0)
        {
          state->active = 1;
          state->adjustments = 0;
        }
    }
  else if (state->active == 1)
    {
      if (mean >= 1900 && mean <= 2100)
        {
          state->active = state->high = state->low = 0;
          goto out;
        }
      correction = TRUE;
    }
  else
    {
      if (state->high < 3)
        state->high = 0;
      if (state->low < 3)
        state->low = 0;
      goto out;
    }

  reg = goodix_dynamic_dac_step (reg, state->default_dac, params->tcode,
                                 mean, correction);
  state->adjustments = (guint16) (state->adjustments + 1);
out:
  /* Retain the native word here; algorithm consumers project its low byte. */
  params->dac_h = reg >> 4;
}

/* OTP hash lookup table (from driver_53x5.py) */
static const guint8 otp_hash_table[256] = {
  0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15,
  0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d,
  0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65,
  0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d,
  0xe0, 0xe7, 0xee, 0xe9, 0xfc, 0xfb, 0xf2, 0xf5,
  0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd,
  0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85,
  0xa8, 0xaf, 0xa6, 0xa1, 0xb4, 0xb3, 0xba, 0xbd,
  0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2,
  0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea,
  0xb7, 0xb0, 0xb9, 0xbe, 0xab, 0xac, 0xa5, 0xa2,
  0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a,
  0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32,
  0x1f, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0d, 0x0a,
  0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42,
  0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a,
  0x89, 0x8e, 0x87, 0x80, 0x95, 0x92, 0x9b, 0x9c,
  0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4,
  0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec,
  0xc1, 0xc6, 0xcf, 0xc8, 0xdd, 0xda, 0xd3, 0xd4,
  0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c,
  0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44,
  0x19, 0x1e, 0x17, 0x10, 0x05, 0x02, 0x0b, 0x0c,
  0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34,
  0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b,
  0x76, 0x71, 0x78, 0x7f, 0x6a, 0x6d, 0x64, 0x63,
  0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b,
  0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13,
  0xae, 0xa9, 0xa0, 0xa7, 0xb2, 0xb5, 0xbc, 0xbb,
  0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8d, 0x84, 0x83,
  0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb,
  0xe6, 0xe1, 0xe8, 0xef, 0xfa, 0xfd, 0xf4, 0xf3,
};

/* Default configuration (from driver_53x5.py DEFAULT_CONFIG) */
static const guint8 default_config[] = {
  0x40, 0x11, 0x6c, 0x7d, 0x28, 0xa5, 0x28, 0xcd,
  0x1c, 0xe9, 0x10, 0xf9, 0x00, 0xf9, 0x00, 0xf9,
  0x00, 0x04, 0x02, 0x00, 0x00, 0x08, 0x00, 0x11,
  0x11, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x07,
  0x00, 0x84, 0x00, 0xbe, 0xb2, 0x86, 0x00, 0xc5,
  0xb9, 0x88, 0x00, 0xb5, 0xad, 0x8a, 0x00, 0x9d,
  0x95, 0x8c, 0x00, 0x00, 0xbe, 0x8e, 0x00, 0x00,
  0xc5, 0x90, 0x00, 0x00, 0xb5, 0x92, 0x00, 0x00,
  0x9d, 0x94, 0x00, 0x00, 0xaf, 0x96, 0x00, 0x00,
  0xbf, 0x98, 0x00, 0x00, 0xb6, 0x9a, 0x00, 0x00,
  0xa7, 0x30, 0x00, 0x6c, 0x1c, 0x50, 0x00, 0x01,
  0x05, 0xd0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00,
  0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34,
  0x12, 0x26, 0x00, 0x00, 0x12, 0x20, 0x00, 0x10,
  0x40, 0x12, 0x00, 0x03, 0x04, 0x02, 0x02, 0x16,
  0x21, 0x2c, 0x02, 0x0a, 0x03, 0x2a, 0x01, 0x02,
  0x00, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x32,
  0x00, 0x80, 0x00, 0x05, 0x04, 0x5c, 0x00, 0x00,
  0x01, 0x56, 0x00, 0x28, 0x20, 0x58, 0x00, 0x01,
  0x00, 0x32, 0x00, 0x24, 0x02, 0x82, 0x00, 0x80,
  0x0c, 0x20, 0x02, 0x88, 0x0d, 0x2a, 0x01, 0x92,
  0x07, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
  0x00, 0x80, 0x00, 0x05, 0x04, 0x5c, 0x00, 0x00,
  0x01, 0x56, 0x00, 0x08, 0x20, 0x58, 0x00, 0x03,
  0x00, 0x32, 0x00, 0x08, 0x04, 0x82, 0x00, 0x80,
  0x0c, 0x20, 0x02, 0x88, 0x0d, 0x2a, 0x01, 0x18,
  0x04, 0x5c, 0x00, 0x80, 0x00, 0x54, 0x00, 0x00,
  0x01, 0x62, 0x00, 0x09, 0x03, 0x64, 0x00, 0x18,
  0x00, 0x82, 0x00, 0x80, 0x0c, 0x20, 0x02, 0x88,
  0x0d, 0x2a, 0x01, 0x18, 0x04, 0x5c, 0x00, 0x80,
  0x00, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x4f,
};

/* Config tag constants */
#define TCODE_TAG      0x5C
#define DAC_L_TAG      0x220
#define DELTA_DOWN_TAG 0x82

/**
 * goodix_device_get_default_config:
 *
 * Return a pointer to the default config and its length.
 */
const guint8 *
goodix_device_get_default_config (gsize *out_len)
{
  *out_len = sizeof (default_config);
  return default_config;
}

/**
 * goodix_device_compute_otp_hash:
 *
 * Compute OTP hash over data using the lookup table.
 */
guint8
goodix_device_compute_otp_hash (const guint8 *hash_input,
                                gsize         hash_input_len)
{
  guint8 checksum = 0;

  for (gsize i = 0; i < hash_input_len; i++)
    checksum = otp_hash_table[checksum ^ hash_input[i]];

  return ~checksum & 0xFF;
}

/**
 * goodix_device_verify_otp:
 *
 * Verify OTP hash. The hash byte is at offset 25.
 * Data for hashing = otp[0:25] + otp[26:].
 */
gboolean
goodix_device_verify_otp (const guint8 *otp,
                          gsize         otp_len)
{
  guint8 received_hash, computed_hash;
  g_autofree guint8 *hash_input = NULL;
  gsize hash_input_len;

  if (otp_len < 27)
    return FALSE;

  received_hash = otp[25];

  /* Build data = otp[:25] + otp[26:] */
  hash_input_len = otp_len - 1;
  hash_input = g_malloc (hash_input_len);
  memcpy (hash_input, otp, 25);
  memcpy (hash_input + 25, otp + 26, otp_len - 26);

  computed_hash = goodix_device_compute_otp_hash (hash_input, hash_input_len);

  if (received_hash != computed_hash)
    {
      fp_warn ("OTP hash mismatch: received 0x%02x, computed 0x%02x",
               received_hash, computed_hash);
      return FALSE;
    }

  fp_dbg ("OTP hash verified");
  return TRUE;
}

/**
 * goodix_device_parse_otp:
 *
 * Parse OTP data and extract calibration parameters.
 * Ported from driver_53x5.py check_sensor().
 */
void
goodix_device_parse_otp (const guint8      *otp,
                         gsize              otp_len,
                         GoodixCalibParams *params)
{
  guint8 diff;
  guint16 rounded_difference, scaled_difference;

  memset (params, 0, sizeof (GoodixCalibParams));

  params->tcode = (otp[23] != 0) ? otp[23] + 1 : 0;

  diff = (otp[17] >> 1) & 0x1F;
  fp_dbg ("OTP diff[5:1] = 0x%02x", diff);

  if (diff == 0)
    {
      params->delta_fdt = 0;
      params->delta_down = 0xD;
      params->delta_up = 0xB;
      params->delta_img = 0xC8;
      params->delta_nav = 0x28;
    }
  else
    {
      rounded_difference = diff + 5;
      scaled_difference = (rounded_difference * 0x32) >> 4;

      params->delta_fdt = scaled_difference / 5;
      params->delta_down = scaled_difference / 3;
      params->delta_up = params->delta_down - 2;
      params->delta_img = 0xC8;
      params->delta_nav = rounded_difference * 4;
    }

  if (otp[17] == 0 || otp[22] == 0 || (otp_len > 31 ? otp[31] == 0 : TRUE))
    {
      params->dac_h = 0x97;
      params->dac_l = 0xD0;
    }
  else
    {
      params->dac_h = ((guint16) otp[17] << 8 ^ otp[22]) & 0x1FF;
      params->dac_l = ((otp[17] & 0x40) << 2) ^ otp[31];
      params->dac_from_otp = TRUE;
    }

  if (params->tcode != 0)
    params->dac_delta = 0xC83 / params->tcode;
  else
    params->dac_delta = 0;

  fp_dbg ("tcode=0x%x delta_down=0x%x delta_up=0x%x "
          "delta_img=0x%x delta_nav=0x%x dac_h=0x%x dac_l=0x%x",
          params->tcode, params->delta_down, params->delta_up,
          params->delta_img, params->delta_nav,
          params->dac_h, params->dac_l);
}

/**
 * replace_value_in_section:
 *
 * Replace a tagged value in a config section.
 */
static void
replace_value_in_section (guint8 *config,
                          gsize   config_len,
                          int     section_num,
                          guint16 tag,
                          guint16 value)
{
  const guint8 *section_table = config + 1;
  guint8 section_base = section_table[section_num * 2];
  guint8 section_size = section_table[section_num * 2 + 1];

  for (int entry_base = section_base;
       entry_base < section_base + section_size;
       entry_base += 4)
    {
      guint16 entry_tag = config[entry_base] |
                          ((guint16) config[entry_base + 1] << 8);
      if (entry_tag == tag)
        {
          config[entry_base + 2] = value & 0xFF;
          config[entry_base + 3] = (value >> 8) & 0xFF;
        }
    }
}

/**
 * goodix_device_fix_config_checksum:
 *
 * Recompute and fix the 2-byte checksum at the end of the config.
 */
void
goodix_device_fix_config_checksum (guint8 *config,
                                   gsize   config_len)
{
  guint32 checksum = 0xA5A5;

  for (gsize i = 0; i < config_len - 2; i += 2)
    {
      guint16 config_word = config[i] | ((guint16) config[i + 1] << 8);
      checksum += config_word;
      checksum &= 0xFFFF;
    }

  checksum = 0x10000 - checksum;
  config[config_len - 2] = checksum & 0xFF;
  config[config_len - 1] = (checksum >> 8) & 0xFF;
}

/**
 * goodix_device_patch_config:
 *
 * Apply calibration parameters to the config buffer.
 */
void
goodix_device_patch_config (guint8                  *config,
                            gsize                    config_len,
                            const GoodixCalibParams *params)
{
  if (params->tcode != 0)
    {
      replace_value_in_section (config, config_len, 2, TCODE_TAG, params->tcode);
      replace_value_in_section (config, config_len, 3, TCODE_TAG, params->tcode);
      replace_value_in_section (config, config_len, 4, TCODE_TAG, params->tcode);
    }
  if (params->dac_from_otp)
    {
      replace_value_in_section (config, config_len, 2, DAC_L_TAG,
                                (params->dac_l << 4) | 8);
      replace_value_in_section (config, config_len, 3, DAC_L_TAG,
                                (params->dac_l << 4) | 8);
    }
  replace_value_in_section (config, config_len, 2, DELTA_DOWN_TAG,
                            (params->delta_down << 8) | 0x80);

  goodix_device_fix_config_checksum (config, config_len);
}

/**
 * goodix_device_is_fdt_base_valid:
 *
 * Compare two FDT data arrays and check if the max delta is within bounds.
 * Each pair of bytes is a 16-bit LE value, compared as (val >> 1).
 */
gboolean
goodix_device_is_fdt_base_valid (const guint8 *first_base,
                                 const guint8 *second_base,
                                 gsize         len,
                                 guint16       max_delta)
{
  for (gsize i = 0; i < len; i += 2)
    {
      guint16 first_sample = first_base[i] | ((guint16) first_base[i + 1] << 8);
      guint16 second_sample = second_base[i] | ((guint16) second_base[i + 1] << 8);
      gint delta = abs ((gint) (second_sample >> 1) - (gint) (first_sample >> 1));

      if ((guint16) delta > max_delta)
        {
          fp_dbg ("FDT delta %d exceeds max %d at offset %zu",
                  delta, max_delta, i);
          return FALSE;
        }
    }

  return TRUE;
}

/**
 * goodix_device_generate_fdt_base:
 *
 * Generate FDT base from FDT event data.
 * For each 16-bit LE pair:
 *   fdt_base_val = (val & 0xFFFE) * 0x80 + (val >> 1)
 */
void
goodix_device_generate_fdt_base (const guint8 *fdt_data,
                                 gsize         len,
                                 guint8       *fdt_base)
{
  for (gsize i = 0; i < len; i += 2)
    {
      guint16 fdt_sample = fdt_data[i] | ((guint16) fdt_data[i + 1] << 8);
      guint16 fdt_base_word = (guint16) (((fdt_sample & 0xFFFE) * 0x80) + (fdt_sample >> 1));

      fdt_base[i] = fdt_base_word & 0xFF;
      fdt_base[i + 1] = (fdt_base_word >> 8) & 0xFF;
    }
}

/**
 * goodix_device_generate_fdt_up_base:
 *
 * Generate FDT "up" base from event data and touch flag.
 * Ported from driver_53x5.py generate_fdt_up_base().
 */
void
goodix_device_generate_fdt_up_base (const guint8        *fdt_data,
                                    guint16              touch_flag,
                                    const GoodixCalibParams *params,
                                    guint8              *fdt_base_up)
{
  guint16 fdt_samples[12];
  guint16 fdt_up_base_words[12];

  for (int i = 0; i < 12; i++)
    fdt_samples[i] = fdt_data[i * 2] | ((guint16) fdt_data[i * 2 + 1] << 8);

  for (int i = 0; i < 12; i++)
    {
      guint16 adjusted_sample = (fdt_samples[i] >> 1) + params->delta_down;
      fdt_up_base_words[i] = (guint16) (adjusted_sample * 0x100 | adjusted_sample);
    }

  for (int i = 0; i < 12; i++)
    {
      if (((touch_flag >> i) & 1) == 0)
        fdt_up_base_words[i] = (guint16) (params->delta_up * 0x100 |
                                       params->delta_up);
    }

  for (int i = 0; i < 12; i++)
    {
      fdt_base_up[i * 2] = fdt_up_base_words[i] & 0xFF;
      fdt_base_up[i * 2 + 1] = (fdt_up_base_words[i] >> 8) & 0xFF;
    }
}
