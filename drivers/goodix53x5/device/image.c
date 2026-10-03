/*
 * Goodix 53x5 driver for libfprint — Image decoding and preprocessing
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
#include "device/image.h"

/**
 * goodix_device_decode_image:
 *
 * Decode 12-bit packed image data to 16-bit pixel array.
 * 6 bytes → 4 pixels, matching tool.py decode_image().
 *
 * Returns newly allocated array of GOODIX_SENSOR_PIXELS guint16 values, or
 * NULL if the decrypted payload is too short for a full raw12 frame.
 */
guint16 *
goodix_device_decode_image (const guint8 *data,
                             gsize         data_len)
{
  guint16 *image;
  gsize pixel_idx = 0;

  if (data_len < GOODIX_SENSOR_RAW12_BYTES)
    {
      fp_warn ("Truncated raw12 image payload: %zu < %d",
               data_len, GOODIX_SENSOR_RAW12_BYTES);
      return NULL;
    }

  image = g_new0 (guint16, GOODIX_SENSOR_PIXELS);

  for (gsize i = 0; i + 5 < data_len && pixel_idx + 3 < GOODIX_SENSOR_PIXELS; i += 6)
    {
      /* 6 bytes → 4 pixels of 12 bits each.
       * Byte order matches tool.py decode_image() — NOT standard LE packed. */
      image[pixel_idx++] = ((data[i + 0] & 0x0F) << 8) | data[i + 1];
      image[pixel_idx++] = ((guint16) data[i + 3] << 4) | (data[i + 0] >> 4);
      image[pixel_idx++] = ((data[i + 5] & 0x0F) << 8) | data[i + 2];
      image[pixel_idx++] = ((guint16) data[i + 4] << 4) | (data[i + 5] >> 4);
    }

  return image;
}
