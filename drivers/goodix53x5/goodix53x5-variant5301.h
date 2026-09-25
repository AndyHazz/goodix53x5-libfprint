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

#pragma once

#include "goodix53x5-private.h"

/*
 * The 27c6:5301 (chip 0x2202, firmware GF5288/GF3208_HT_APP_10035) shares the
 * 53x5 transport, commands, raw12 frame layout, config format and FDT flow.
 * It differs in four places, all derived from static analysis of its own
 * Windows driver (milanFusb.dll) and confirmed on the sensor:
 *
 *   - no PSK/GTLS pairing; frames arrive in the clear with a CRC-32 trailer
 *     and a fixed XOR stream applied by the firmware
 *   - a different 32-byte OTP checksum layout and calibration formulas
 *   - its own 256-byte host configuration template (chip 0x2202 variant)
 *   - the reset command is answered with a 3-byte reply
 *
 * Selected through FpIdEntry.driver_data.
 */
#define GOODIX_VARIANT_53X5 0
#define GOODIX_VARIANT_5301 1

/* 5-byte header, raw12 frame, 4-byte CRC */
#define GOODIX_5301_IMAGE_HEADER 5
#define GOODIX_5301_IMAGE_TRAILER 4
#define GOODIX_5301_IMAGE_PAYLOAD (GOODIX_5301_IMAGE_HEADER + \
                                   GOODIX_SENSOR_RAW12_BYTES + \
                                   GOODIX_5301_IMAGE_TRAILER)

gboolean goodix_is_5301 (FpDevice *dev);

gboolean goodix_5301_verify_otp (const guint8 *otp,
                                 gsize         otp_len);

void     goodix_5301_parse_otp (const guint8      *otp,
                                gsize              otp_len,
                                GoodixCalibParams *params);

const guint8 *goodix_5301_get_default_config (gsize *out_len);

void     goodix_5301_patch_config (guint8                  *config,
                                   gsize                    config_len,
                                   const GoodixCalibParams *params);

/* Validate the CRC and undo the firmware's XOR stream. Returns a newly
 * allocated GOODIX_SENSOR_RAW12_BYTES buffer, or NULL on a bad frame. */
guint8  *goodix_5301_unwrap_image (const guint8 *payload,
                                   gsize         payload_len,
                                   gsize        *out_len);
