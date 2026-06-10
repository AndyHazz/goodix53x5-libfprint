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

#pragma once

#include "goodix53x5-private.h"

guint8   goodix_device_compute_otp_hash (const guint8 *data,
                                         gsize         len);

gboolean goodix_device_verify_otp (const guint8 *otp,
                                   gsize         otp_len);

void     goodix_device_parse_otp (const guint8      *otp,
                                  gsize              otp_len,
                                  GoodixCalibParams *params);

void     goodix_device_patch_config (guint8              *config,
                                     gsize                config_len,
                                     const GoodixCalibParams *params);

void     goodix_device_fix_config_checksum (guint8 *config,
                                            gsize   config_len);

gboolean goodix_device_is_fdt_base_valid (const guint8 *data1,
                                          const guint8 *data2,
                                          gsize         len,
                                          guint16       max_delta);

void     goodix_device_generate_fdt_base (const guint8 *fdt_data,
                                          gsize         len,
                                          guint8       *fdt_base);

void     goodix_device_generate_fdt_up_base (const guint8        *fdt_data,
                                             guint16              touch_flag,
                                             const GoodixCalibParams *params,
                                             guint8              *fdt_base_up);

const guint8 *goodix_device_get_default_config (gsize *out_len);
