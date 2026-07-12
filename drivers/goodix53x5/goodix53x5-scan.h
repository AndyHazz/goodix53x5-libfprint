/*
 * Goodix 53x5 driver for libfprint — Scan flow (FDT finger detection and capture)
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

/* Capture the TX-off no-finger reference frame into reference_image.
 * Must run before a live capture. */
void goodix_scan_start_ref_capture_subsm (FpiSsm   *parent_ssm,
                                          FpDevice *dev);

/* Power the sensor and block (cancellably) until a validated finger-down
 * FDT event arrives. Filters false FDT-down interrupts. */
void goodix_scan_start_finger_wait_subsm (FpiSsm   *parent_ssm,
                                          FpDevice *dev);

/* Capture a live finger frame, decrypt and preprocess it into
 * captured_image, consuming the reference frame. */
void goodix_scan_start_capture_subsm (FpiSsm   *parent_ssm,
                                      FpDevice *dev);

/* Block (cancellably) until finger lift-off, regenerate the finger-down
 * base, then sleep the MCU and power the EC off. */
void goodix_scan_start_finger_up_subsm (FpiSsm   *parent_ssm,
                                        FpDevice *dev);

/* Bounded sensor shutdown (sleep + EC power off) without waiting for
 * lift-off — used after successful verify/identify. */
void goodix_scan_start_deactivate_subsm (FpiSsm   *parent_ssm,
                                         FpDevice *dev);
