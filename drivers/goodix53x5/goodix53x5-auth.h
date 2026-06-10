/*
 * Goodix 53x5 driver for libfprint — Verify/identify flow
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

/* Reset verify/identify action state and run the full auth flow; the shared
 * SSM dispatches on the current libfprint action. Implements both
 * FpDeviceClass::verify and FpDeviceClass::identify. */
void goodix_auth_start (FpDevice *dev);

/* Drop any match result queued while waiting for finger-up. Used by auth
 * setup and by close to discard stale results. */
void goodix_clear_pending_result_report (FpiDeviceGoodix53x5 *self);
