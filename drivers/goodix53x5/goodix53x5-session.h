/*
 * Goodix 53x5 driver for libfprint — Device session (open, GTLS, reinit)
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

/**
 * Start the full open/initialization SSM as the top-level task SSM and
 * complete the libfprint open action when it finishes.
 */
void goodix_start_open_ssm (FpDevice *dev);

/**
 * If the device needs reinitialization (system sleep happened while it was
 * open), release any stale interface claim and run the full open-time
 * initialization SSM as a sub-SSM of @ssm.
 *
 * Returns TRUE if a reinit sub-SSM was started (caller returns and the
 * parent advances when it completes), FALSE if no reinit was needed.
 */
gboolean goodix_maybe_start_reinit_subsm (FpiSsm   *ssm,
                                          FpDevice *dev);

/**
 * TRUE for errors that indicate the USB device/claim is likely stale or
 * gone. Setting needs_reinit on these makes the next action attempt
 * self-heal with a full reinitialization.
 */
gboolean goodix_error_indicates_stale_device (const GError *error);

/**
 * Handle system sleep/wake while the device is open. Mark the device for
 * reinitialization, and for verify/identify either cancel a pending blocking
 * read (suspend) or restart the suspended SSM from its re-arm state (resume).
 * Implement FpDeviceClass::suspend and ::resume.
 */
void goodix_session_suspend (FpDevice *dev);
void goodix_session_resume (FpDevice *dev);
