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

#include "driver-private.h"

/**
 * Start the full open/initialization SSM as the top-level task SSM and
 * complete the libfprint open action when it finishes.
 */
void goodix_start_open_ssm (FpDevice *dev);

typedef void (*GoodixGtlsRestartDone) (FpDevice *dev,
                                       GError   *error,
                                       gpointer  data);

/* Run the native three-attempt restart with the retained selected PSK.
 * The caller joins the asynchronous completion before resuming scan work. */
void goodix_start_gtls_restart (FpDevice             *dev,
                                GoodixGtlsRestartDone done,
                                gpointer              data);

/**
 * If the hardware session is invalid, release any stale interface claim and
 * run the full open-time initialization SSM as a sub-SSM of @ssm.
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
 * Handle system sleep/wake while the device is open, including ACTION_NONE.
 * Suspend cancels/joins the selected hardware owner and CPU consumer, sends
 * sleep/EC-off, then joins reception while retaining calibration/reference/FDT
 * state. Resume reclaims USB and re-keys GTLS, with one cold reconstruction on
 * failure, then restarts packet-driven servicing before completing.
 */
void goodix_session_suspend (FpDevice *dev);
void goodix_session_resume (FpDevice *dev);

/* Join every hardware owner, release the interface and complete the close. */
void goodix_session_close (FpDevice *dev);

/* Background and power owners use session_cancel even during foreground
 * admission. Only foreground/open callers use libfprint's action token. */
GCancellable *goodix_session_io_cancellable (FpDevice *dev);

/* Every hardware owner reports here when it stops; the session then starts
 * the pending action, the requested reader join, or idle maintenance. */
void goodix_session_settle (FpDevice *dev);
/* The idle service or a detached deactivation tail finished. A terminal error
 * disables maintenance until the next action reconstructs the session. */
void goodix_session_service_done (FpDevice *dev, GError *error);
/* The coordinator hands a finished action back and keeps running its
 * deactivation tail as background maintenance. */
void goodix_session_detach_action (FpDevice *dev);
void goodix_session_quiesce (FpDevice *dev,
                            void (*joined) (FpDevice *, gpointer),
                            gpointer data);
void goodix_session_start_action (FpDevice *dev);
/* Complete an unadmitted request without taking ownership of maintenance I/O. */
gboolean goodix_session_cancel_pending_action (FpDevice *dev);
/* Deliver the action's outcome, then settle the next hardware owner. */
void goodix_session_action_done (FpDevice *dev, GError *error,
                                void (*complete) (FpDevice *, GError *));
