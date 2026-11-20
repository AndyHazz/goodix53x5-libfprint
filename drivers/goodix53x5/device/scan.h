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

#include "driver-private.h"

/* Takes an ordinary exhausted command error only when its native continuation
 * ignores that result. Terminal hardware/host errors never enter this path. */
gboolean goodix_scan_continue_command_error (FpiSsm   *ssm,
                                             FpDevice *dev,
                                             GError   *error);

typedef enum
{
  /* Authentication matched; stop without waiting for a later lift event. */
  GOODIX_SCAN_DISPOSITION_AUTH_SUCCESS = 0,
  /* Authentication did not match or needs retry; settle the lift first. */
  GOODIX_SCAN_DISPOSITION_AUTH_RETRY_AFTER_UP,
  /* Enrollment accepted/rejected one probe and needs another lift-delimited cycle. */
  GOODIX_SCAN_DISPOSITION_ENROLL_CONTINUE_AFTER_UP,
  /* Enrollment accepted its final probe; settle the lift, then stop. */
  GOODIX_SCAN_DISPOSITION_ENROLL_FINAL_AFTER_UP,
  /* Stop after bounded cleanup and fail with the supplied error. */
  GOODIX_SCAN_DISPOSITION_FATAL,
  /* Stop after bounded cleanup with cancellation. */
  GOODIX_SCAN_DISPOSITION_CANCELLED,
} GoodixScanDisposition;

typedef void (*GoodixScanCaptureReadyCallback) (FpDevice *dev,
                                                 gpointer  user_data);
typedef void (*GoodixScanCycleSettledCallback) (
  FpDevice             *dev,
  GoodixScanDisposition disposition,
  gpointer              user_data);

/* Start the action-scoped profile-9 event coordinator as @parent_ssm's child.
 * It owns command/event I/O until completion. @capture_ready is invoked only
 * after capture, up-arm, and submission of the event receive. The action's CPU
 * callback must return one disposition with goodix_scan_set_disposition().
 * Enrollment may return ENROLL_CONTINUE repeatedly; @cycle_settled runs after
 * lift/reverse handling and down rearm, before the next capture cycle. */
void goodix_scan_start_coordinator_subsm (
  FpiSsm                       *parent_ssm,
  FpDevice                     *dev,
  GoodixScanCaptureReadyCallback capture_ready,
  GoodixScanCycleSettledCallback cycle_settled,
  gpointer                      user_data);

/* Transfer @error to the active coordinator. @error is required only for
 * GOODIX_SCAN_DISPOSITION_FATAL and ignored (and freed) otherwise. */
void goodix_scan_set_disposition (FpDevice             *dev,
                                  GoodixScanDisposition disposition,
                                  GError               *error);

/* Request external cancellation/failure and cancel any outstanding CPU task.
 * Internal successful stops are requested by returning a disposition instead. */
void goodix_scan_stop_coordinator (FpDevice *dev,
                                   GError   *error);

/* Request-independent mode of the same coordinator. Start only after the
 * preceding logical wait has joined. Stop completes selected work before the
 * session handoff; it neither captures a live frame nor adds an initial arm. */
void goodix_scan_start_service (FpDevice *dev);
void goodix_scan_join_service (FpDevice *dev);
