/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "drivers_api.h"
#include "drivers/goodix53x5/driver-private.h"

typedef struct {
  FpiUsbTransfer *pending;
  FpiUsbTransferCallback callback;
  gpointer user_data;
  GCancellable *cancel;
  guint timeout;
  GCancellable *physical_cancel;
} TestUsb;

extern TestUsb usb;
extern gint64 test_clock_us;
extern GCancellable *action_cancel_token;

void mock_submit (FpiUsbTransfer *, guint, GCancellable *, FpiUsbTransferCallback, gpointer);
void check_submit (FpiUsbTransfer *transfer, guint timeout, GCancellable *cancel);
gint64 test_monotonic_time (void);
GCancellable *test_action_cancellable (FpDevice *dev);
FpDevice *fixture_device_new (void);
void fixture_complete (GError *error);
void fixture_refresh_wait (void);
void fixture_select_read (void);
void fixture_join_reader (FpDevice *dev);
void test_transport_wait_info (FpDevice *dev, guint *timeout, GCancellable **cancel);
void test_transport_wait_failed (FpDevice *dev, GError *error);
gsize fixture_fragment (const guint8 *packet, gsize size, gsize offset);
void reply (FpiUsbTransfer *, guint8, guint8, const guint8 *, gsize);
void ack_reply (FpiUsbTransfer *, guint8);
void add_transport_case (const char *name, gconstpointer data, GTestDataFunc test);
