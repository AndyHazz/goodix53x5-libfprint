/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "test-goodix53x5-milan-transport-fixture.h"

TestUsb usb;
static TestUsb queued_read;
gint64 test_clock_us;
GCancellable *action_cancel_token;

gint64
test_monotonic_time (void)
{
  return test_clock_us;
}

GCancellable *
test_action_cancellable (FpDevice *dev)
{
  /* Production idle commands must not borrow libfprint's action-only token. */
  g_assert_false (FPI_DEVICE_GOODIX53X5 (dev)->service_active);
  g_assert_false (FPI_DEVICE_GOODIX53X5 (dev)->session_suspended);
  return action_cancel_token;
}

FpDevice *
fixture_device_new (void)
{
  FpDeviceClass *klass = g_type_class_ref (FPI_TYPE_DEVICE_GOODIX53X5);
  FpDevice *dev;

  g_assert_null (usb.pending);
  g_assert_null (usb.cancel);
  g_assert_null (queued_read.pending);
  g_assert_null (action_cancel_token);
  test_clock_us = G_USEC_PER_SEC;
  action_cancel_token = g_cancellable_new ();
  klass->type = FP_DEVICE_TYPE_VIRTUAL;
  dev = g_object_new (FPI_TYPE_DEVICE_GOODIX53X5, NULL);
  /* Existing command/coordinator fixtures enter with a constructed HAL. */
  goodix_health_reset (&FPI_DEVICE_GOODIX53X5 (dev)->health);
  g_type_class_unref (klass);
  return dev;
}

void
mock_submit (FpiUsbTransfer *transfer, guint timeout, GCancellable *cancel,
             FpiUsbTransferCallback callback, gpointer user_data)
{
  /* One physical IN can coexist with one OUT, never with another IN. OUT
   * callbacks are selected first unless a case explicitly delivers IN. */
  TestUsb submitted = { .pending = transfer, .callback = callback,
                        .user_data = user_data, .timeout = timeout,
                        .physical_cancel = cancel ? g_object_ref (cancel) : NULL };
  if (usb.pending)
    {
      g_assert_null (queued_read.pending);
      if (transfer->endpoint & FPI_USB_ENDPOINT_IN)
        {
          g_assert_false (usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          queued_read = submitted;
        }
      else
        {
          g_assert_true (usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          queued_read = usb;
          usb = submitted;
        }
    }
  else
    usb = submitted;
  check_submit (transfer, timeout, cancel);
  fixture_refresh_wait ();
}

void
fixture_refresh_wait (void)
{
  if (!usb.pending)
    return;
  g_clear_object (&usb.cancel);
  if (usb.pending->endpoint & FPI_USB_ENDPOINT_IN)
    {
      GCancellable *cancel = NULL;
      /* Existing budget assertions observe the logical wait now. Submission
       * assertions independently require an infinite physical IN timeout. */
      test_transport_wait_info (usb.pending->device, &usb.timeout, &cancel);
      usb.cancel = cancel ? g_object_ref (cancel) : NULL;
    }
  else
    usb.cancel = usb.physical_cancel ? g_object_ref (usb.physical_cancel) : NULL;
}

void
fixture_select_read (void)
{
  if (usb.pending->endpoint & FPI_USB_ENDPOINT_IN)
    return;
  TestUsb write = usb;
  g_assert_nonnull (queued_read.pending);
  usb = queued_read;
  queued_read = write;
  fixture_refresh_wait ();
}

void
fixture_complete (GError *error)
{
  if (usb.pending && (usb.pending->endpoint & FPI_USB_ENDPOINT_IN) && error &&
      (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) ||
       (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
        !g_cancellable_is_cancelled (usb.physical_cancel))))
    {
      /* Command expiry/cancel does not complete, truncate or replace IN. */
      test_transport_wait_failed (usb.pending->device, error);
      fixture_refresh_wait ();
      return;
    }
  FpiUsbTransfer *transfer = g_steal_pointer (&usb.pending);
  FpiUsbTransferCallback callback = usb.callback;
  gpointer data = usb.user_data;
  g_autoptr(GCancellable) cancel = g_steal_pointer (&usb.cancel);
  g_autoptr(GCancellable) physical = g_steal_pointer (&usb.physical_cancel);

  g_assert_nonnull (transfer);
  usb.callback = NULL;
  usb.user_data = NULL;
  if (queued_read.pending)
    {
      usb = queued_read;
      memset (&queued_read, 0, sizeof (queued_read));
    }
  if (!error && !(transfer->endpoint & FPI_USB_ENDPOINT_IN))
    transfer->actual_length = transfer->length;
  callback (transfer, transfer->device, data, error);
  fpi_usb_transfer_unref (transfer);
  fixture_refresh_wait ();
}

void
reply (FpiUsbTransfer *transfer, guint8 category, guint8 command,
       const guint8 *payload, gsize length)
{
  gsize size;
  g_autofree guint8 *bytes = goodix_proto_build_message (
    category, command, payload, length, TRUE, &size);
  g_assert_cmpuint (size, <=, transfer->length);
  memset (transfer->buffer, 0, transfer->length);
  memcpy (transfer->buffer, bytes, size);
  transfer->actual_length = 64; /* One padded protocol cell, not the read capacity. */
}


gsize
fixture_fragment (const guint8 *packet, gsize size, gsize offset)
{
  gsize header = offset ? 1 : 0;
  gsize count = MIN (size - offset, 64 - header);

  g_assert_nonnull (usb.pending);
  if (header)
    usb.pending->buffer[0] = packet[0] | 1;
  memcpy (usb.pending->buffer + header, packet + offset, count);
  usb.pending->actual_length = count + header;
  return offset + count;
}

void
ack_reply (FpiUsbTransfer *transfer, guint8 command)
{
  guint8 ack[] = { command, 1 };
  reply (transfer, 0x0b, 0, ack, sizeof (ack));
}

void
add_transport_case (const char *name, gconstpointer data, GTestDataFunc test)
{
  g_autofree char *path = g_strconcat ("/goodix53x5/milan/transport/", name, NULL);
  g_test_add_data_func (path, data, test);
}
