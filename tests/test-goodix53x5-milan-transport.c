/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Keep the private production boundaries in one translation unit. The USB/time
 * fixture is separately compiled; these files own the existing case families. */
#include "test-goodix53x5-milan-transport-owners.h"
#include "test-goodix53x5-milan-transport-cases.h"

void
test_transport_wait_info (FpDevice *dev, guint *timeout, GCancellable **cancel)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport *operation = self->transport;

  *timeout = operation && operation->deadline_us ?
             goodix_deadline_remaining (operation->deadline_us) : 0;
  *cancel = operation ? operation->cancellable : self->reader->cancel;
}

void
test_transport_wait_failed (FpDevice *dev, GError *error)
{
  GoodixTransport *operation = FPI_DEVICE_GOODIX53X5 (dev)->transport;

  g_assert_nonnull (operation);
  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
    {
      g_assert_nonnull (operation->timer);
      g_clear_pointer (&operation->timer, g_source_destroy);
      goodix_transport_expired (dev, operation);
      g_error_free (error);
    }
  else
    {
      goodix_transport_complete (operation, error);
    }
}

static void
fixture_reader_joined (FpDevice *dev, gpointer data)
{
  g_assert_null (FPI_DEVICE_GOODIX53X5 (dev)->reader);
}

void
fixture_join_reader (FpDevice *dev)
{
  GoodixReader *reader = FPI_DEVICE_GOODIX53X5 (dev)->reader;
  gboolean pending = reader && reader->pending;

  goodix_transport_quiesce (dev, fixture_reader_joined, NULL);
  if (pending)
    fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Joined reader"));
}

#include "test-goodix53x5-milan-transport-commands.c"
#include "test-goodix53x5-milan-transport-capture.c"
#include "test-goodix53x5-milan-transport-lifecycle.c"

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  register_command_tests ();
  register_capture_tests ();
  register_lifecycle_tests ();
  return g_test_run ();
}
