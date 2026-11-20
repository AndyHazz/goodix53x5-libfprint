/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Idle tails, command handoff, startup and joined reset/open/close. */

static guint idle_releases;
static guint idle_closes;
static guint idle_resets;
static gboolean idle_reinit_testing;
static gboolean idle_open_testing;
static gboolean idle_claim_failure;
static guint idle_usb_closes;
static guint idle_open_ssms_freed;
static FpDevice *idle_device;

static gboolean
idle_test_release (void)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (idle_device);
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  if ((idle_reinit_testing || idle_open_testing) && idle_releases == 0)
    {
      g_assert_cmpuint (self->rx.len, ==, 0);
      g_assert_cmpuint (self->rx.expected, ==, 0);
      g_assert_false (self->rx_idle_partial);
    }
  idle_releases++;
  return TRUE;
}

static gboolean
idle_test_claim (GError **error)
{
  if (!idle_claim_failure)
    return TRUE;
  g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE,
                       "Early claim failure");
  return FALSE;
}

static gboolean
idle_test_usb_close (void)
{
  g_assert_true (idle_open_testing);
  g_assert_null (usb.pending);
  g_assert_null (FPI_DEVICE_GOODIX53X5 (idle_device)->transport);
  g_assert_cmpuint (idle_releases, ==, idle_claim_failure ? 0 : 1);
  if (idle_claim_failure)
    g_assert_null (FPI_DEVICE_GOODIX53X5 (idle_device)->rx.buf);
  idle_usb_closes++;
  return TRUE;
}

static void
idle_test_open_complete (FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_assert_true (idle_open_testing);
  g_assert_true (dev == idle_device);
  fixture_refresh_wait ();
  if (error)
    {
      g_assert_null (usb.pending);
      g_assert_null (self->transport);
      g_assert_false (self->service_active);
    }
  else
    {
      g_assert_nonnull (usb.pending);
      g_assert_cmpuint (usb.pending->endpoint, ==, GOODIX_EP_IN);
      g_assert_cmpuint (usb.timeout, ==, 0);
      g_assert_nonnull (self->transport);
      g_assert_true (self->service_active);
      g_assert_true (self->session_open);
      g_assert_nonnull (self->profile9_fdt.owner);
    }
  g_assert_null (io.error);
  io.error = error;
  io.completions++;
}

static void
idle_test_close_complete (FpDevice *dev, GError *error)
{
  g_assert_true (dev == idle_device);
  g_assert_no_error (error);
  g_assert_cmpuint (idle_releases, ==, 1 + idle_resets);
  idle_closes++;
}

static gboolean
idle_test_reset (void)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (idle_device);

  g_assert_true (idle_reinit_testing || idle_open_testing);
  g_assert_cmpuint (idle_releases, ==, 1);
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  g_assert_false (self->rx_idle_partial);
  g_assert_cmpuint (self->rx.len, ==, 0);
  idle_resets++;
  return TRUE;
}

static FpiSsm *
idle_test_reinit_ssm (FpDevice *dev, FpiSsmHandlerCallback handler,
                      int states, int cleanup, const char *name)
{
  /* The startup fixture retains its claim/probe/reset boundary now that reset
   * belongs to the chip child. Run the real reset and its delay, but no read. */
  if (startup_trace && handler == goodix_chip_ssm_handler)
    return fpi_ssm_new_full (dev, handler, GOODIX_CHIP_READ,
                             GOODIX_CHIP_READ, name);
  if (handler != goodix_open_ssm_handler)
    return fpi_ssm_new_full (dev, handler, states, cleanup, name);
  g_assert_true (idle_reinit_testing || idle_open_testing);
  g_assert_true (handler == goodix_open_ssm_handler);
  /* Run reset/claim and the whole startup probe, stopping before calibration. */
  return fpi_ssm_new_full (dev, handler, GOODIX_OPEN_RESET,
                           GOODIX_OPEN_RESET, name);
}

static void
idle_test_reinit (FpiSsm *ssm, FpDevice *dev)
{
  g_assert_true (goodix_maybe_start_reinit_subsm (ssm, dev));
}


static void
idle_test_command_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (g_cancellable_is_cancelled (action_cancel_token))
    {
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
      g_assert_true (FPI_DEVICE_GOODIX53X5 (dev)->needs_reinit);
      g_clear_error (&error);
    }
  else
    g_assert_no_error (error);
  io.completions++;
}

static void
idle_test_ec (FpiSsm *ssm, FpDevice *dev)
{
  goodix_cmd_ec_control (ssm, dev, FALSE);
}

static void
idle_test_ping (FpiSsm *ssm, FpDevice *dev)
{
  goodix_cmd_ping (ssm, dev);
}

static void
idle_test_firmware_success (void)
{
  guint8 version[] = "fixture";

  g_assert_cmpuint (io.command, ==, 0xa8);
  fixture_complete (NULL);
  ack_reply (usb.pending, 0xa8);
  fixture_complete (NULL);
  reply (usb.pending, 0x0a, 4, version, sizeof (version));
  fixture_complete (NULL);
}

static void
test_idle_lifetime (gconstpointer user_data)
{
  guint which = GPOINTER_TO_UINT (user_data);
  static const Scenario scenario = { .schedule = EVENT_CANCELLED };
  FpDevice *dev;
  FpDevice *weak;
  FpiDeviceGoodix53x5 *self;
  guint8 ec_data[] = { 1, 0 };
  guint8 partial_payload[96] = { 0 };
  gsize partial_length;
  g_autofree guint8 *partial = goodix_proto_build_message (
    which == 13 ? 0x0a : 9, which == 13 ? 4 : 0,
    partial_payload, sizeof (partial_payload), TRUE, &partial_length);
  guint8 fragment[64];
  gboolean handoff = which == 2 || which == 3 || which == 4 || which == 6 || which >= 11;

  memset (&io, 0, sizeof (io));
  io.scenario = &scenario;
  idle_releases = idle_closes = 0;
  idle_resets = 0;
  idle_reinit_testing = which == 11;
  dev = fixture_device_new ();
  idle_device = dev;
  weak = dev;
  g_object_add_weak_pointer (G_OBJECT (dev), (gpointer *) &weak);
  self = FPI_DEVICE_GOODIX53X5 (dev);
  self->cancel = g_cancellable_new ();
  fpi_ssm_start (fpi_ssm_new (dev, idle_test_ec, 1), idle_test_command_done);
  fixture_complete (NULL); /* EC write */
  ack_reply (usb.pending, 0xae);
  fixture_complete (NULL);

  /* EC and its parent SSM are already gone, without any optional reply. */
  g_assert_cmpuint (io.completions, ==, 1);
  g_assert_cmpuint (usb.timeout, ==, 0);
  g_assert_true (usb.cancel != action_cancel_token && usb.cancel != self->cancel);

  if (which == 1)
    {
      reply (usb.pending, 0xa, 7, ec_data, sizeof (ec_data));
      fixture_complete (NULL);
      g_assert_nonnull (usb.pending);
      g_assert_cmpuint (self->rx.len, ==, 0);
      g_assert_cmpuint (self->command_response_ready, ==, 0);
    }
  if (which == 12)
    {
      guint8 firmware[] = "idle-version";
      reply (usb.pending, 0x0a, 4, firmware, sizeof (firmware));
      fixture_complete (NULL);
      g_assert_cmpuint (self->command_response_ready, ==, 4);
    }
  if (which == 4 || which == 11 || which == 13)
    {
      g_assert_cmpuint (partial_length, ==, 100);
      fixture_fragment (partial, partial_length, 0);
      fixture_complete (NULL);
      g_assert_cmpuint (self->rx.len, ==, sizeof (fragment));
      g_assert_cmpuint (usb.timeout, ==, 0);
    }
  if (which == 9)
    {
      reverse_event (usb.pending, 0);
      fixture_complete (NULL);
      reverse_event (usb.pending, 1);
      fixture_complete (NULL);
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        {
          g_assert_cmpuint (self->fdt_prior_down[i], ==, 50 + i);
          g_assert_cmpuint (self->profile9_fdt.base_manual[2 * i], ==, 50 + i);
          g_assert_cmpuint (self->profile9_fdt.base_down[2 * i], ==, 51 + i);
        }
      g_assert_true (self->pending_fdt.event.pending);
      g_assert_cmpint (self->pending_fdt.type, ==, GOODIX_FDT_EVENT_REVERSE);
      g_assert_null (self->profile9_fdt.owner);

      /* The retained notification is work for the session owner. Even a
       * cancelled previous action must not suppress its arm/config repair. */
      self->session_open = TRUE;
      self->profile9_fdt.base_valid = TRUE;
      self->calib.delta_down = G_MAXUINT16;
      g_cancellable_cancel (self->cancel);
      GoodixReader *reader = self->reader;
      goodix_session_settle (dev);
      /* The worker snapshots the shared predecessor at selection. */
      GoodixScanCoordinatorData *selected = fpi_ssm_get_data (self->profile9_fdt.owner);
      g_assert_cmpmem (selected->prior_down, sizeof (selected->prior_down),
                       self->fdt_prior_down, sizeof (self->fdt_prior_down));
      g_assert_true (self->reader == reader);
      g_assert_false (g_cancellable_is_cancelled (reader->cancel));
      g_assert_true (self->service_active);
      g_assert_false (self->pending_fdt.event.pending);
      g_assert_cmpuint (io.command, ==, 0x32);
      g_assert_true (usb.cancel == self->session_cancel);
      fixture_complete (NULL);
      guint8 repair_ack[] = { 0x32, 3 };
      reply (usb.pending, 0x0b, 0, repair_ack, sizeof (repair_ack));
      fixture_complete (NULL);
      g_assert_cmpuint (io.command, ==, 0x90);
      fixture_complete (NULL);
      ack_reply (usb.pending, 0x90);
      fixture_complete (NULL);
      reply (usb.pending, 9, 0, ec_data, 1);
      fixture_complete (NULL);
      g_assert_cmpuint (io.command, ==, 0x32);
      fixture_complete (NULL);
      ack_reply (usb.pending, 0x32);
      fixture_complete (NULL);
      g_assert_true (self->service_active);
      g_assert_cmpuint (usb.timeout, ==, 0);
      g_assert_cmpuint (io.sends[0x32], ==, 2);
      g_assert_cmpuint (io.sends[0x90], ==, 1);
      g_assert_cmpuint (io.sends[0x20], ==, 0);
    }
  if (which == 10)
    {
      guint8 manual[28] = { 0x80 };
      reply (usb.pending, 3, 3, manual, sizeof (manual));
      fixture_complete (NULL);
      reply (usb.pending, 9, 0, ec_data, 1);
      fixture_complete (NULL);
      g_assert_cmpuint (self->command_response_ready, ==, 3);
      g_assert_cmpmem (self->manual_response, sizeof (manual), manual, sizeof (manual));
      g_assert_cmpuint (self->profile9_fdt.base_manual[0], ==, 0);
    }
  if (which == 5 || which == 8)
    {
      if (which == 5)
        fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR,
                                                G_USB_DEVICE_ERROR_NO_DEVICE, "Removed idle reader"));
      else
        {
          reply (usb.pending, 0xa, 7, ec_data, sizeof (ec_data));
          usb.pending->buffer[5] ^= 1;
          g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                                 "*checksum validation failed*");
          fixture_complete (NULL);
          g_test_assert_expected_messages ();
        }
      if (which == 5)
        {
          g_assert_null (usb.pending);
          g_assert_null (self->transport);
          g_assert_true (self->needs_reinit);
        }
      else
        {
          g_assert_nonnull (usb.pending);
          g_assert_nonnull (self->reader);
          g_assert_false (self->needs_reinit);
        }
    }
  if (handoff)
    {
      guint writes = io.started_writes;
      if (which == 11)
        {
          self->needs_reinit = TRUE;
          self->usb_interface_claimed = TRUE;
          fpi_ssm_start (fpi_ssm_new (dev, idle_test_reinit, 1), idle_test_command_done);
          g_assert_cmpuint (idle_releases, ==, 0);
          g_assert_cmpuint (idle_resets, ==, 0);
          g_assert_cmpuint (self->rx.len, ==, sizeof (fragment));
        }
      else
        fpi_ssm_start (fpi_ssm_new (dev, idle_test_ping, 1), idle_test_command_done);
      if (which == 11)
        {
          g_assert_true (g_cancellable_is_cancelled (usb.cancel));
          g_assert_cmpuint (io.started_writes, ==, writes);
          fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Joined idle"));
        }
      else
        g_assert_cmpuint (io.started_writes, ==, writes + 1);
      if (which == 6)
        g_cancellable_cancel (action_cancel_token);
      if (which == 3)
        {
          fixture_select_read ();
          reply (usb.pending, 0xa, 7, ec_data, sizeof (ec_data));
          fixture_complete (NULL); /* Reader publishes during the OUT. */
        }
      g_assert_cmpuint (usb.pending->endpoint, ==, GOODIX_EP_OUT);
      if (which == 11)
        {
          g_assert_cmpuint (idle_resets, ==, 1);
          g_assert_cmpuint (self->rx.len, ==, 0);
          g_assert_false (self->rx_idle_partial);
        }
      if (which == 6)
        {
          /* The already submitted write is cancelled; IN is unaffected. */
          g_assert_true (g_cancellable_is_cancelled (usb.cancel));
          g_assert_cmpuint (io.started_writes, ==, writes + 1);
        }
      fixture_complete (which == 6 ? g_error_new_literal (
        G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled command write") : NULL);
      if (which == 4 || which == 13)
        {
          g_assert_cmpuint (self->rx.len, ==, sizeof (fragment));
          fixture_fragment (partial, partial_length, sizeof (fragment));
          fixture_complete (NULL);
          g_assert_false (self->rx_idle_partial);
          g_assert_cmpuint (self->command_response_ready, ==, which == 13 ? 4 : 2);
          g_assert_cmpuint (io.completions, ==, 1);
        }
      if (which != 6)
        {
          ack_reply (usb.pending, 0);
          fixture_complete (NULL);
        }
      if (which == 11)
        idle_test_firmware_success ();
      g_assert_cmpuint (io.completions, ==, 2);
      if (which >= 12)
        {
          const guint8 *cached = NULL;
          gsize len = 0;
          g_assert_true (goodix_cmd_parse_fw_version_reply (dev, &cached, &len, NULL));
          g_assert_cmpuint (len, ==, 64);
          if (which == 12)
            g_assert_cmpstr ((const gchar *) cached, ==, "idle-version");
          else
            g_assert_cmpmem (cached, len, partial_payload, 64);
          g_assert_null (self->fw_version);
        }
    }

  /* Retain only the explicit idle device reference until the close joins. */
  gboolean pending = self->reader && self->reader->pending;
  gboolean service = self->service_active;
  goodix_close (dev);
  if (service)
    {
      fixture_refresh_wait ();
      g_assert_true (g_cancellable_is_cancelled (usb.cancel));
      g_assert_false (g_cancellable_is_cancelled (usb.physical_cancel));
      fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                              "Retired maintenance wait"));
      g_assert_true (g_cancellable_is_cancelled (usb.physical_cancel));
    }
  if (pending)
    {
      g_assert_cmpuint (idle_releases, ==, idle_resets);
      g_assert_cmpuint (idle_closes, ==, 0);
      g_assert_nonnull (self->rx.buf);
      g_object_unref (dev);
      g_assert_nonnull (weak);
      if (which == 7)
        {
          reply (usb.pending, 0xa, 7, ec_data, sizeof (ec_data));
          fixture_complete (NULL);
        }
      else
        fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Close idle join"));
    }
  else
    g_object_unref (dev);
  g_assert_cmpuint (idle_closes, ==, 1);
  g_assert_null (weak);
  g_assert_null (usb.pending);
  g_clear_pointer (&io.first_down, g_bytes_unref);
  g_clear_object (&action_cancel_token);
  idle_device = NULL;
}

static void
idle_open_cleanup_entry (FpiSsm *ssm, FpDevice *dev)
{
  /* Admit the completed reference-capture boundary; all cleanup states and
   * the failed-open completion/recovery owner below are production code. */
  if (fpi_ssm_get_cur_state (ssm) == 0)
    fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_SLEEP);
  else
    goodix_open_ssm_handler (ssm, dev);
}

static void
idle_open_data_free (gpointer data)
{
  g_assert_true (data == &idle_open_ssms_freed);
  idle_open_ssms_freed++;
}

static void
test_idle_failed_open (gconstpointer user_data)
{
  guint which = GPOINTER_TO_UINT (user_data);
  gboolean recover = which < 3 || which == 6;
  guint completion = which == 8 ? 0 : which >= 6 ? 3 : which % 3;
  /* cancelled, partial completion, no idle, complete optional response */
  static const Scenario scenario = { .schedule = EVENT_CANCELLED };
  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceGoodix53x5 *self;
  FpiSsm *ssm;
  g_autoptr(GError) original = NULL;
  FpDevice *weak;

  memset (&io, 0, sizeof (io));
  io.scenario = &scenario;
  idle_releases = idle_closes = idle_resets = idle_usb_closes = idle_open_ssms_freed = 0;
  idle_open_testing = TRUE;
  idle_reinit_testing = FALSE;
  dev = fixture_device_new ();
  weak = dev;
  g_object_add_weak_pointer (G_OBJECT (dev), (gpointer *) &weak);
  idle_device = dev;
  self = FPI_DEVICE_GOODIX53X5 (dev);
  self->cancel = g_cancellable_new ();
  self->usb_interface_claimed = TRUE;
  self->open_ref_powered = TRUE;
  self->open_recovery_attempted = !(recover || which == 8);
  ssm = fpi_ssm_new_full (dev, idle_open_cleanup_entry, GOODIX_OPEN_NUM_STATES,
                          GOODIX_OPEN_SLEEP, "failed-open-cleanup");
  self->task_ssm = ssm;
  fpi_ssm_set_data (ssm, &idle_open_ssms_freed, idle_open_data_free);
  fpi_ssm_start (ssm, goodix_open_ssm_done);
  for (guint i = 0; i < 2; i++)
    {
      g_assert_cmpuint (io.command, ==, 0x60);
      fixture_complete (NULL);
      fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR,
                                               G_USB_DEVICE_ERROR_TIMED_OUT,
                                               "original sleep timeout"));
    }
  original = g_error_copy (fpi_ssm_get_error (ssm));
  g_assert_error (original, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);
  g_assert_nonnull (strstr (original->message, "Receive deadline expired"));
  g_assert_cmpuint (io.sends[0x60], ==, 2);
  g_assert_cmpuint (io.command, ==, 0xae);
  fixture_complete (NULL);
  if (!recover)
    g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                           "*Device open failed:*Receive deadline expired*");
  if (completion == 2)
    {
      fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR,
                                            G_USB_DEVICE_ERROR_TIMED_OUT,
                                            "later EC timeout"));
      fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Joined failed reader"));
    }
  else
    {
      ack_reply (usb.pending, 0xae);
      fixture_complete (NULL);
      g_assert_cmpuint (idle_open_ssms_freed, ==, 1);
      g_assert_null (self->task_ssm);
      g_assert_cmpuint (idle_releases, ==, 0);
      g_assert_cmpuint (idle_resets, ==, 0);
      g_assert_cmpuint (idle_usb_closes, ==, 0);
      g_assert_cmpuint (io.completions, ==, 0);
      g_assert_true (g_cancellable_is_cancelled (usb.cancel));
      if (which == 8)
        g_cancellable_cancel (action_cancel_token);
      if (completion == 1)
        {
          guint8 payload[96] = { 0 };
          gsize len;
          g_autofree guint8 *packet = goodix_proto_build_message (
            9, 0, payload, sizeof (payload), TRUE, &len);
          g_assert_cmpuint (len, >, 64);
          fixture_fragment (packet, len, 0);
          fixture_complete (NULL); /* Partial data wins cancellation. */
        }
      else if (completion == 3)
        {
          guint8 payload[] = { 1, 0 };
          reply (usb.pending, 0xa, 7, payload, sizeof (payload));
          fixture_complete (NULL); /* Complete optional reply wins cancellation. */
        }
      else
        fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                "idle cancellation joined"));
    }
  g_assert_cmpuint (idle_releases, ==, 1);
  g_assert_false (self->rx_idle_partial);
  g_assert_cmpuint (self->rx.len, ==, 0);
  if (recover)
    {
      g_assert_cmpuint (idle_resets, ==, 1);
      g_assert_cmpuint (idle_usb_closes, ==, 0);
      g_assert_cmpuint (io.completions, ==, 0);
      g_assert_cmpuint (io.command, ==, 0);
      fixture_complete (NULL);
      g_assert_cmpuint (usb.timeout, ==, 500);
      ack_reply (usb.pending, 0);
      fixture_complete (NULL);
      idle_test_firmware_success ();
      g_assert_no_error (io.error);
    }
  else
    {
      g_test_assert_expected_messages ();
      g_assert_cmpuint (idle_resets, ==, 0);
      g_assert_cmpuint (idle_usb_closes, ==, 1);
      g_assert_error (io.error, original->domain, original->code);
      g_assert_cmpstr (io.error->message, ==, original->message);
    }
  g_assert_cmpuint (io.completions, ==, 1);
  g_assert_cmpuint (idle_open_ssms_freed, ==, 1);
  if (recover)
    g_assert_nonnull (usb.pending);
  else
    g_assert_null (usb.pending);
  g_assert_null (self->task_ssm);
  g_clear_error (&io.error);
  g_clear_pointer (&io.first_sleep, g_bytes_unref);
  if (recover)
    {
      g_assert_nonnull (usb.pending);
      g_assert_true (self->service_active);
      goodix_close (dev);
      fixture_refresh_wait ();
      g_assert_true (g_cancellable_is_cancelled (usb.cancel));
      g_assert_cmpuint (idle_closes, ==, 0);
      g_assert_false (g_cancellable_is_cancelled (usb.physical_cancel));
      fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                              "Retired maintenance wait"));
      g_assert_true (g_cancellable_is_cancelled (usb.physical_cancel));
      fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                              "Joined maintenance at close"));
      g_assert_cmpuint (idle_closes, ==, 1);
    }
  else
    {
      /* A failed open has already closed USB; release fixture allocations. */
      g_clear_pointer (&self->rx.buf, g_free);
      g_clear_object (&self->cancel);
      g_assert_cmpuint (idle_closes, ==, 0);
    }
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  g_assert_false (self->service_active);
  g_clear_object (&action_cancel_token);
  idle_device = NULL;
  g_clear_object (&dev);
  g_assert_null (weak);
  if (which == 5)
    {
      /* Also fail before the first receive: teardown must not allocate RX. */
      guint writes = io.started_writes;

      dev = g_object_new (FPI_TYPE_DEVICE_GOODIX53X5, NULL);
      idle_device = dev;
      self = FPI_DEVICE_GOODIX53X5 (dev);
      g_assert_null (self->rx.buf);
      self->open_recovery_attempted = TRUE;
      idle_releases = 0;
      idle_claim_failure = TRUE;
      ssm = fpi_ssm_new_full (dev, goodix_open_ssm_handler, GOODIX_OPEN_NUM_STATES,
                              GOODIX_OPEN_SLEEP, "early-failed-open");
      self->task_ssm = ssm;
      g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                             "*Device open failed: Early claim failure*");
      fpi_ssm_start (ssm, goodix_open_ssm_done);
      g_test_assert_expected_messages ();
      g_assert_error (io.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE);
      g_assert_cmpstr (io.error->message, ==, "Early claim failure");
      g_assert_cmpuint (io.completions, ==, 2);
      g_assert_cmpuint (io.started_writes, ==, writes);
      g_assert_null (usb.pending);
      g_assert_null (self->rx.buf);
      g_clear_error (&io.error);
      idle_device = NULL;
      idle_claim_failure = FALSE;
    }
  idle_open_testing = FALSE;
}

static void
startup_delay (FpiSsm *ssm, int state, int delay)
{
  g_assert_nonnull (startup_trace);
  g_assert_nonnull (usb.pending);
  g_assert_cmpint (delay, ==, 100);
  startup_delays++;
  g_string_append (startup_trace, "D,");
  test_clock_us += delay * 1000LL;
  /* Exercise FpiSsm's real delayed transition without sleeping in the test. */
  fpi_ssm_jump_to_state_delayed (ssm, state, 0);
}

typedef enum {
  PROBE_NORMAL, PROBE_EARLY, PROBE_NUL, PROBE_FULL, PROBE_LATE,
  PROBE_LATE_FW, PROBE_READY_RESET, PROBE_DEADLINE,
  PROBE_CANCEL_WRITE, PROBE_CANCEL_ACK, PROBE_CANCEL_DATA, PROBE_CANCEL_DELAY,
  PROBE_MALFORMED, PROBE_REMOVED,
} ProbeSchedule;

typedef struct {
  guint ping_failures;
  guint firmware_failures;
  ProbeSchedule schedule;
  const char *trace;
  guint delays;
} ProbeCase;

static void
startup_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  io.completions++;
  io.error = error;
}

static void
test_startup_probe (gconstpointer data)
{
  const ProbeCase *test = data;
  static const Scenario scenario = { .schedule = EVENT_CANCELLED };
  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceGoodix53x5 *self;
  guint8 version[64];
  gboolean early = FALSE;
  gboolean late = FALSE;
  guint interruptions = 0;

  memset (&io, 0, sizeof (io));
  io.scenario = &scenario;
  startup_delays = 0;
  startup_trace = g_string_new (NULL);
  dev = fixture_device_new ();
  self = FPI_DEVICE_GOODIX53X5 (dev);
  self->cancel = g_cancellable_new ();
  self->fw_version = g_strdup ("previous-getter-output");
  memset (self->shared_response, 0x55, sizeof (self->shared_response));
  memset (version, 'V', sizeof (version));
  if (test->schedule != PROBE_FULL)
    memcpy (version, test->schedule == PROBE_NUL ? "\0bc" : "abc", 4);

  /* Execute real claim/probe and the reset-only prefix of the chip child. */
  fpi_ssm_start (fpi_ssm_new_full (dev, goodix_open_ssm_handler,
                                  GOODIX_OPEN_READ_OTP, GOODIX_OPEN_READ_OTP,
                                  "startup-boundary"), startup_done);
  for (guint step = 0; !io.completions && step < 150; step++)
    {
      if (!self->transport)
        {
          if (test->schedule == PROBE_CANCEL_DELAY)
            g_cancellable_cancel (action_cancel_token);
          g_main_context_iteration (NULL, TRUE);
          continue;
        }
      if (usb.pending->endpoint == GOODIX_EP_OUT)
        {
          if (test->schedule == PROBE_CANCEL_WRITE && io.command == 0)
            {
              g_cancellable_cancel (action_cancel_token);
              fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Write cancelled"));
            }
          else
            fixture_complete (NULL);
          continue;
        }
      gboolean fw = io.command == 0xa8;
      gboolean response = fw && io.ec_data;
      if (io.command == 0 || fw)
        {
          if (usb.timeout != (response ? 2000 - interruptions * 500 : 500))
            g_test_fail ();
          if (usb.cancel != action_cancel_token)
            g_test_fail ();
        }
      if ((test->schedule == PROBE_CANCEL_ACK && io.command == 0) ||
          (test->schedule == PROBE_CANCEL_DATA && response))
        {
          g_cancellable_cancel (action_cancel_token);
          fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Wait cancelled"));
        }
      else if (test->schedule == PROBE_REMOVED && io.command == 0)
        fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE, "Removed"));
      else if (test->schedule == PROBE_MALFORMED && io.command == 0 && !late)
        {
          ack_reply (usb.pending, 0x82);
          late = TRUE;
          fixture_complete (NULL);
        }
      else if ((io.command == 0 && io.sends[0] <= test->ping_failures) ||
               (response && io.sends[0xa8] <= test->firmware_failures) ||
               (fw && !response && early && io.sends[0xa8] == 1 &&
                test->schedule == PROBE_READY_RESET))
        {
          test_clock_us += usb.timeout * 1000LL;
          fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR,
                                                  G_USB_DEVICE_ERROR_TIMED_OUT, "Scheduled probe timeout"));
        }
      else if (fw && !io.ec_data &&
               (test->schedule == PROBE_EARLY || test->schedule == PROBE_READY_RESET) && !early)
        {
          reply (usb.pending, 0x0a, 4, test->schedule == PROBE_READY_RESET ?
                 (const guint8 *) "old" : version, 4);
          if (test->schedule == PROBE_EARLY)
            {
              const guint8 status[] = { 0xa8, 1 };
              gsize length;
              g_autofree guint8 *ack = goodix_proto_build_message (
                0x0b, 0, status, sizeof (status), TRUE, &length);
              memcpy (usb.pending->buffer + 64, ack, length);
              usb.pending->actual_length = 128;
            }
          early = TRUE;
          fixture_complete (NULL);
        }
      else if (fw && test->schedule == PROBE_LATE && !late)
        {
          ack_reply (usb.pending, 0);
          late = TRUE;
          fixture_complete (NULL);
        }
      else if (!fw && io.command == 0 && io.sends[0] == 2 &&
               test->schedule == PROBE_LATE_FW && !late)
        {
          ack_reply (usb.pending, 0xa8);
          late = TRUE;
          fixture_complete (NULL);
        }
      else if (response && test->schedule == PROBE_DEADLINE && interruptions < 2)
        {
          test_clock_us += 500000;
          if (interruptions == 0)
            {
              guint8 value = 0;
              reply (usb.pending, 0x0a, 7, &value, 1);
            }
          else
            usb.pending->actual_length = 0;
          interruptions++;
          fixture_complete (NULL);
        }
      else if (response)
        {
          if (test->schedule == PROBE_FULL)
            {
              gsize len;
              g_autofree guint8 *packet = goodix_proto_build_message (0x0a, 4, version, 64, TRUE, &len);
              fixture_fragment (packet, len, 0);
              usb.pending->buffer[64] = packet[0] | 1;
              memcpy (usb.pending->buffer + 65, packet + 64, len - 64);
              memset (usb.pending->buffer + len + 1, 0, 128 - len - 1);
              usb.pending->actual_length = 128;
              fixture_complete (NULL);
            }
          else
            {
              reply (usb.pending, 0x0a, 4, version, 4);
              fixture_complete (NULL);
            }
        }
      else
        {
          ack_reply (usb.pending, io.command);
          if (fw)
            io.ec_data = TRUE;
          fixture_complete (NULL);
        }
    }
  g_test_message ("startup trace=%s delays=%u output=%s error=%s", startup_trace->str,
                  startup_delays, self->fw_version, io.error ? io.error->message : "none");
  g_assert_cmpuint (io.completions, ==, 1);
  g_assert_cmpstr (startup_trace->str, ==, test->trace);
  g_assert_cmpuint (startup_delays, ==, test->delays);
  if (test->schedule >= PROBE_CANCEL_WRITE && test->schedule != PROBE_MALFORMED)
    {
      if (test->schedule <= PROBE_CANCEL_DELAY)
        g_assert_error (io.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
      else
        g_assert_error (io.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE);
      g_assert_cmpstr (self->fw_version, ==, "previous-getter-output");
    }
  else
    {
      g_assert_no_error (io.error);
      g_assert_false (self->needs_reinit);
      if (test->firmware_failures >= 10)
        g_assert_cmpstr (self->fw_version, ==, "previous-getter-output");
      else
        {
          g_assert_cmpstr (self->fw_version, ==, test->schedule == PROBE_NUL ? "" :
                          test->schedule == PROBE_FULL ?
                          "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV" : "abc");
          if (test->schedule != PROBE_FULL)
            for (guint i = 4; i < 64; i++)
              g_assert_cmpuint (self->shared_response[i], ==, 0x55);
        }
    }
  fixture_join_reader (dev);
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  g_clear_error (&io.error);
  g_clear_pointer (&self->rx.buf, g_free);
  g_clear_pointer (&self->fw_version, g_free);
  g_clear_object (&self->cancel);
  g_clear_object (&action_cancel_token);
  g_string_free (startup_trace, TRUE);
  startup_trace = NULL;
}

static void
register_lifecycle_tests (void)
{
  static const ProbeCase probes[] = {
    { 0, 1, PROBE_NORMAL, "00,a8,a8,a2,", 0 },
    { 10, 10, PROBE_NORMAL, "00,00,a8,a8,D,00,00,a8,a8,D,00,00,a8,a8,D,00,00,a8,a8,D,00,00,a8,a8,D,a2,", 5 },
    { 0, 0, PROBE_EARLY, "00,a8,a2,", 0 },
    { 0, 0, PROBE_NUL, "00,a8,a2,", 0 },
    { 0, 0, PROBE_FULL, "00,a8,a2,", 0 },
    { 2, 0, PROBE_LATE, "00,00,a8,a2,", 0 },
    { 0, 2, PROBE_LATE_FW, "00,a8,a8,D,00,a8,a2,", 1 },
    { 0, 0, PROBE_READY_RESET, "00,a8,a8,a2,", 0 },
    { 0, 0, PROBE_DEADLINE, "00,a8,a2,", 0 },
    { 0, 0, PROBE_CANCEL_WRITE, "00,", 0 },
    { 0, 0, PROBE_CANCEL_ACK, "00,", 0 },
    { 0, 0, PROBE_CANCEL_DATA, "00,a8,", 0 },
    { 0, 2, PROBE_CANCEL_DELAY, "00,a8,a8,D,", 1 },
    { 0, 0, PROBE_MALFORMED, "00,a8,a2,", 0 },
    { 0, 0, PROBE_REMOVED, "00,", 0 },
  };
  const char *probe_names[] = { "firmware-retry", "all-exhausted", "early-response", "empty-string",
                               "full-string", "late-ping-ack", "late-firmware-ack", "ready-reset", "response-deadline",
                               "cancel-write", "cancel-ack", "cancel-data",
                               "cancel-delay", "unrelated-ack", "removed" };
  for (guint i = 0; i < G_N_ELEMENTS (probes); i++)
    {
      g_autofree char *name = g_strdup_printf ("startup/%s", probe_names[i]);
      add_transport_case (name, &probes[i], test_startup_probe);
    }
  const char *failed_open_names[] = { "recovery-cancel", "recovery-partial-race", "recovery-no-idle",
                                     "final-cancel", "final-partial-race", "final-no-idle",
                                     "recovery-reply-race", "final-reply-race", "action-cancel-during-join" };
  for (guint i = 0; i < G_N_ELEMENTS (failed_open_names); i++)
    {
      g_autofree char *name = g_strdup_printf ("failed-open/%s",
                                              failed_open_names[i]);
      add_transport_case (name, GUINT_TO_POINTER (i), test_idle_failed_open);
    }
  const char *idle_names[] = { "ack-only-close", "tail", "handoff", "handoff-race",
                              "partial-handoff", "removal", "action-cancel", "close-race", "bad-frame",
                              "stopped-fdt", "response-caches", "partial-reinit", "firmware-cache", "firmware-partial-handoff" };
  for (guint i = 0; i < G_N_ELEMENTS (idle_names); i++)
    {
      g_autofree char *name = g_strdup_printf ("idle/%s", idle_names[i]);
      add_transport_case (name, GUINT_TO_POINTER (i), test_idle_lifetime);
    }
}
