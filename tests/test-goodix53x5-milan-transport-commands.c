/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Command bytes, retries, independent deadlines and shared reply caches. */

static gboolean
arm_repair_case (const Scenario *scenario)
{
  Schedule schedule = scenario->schedule;

  return schedule == ARM_STATUS || schedule == ARM_CONFIG_FAIL ||
         schedule == ARM_REPEAT_FAIL || schedule == ARM_REPEAT_STATUS ||
         schedule == ARM_REFRESH || schedule == ARM_MAX ||
         schedule == ARM_CONFIG_DATA_FAIL || schedule == ARM_CONFIG_PROTO ||
         schedule == ARM_CONFIG_CANCEL || schedule == ARM_FIRST_FAIL;
}

static gboolean
response_command_case (const Scenario *scenario)
{
  Schedule schedule = scenario->schedule;

  return schedule == RESPONSE_EARLY || schedule == RESPONSE_RETRY ||
         schedule == RESPONSE_EARLY_RESET || schedule == RESPONSE_STATUS ||
         schedule == RESPONSE_DUPLICATE ||
         schedule == RESPONSE_HANDOFF;
}

static gboolean
send_error_case (const Scenario *scenario)
{
  Schedule schedule = scenario->schedule;

  return schedule == SEND_IO_RETRY || schedule == SEND_TIMEOUT_RETRY ||
         schedule == SEND_DISCONNECT || schedule == SEND_CANCELLED ||
         schedule == SEND_FAILED_RETRY || schedule == SEND_STALL_RETRY ||
         schedule == SEND_INTERNAL_RETRY;
}

static gboolean
write_contract_case (const Scenario *scenario)
{
  Schedule schedule = scenario->schedule;

  return schedule == SEND_FAILED_RETRY || schedule == SEND_STALL_RETRY ||
         schedule == SEND_INTERNAL_RETRY || schedule == WRITE_STALLED_CANCEL;
}

void
check_submit (FpiUsbTransfer *transfer, guint timeout, GCancellable *cancel)
{
  if (transfer->endpoint == GOODIX_EP_IN)
    {
      g_assert_cmpuint (transfer->length, ==, 0x8000);
      g_assert_cmpuint (timeout, ==, 0);
      g_assert_nonnull (cancel);
      g_assert_true (cancel != action_cancel_token);
    }
  else
    {
      GBytes **first = NULL;
      g_assert_cmpuint (transfer->endpoint, ==, GOODIX_EP_OUT);
      if (write_contract_case (io.scenario) &&
          (timeout != 0 || cancel != FPI_DEVICE_GOODIX53X5 (transfer->device)->session_cancel))
        g_test_fail ();
      if (cancel && g_cancellable_is_cancelled (cancel))
        io.precancelled_writes++;
      else
        io.started_writes++;
      io.command = transfer->buffer[0];
      if (startup_trace)
        {
          guint8 ping[] = { 0, 3, 0, 0, 0, 0xa7 };
          guint8 fw[] = { 0xa8, 3, 0, 0, 0, 0xff };
          guint8 reset[] = { 0xa2, 3, 0, 1, 0x14, 0xf0 };
          const guint8 *expected = io.command == 0 ? ping : io.command == 0xa8 ? fw : reset;
          g_assert_cmpmem (transfer->buffer, 6, expected, 6);
          g_string_append_printf (startup_trace, "%02x,", io.command);
        }
      io.sends[io.command]++;
      io.ec_data = FALSE;
      if (arm_repair_case (io.scenario) && io.command == 0x90)
        {
          gsize len;
          const guint8 *config = goodix_device_get_default_config (&len);
          guint8 expected[256];
          guint16 sum = 0xa5a5;

          g_assert_cmpuint (len, ==, sizeof (expected));
          memcpy (expected, config, len);
          expected[0xc7] = 0x80;
          expected[0xc8] = 30; /* Native delta patch; zero TCODE / invalid DAC retain template. */
          for (guint i = 0; i < 254; i += 2)
            sum += expected[i] | ((guint16) expected[i + 1] << 8);
          sum = -sum;
          expected[254] = sum;
          expected[255] = sum >> 8;
          for (guint i = 0; i < sizeof (expected); i++)
            {
              guint offset = i + 3;
              guint wire_offset = offset < 64 ? offset :
                                  64 + ((offset - 64) / 63) * 64 + 1 + (offset - 64) % 63;
              g_assert_cmpuint (transfer->buffer[wire_offset], ==, expected[i]);
            }
        }
      if (io.command == 0xae)
        io.ec_ack_started = 0;
      if (io.command == 0x34)
        {
          first = &io.first_up;
        }
      else if (io.command == 0x60)
        {
          first = &io.first_sleep;
        }
      else if (io.command == 0x32)
        {
          first = &io.first_down;
          memcpy (io.last_down_payload, transfer->buffer + 5, GOODIX_FDT_BASE_LEN);
        }
      else if (io.command == 0x36 || io.command == 0x90)
        {
          first = &io.first_response;
        }
      if (first)
        {
          g_autoptr(GBytes) bytes = g_bytes_new (transfer->buffer,
                                                 transfer->length);
          if (*first && !(io.scenario->schedule == ARM_REFRESH && io.command == 0x32) &&
              !(io.command == 0x32 &&
                (io.scenario->schedule == EARLY_REARM_REVERSE ||
                 io.scenario->schedule == TWO_EARLY_REVERSE) &&
                io.sends[0x32] > 1 + io.scenario->timeout_count))
            g_assert_true (g_bytes_equal (*first, bytes));
          else if (!*first)
            *first = g_bytes_ref (bytes);
        }
    }
}

static gboolean
polling_case (const Scenario *scenario)
{
  return scenario->schedule == ACK_ZERO_THEN_ONE ||
         scenario->schedule == ACK_TWO_THEN_ONE ||
         scenario->schedule == ACK_EVEN_TIMEOUT ||
         scenario->schedule == ACK_EVEN_THEN_MALFORMED;
}

/* Independent native caller values, also used by the scheduling assertions. */
static guint
ack_budget (guint8 command)
{
  if (command == 0x60 || command == 0xae)
    return 200;
  if (command == 0x32 || command == 0x34 || command == 0x36 || command == 0x90 ||
      command == 0xa2 || command == 0x82 || command == 0xa6 || command == 0xe4 || command == 0xe2)
    return 500;
  return 2000;
}

static gboolean
response_case (const Scenario *scenario)
{
  return scenario->schedule == RESPONSE_BUDGET ||
         scenario->schedule == RESPONSE_DEADLINE ||
         scenario->schedule == EC_LATE_ACK ||
         scenario->schedule == EC_LATE_DATA ||
         response_command_case (scenario);
}

static GError *
complete_write (FpiUsbTransfer *transfer, GCancellable *cancel)
{
  const Scenario *scenario = io.scenario;
  GError *error = NULL;
  Schedule order = scenario->schedule;

  if (order == WRITE_STALLED_CANCEL && io.command == 0x34 && !io.action_cancelled)
    {
      /* The write stays owned until its cancellation completion. */
      g_assert_cmpuint (io.completions, ==, 0);
      io.action_cancelled = TRUE;
      stop_after_capture (transfer->device);
      g_cancellable_cancel (action_cancel_token);
      g_cancellable_cancel (FPI_DEVICE_GOODIX53X5 (transfer->device)->cancel);
    }
  /* ACK budgets begin after write completion, not at submission. */
  if (response_case (scenario))
    test_clock_us += 50 * 1000;
  if (cancel && g_cancellable_is_cancelled (cancel))
    {
      io.cancelled_writes++;
      error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Action write cancelled before completion");
    }
  else if (io.command == 0x34 && io.sends[0x34] == 1 &&
           (send_error_case (scenario) ||
            order == EARLIER_CLEANUP_ERROR))
    {
      gint code = order == SEND_IO_RETRY ? G_USB_DEVICE_ERROR_IO :
                  order == SEND_TIMEOUT_RETRY ? G_USB_DEVICE_ERROR_TIMED_OUT :
                  order == SEND_DISCONNECT || order == EARLIER_CLEANUP_ERROR ? G_USB_DEVICE_ERROR_NO_DEVICE :
                  order == SEND_CANCELLED ? G_USB_DEVICE_ERROR_CANCELLED :
                  order == SEND_FAILED_RETRY ? G_USB_DEVICE_ERROR_FAILED :
                  order == SEND_STALL_RETRY ? G_USB_DEVICE_ERROR_NOT_SUPPORTED : G_USB_DEVICE_ERROR_INTERNAL;
      stop_after_capture (transfer->device);
      error = g_error_new_literal (G_USB_DEVICE_ERROR, code, "Scheduled send failure");
    }
  return error;
}

static GError *
command_reply (FpiUsbTransfer *transfer)
{
  const Scenario *scenario = io.scenario;
  GError *error = NULL;

  if (scenario->schedule == RESPONSE_DUPLICATE && io.command == 0xae &&
      io.sends[0xae] == 2 && io.duplicates < 2)
    {
      if (io.duplicates++ == 0)
        {
          ack_reply (transfer, scenario->standalone_arm);
        }
      else
        {
          guint8 payload[4 + GOODIX_FDT_BASE_LEN];
          memset (payload, 0x77, sizeof (payload));
          reply (transfer, scenario->standalone_arm >> 4,
                 (scenario->standalone_arm & 0xf) >> 1,
                 payload, scenario->standalone_arm == 0x90 ? 1 : sizeof (payload));
        }
      test_clock_us += 75 * 1000;
    }
  else if (response_command_case (scenario) &&
           io.command == (scenario->schedule == RESPONSE_HANDOFF ?
                          scenario->timeout_command : scenario->standalone_arm))
    {
      guint8 payload[4 + GOODIX_FDT_BASE_LEN];
      gboolean early = scenario->schedule == RESPONSE_EARLY ||
                       (scenario->schedule == RESPONSE_EARLY_RESET && io.sends[io.command] == 1);

      for (guint i = 0; i < sizeof (payload); i++)
        payload[i] = i + 1;
      if (io.command == 0x90)
        payload[0] = scenario->ec_status;
      if (scenario->schedule == RESPONSE_HANDOFF && io.events < 2)
        {
          reverse_event (transfer, io.events);
        }
      else if (early && !io.ec_data && io.early_attempt != io.sends[io.command])
        {
          io.early_attempt = io.sends[io.command];
          reply (transfer, io.command >> 4, (io.command & 0xf) >> 1,
                 payload, io.command == 0x90 ? 1 : sizeof (payload));
          test_clock_us += 350 * 1000;
          io.data_chunks++;
        }
      else if ((!io.ec_data && scenario->schedule == RESPONSE_EARLY_RESET &&
                io.sends[io.command] == 1) ||
               (io.ec_data && scenario->schedule == RESPONSE_RETRY &&
                io.sends[io.command] == 1))
        {
          test_clock_us += usb.timeout * 1000;
          error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                       "Scheduled response-command timeout");
        }
      else if (!io.ec_data)
        {
          if (usb.timeout != (early ? 150 : 500))
            g_test_fail ();
          ack_reply (transfer, io.command);
          io.ec_data = TRUE;
        }
      else
        {
          /* An early response must avoid this receive entirely. */
          if (early)
            g_test_fail ();
          reply (transfer, io.command >> 4, (io.command & 0xf) >> 1,
                 payload, io.command == 0x90 ? 1 : sizeof (payload));
          io.data_chunks++;
        }
    }
  else if (!io.ec_data)
    {
      if (scenario->schedule == CLEANUP_LATE_PROTO && io.command == 0xae)
        {
          reply (transfer, 0xb, 0, &io.command, 1);
        }
      else if (scenario->schedule == EC_LATE_ACK && io.command == scenario->standalone_arm &&
               io.duplicates == 0)
        {
          if (usb.timeout != 500)
            g_test_fail ();
          test_clock_us += 350 * 1000;
          reply (transfer, 0xa, 7, &scenario->ec_status, 1);
          io.duplicates++;
        }
      else if (polling_case (scenario) && io.command == scenario->timeout_command)
        {
          if (io.even_attempt != io.sends[io.command])
            {
              guint8 ack[] = { io.command, scenario->schedule == ACK_ZERO_THEN_ONE ? 0 : 2 };

              io.even_attempt = io.sends[io.command];
              if (usb.timeout != ack_budget (io.command))
                g_test_fail ();
              test_clock_us += ack_budget (io.command) * 750;
              reply (transfer, 0x0b, 0, ack, sizeof (ack));
            }
          else
            {
              io.even_followups++;
              /* The even ACK consumed three quarters of the native budget. */
              if (usb.timeout != ack_budget (io.command) / 4)
                g_test_fail ();
              if (scenario->schedule == ACK_EVEN_THEN_MALFORMED)
                {
                  reply (transfer, 0x0b, 0, &io.command, 1);
                }
              else if (io.sends[io.command] <= scenario->timeout_count)
                {
                  test_clock_us += usb.timeout * 1000;
                  error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                               "Even ACK exhausted attempt deadline");
                }
              else
                {
                  ack_reply (transfer, io.command);
                  io.ec_data = io.command == 0xae;
                }
            }
        }
      else if (rearm_case (scenario) && io.command == 0x32 && io.sends[0x32] == 1 &&
               io.events < (scenario->schedule == TWO_EARLY_REVERSE ? 2 : 1))
        {
          reverse_event (transfer, io.events);
        }
      else if (io.command == scenario->timeout_command &&
               io.sends[io.command] <= scenario->timeout_count)
        {
          test_clock_us += usb.timeout * 1000;
          error = g_error_new_literal (G_USB_DEVICE_ERROR,
                                       G_USB_DEVICE_ERROR_TIMED_OUT,
                                       "Scheduled ACK timeout");
        }
      else if (io.command == 0x60 &&
               scenario->schedule == EVENT_BEFORE_SLEEP_ACK && io.events == 0)
        {
          up_event (transfer);
        }
      else if (io.command == 0x60 && down_drain_case (scenario) && io.events == 0)
        {
          guint8 payload[4 + GOODIX_FDT_BASE_LEN] = { 2, 0, 0xff, 0x0f };

          if (scenario->schedule == REVERSE_BEFORE_SLEEP_ACK)
            payload[0] = 0x80;
          for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
            payload[4 + 2 * i] = 100 + 2 * i;
          reply (transfer, 3, 1, payload, sizeof (payload));
          io.events++;
        }
      else if (io.command == 0x34 && scenario->schedule == EVENT_BEFORE_ARM_ACK &&
               io.events == 0)
        {
          up_event (transfer);
        }
      else if (io.command == 0xae &&
               (scenario->schedule == DUPLICATE_SLEEP_BEFORE_EC_ACK ||
                scenario->schedule == LATE_EVEN_ACK) &&
               io.duplicates == 0)
        {
          io.duplicates++;
          if (scenario->schedule == LATE_EVEN_ACK)
            {
              const guint8 ack[] = { 0x60, 2 };

              test_clock_us += ack_budget (io.command) * 750;
              reply (transfer, 0x0b, 0, ack, sizeof (ack));
            }
          else
            {
              ack_reply (transfer, 0x60);
            }
        }
      else if (io.command == 0xae &&
               (scenario->schedule == LATE_ACK_DEADLINE ||
                scenario->schedule == LATE_EVEN_DEADLINE))
        {
          gint64 elapsed_ms;
          if (!io.ec_ack_started)
            io.ec_ack_started = test_clock_us;
          elapsed_ms = (test_clock_us - io.ec_ack_started) / 1000;
          if (usb.timeout == 0 || elapsed_ms + usb.timeout > ack_budget (io.command))
            io.deadline_violation = TRUE;
          if (io.duplicates == 0)
            {
              /* Exactly the remaining ACK from the two sleep attempts, not
               * an invented stream of more ACKs than commands sent. */
              test_clock_us += ack_budget (io.command) * 750;
              io.duplicates++;
              const guint8 ack[] = { 0x60, scenario->schedule == LATE_EVEN_DEADLINE ? 0 : 1 };

              reply (transfer, 0x0b, 0, ack, sizeof (ack));
            }
          else
            {
              test_clock_us += usb.timeout * 1000;
              error = g_error_new_literal (G_USB_DEVICE_ERROR,
                                           G_USB_DEVICE_ERROR_TIMED_OUT,
                                           "Scheduled ACK deadline exhaustion");
            }
        }
      else
        {
          /* In retry scenarios this models the delayed first attempt's ACK.
           * The later injected duplicate belongs to the second send. The wire
           * has no attempt number; both carry identical command/status bytes. */
          ack_reply (transfer, io.command);
          guint expected_timeout = scenario->schedule == EC_LATE_ACK &&
                                   io.command == scenario->standalone_arm ? 150 : ack_budget (io.command);
          if (scenario->schedule == RESPONSE_DUPLICATE && io.command == 0xae && io.sends[0xae] == 2)
            expected_timeout = 50;
          if (response_case (scenario) && usb.timeout != expected_timeout)
            g_test_fail ();
          if (io.command == 0xae)
            {
              if (scenario->schedule == LATE_EVEN_ACK && usb.timeout != ack_budget (io.command) / 4)
                g_test_fail ();
              io.expected_acks++;
              if (scenario->schedule == RESPONSE_DUPLICATE && io.sends[0xae] == 2 && usb.timeout != 50)
                g_test_fail ();
            }
          io.ec_data = io.command == 0xae || scenario->schedule == MULTICELL_DATA ||
                       (response_case (scenario) && io.command == scenario->standalone_arm);
        }
    }
  else
    {
      g_assert_true (io.ec_data);
      if (io.command == 0xae)
        {
          /* Native supplies no required EC response. A baseline that asks for
           * one exhausts its receive rather than receiving an invented byte. */
          error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                       "No EC response exists");
        }
      else if (response_case (scenario))
        {
          if (io.duplicates == 0)
            {
              if (usb.timeout != 500)
                g_test_fail ();
              test_clock_us += 350 * 1000;
              io.duplicates++;
              if (scenario->schedule == EC_LATE_DATA)
                reply (transfer, 0xa, 7, &scenario->ec_status, 1);
              else
                ack_reply (transfer, 0x60);
            }
          else
            {
              if (usb.timeout != (scenario->schedule == EC_LATE_ACK ||
                                  io.sends[io.command] > 1 ? 500 : 150))
                g_test_fail ();
              io.data_chunks++;
              if (scenario->schedule == RESPONSE_DEADLINE)
                {
                  test_clock_us += usb.timeout * 1000;
                  error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                               "Response budget exhausted after late ACK");
                }
              else
                {
                  guint8 payload[4 + GOODIX_FDT_BASE_LEN];

                  for (guint i = 0; i < sizeof (payload); i++)
                    payload[i] = i + 1;
                  reply (transfer, io.command >> 4, (io.command & 0xf) >> 1,
                         payload, io.command == 0x90 ? 1 : sizeof (payload));
                }
            }
        }
      else if (scenario->schedule == MULTICELL_DATA)
        {
          guint8 payload[150];
          gsize size;
          for (guint i = 0; i < sizeof (payload); i++)
            payload[i] = i * 7 + 3;
          g_autofree guint8 *message = goodix_proto_build_message (
            8, 1, payload, sizeof (payload), TRUE, &size);
          /* Sized register data has one 200-ms response budget across cells.
           * Three valid cells arrive 60 ms apart; no wall-clock wait. */
          if (usb.timeout != 200 - io.data_chunks * 60)
            g_test_fail ();
          test_clock_us += MIN (usb.timeout, 60) * 1000;
          if (usb.timeout < 60)
            {
              error = g_error_new_literal (G_USB_DEVICE_ERROR,
                                           G_USB_DEVICE_ERROR_TIMED_OUT,
                                           "Continuation budget shortened");
            }
          else
            {
              gsize offset = io.data_chunks ? 64 + (io.data_chunks - 1) * 63 : 0;
              guint prefix = io.data_chunks ? 1 : 0;
              memset (transfer->buffer, 0, transfer->length);
              if (prefix)
                transfer->buffer[0] = 0x83;
              memcpy (transfer->buffer + prefix, message + offset,
                      MIN (64 - prefix, size - offset));
              transfer->actual_length = 64;
              io.data_chunks++;
            }
        }
      else
        {
          g_assert_not_reached ();
        }
    }
  return error;
}

static void
data_handler (FpiSsm *ssm, FpDevice *dev)
{
  /* Opaque multi-cell register response at the framing boundary only.
   * Image responses instead have a fixed deadline and receiver-side decoding. */
  if (fpi_ssm_get_cur_state (ssm) == 0)
    {
      goodix_cmd_read_chip_id (ssm, dev, NULL);
    }
  else
    {
      const guint8 *payload;
      gsize length;
      GError *error = NULL;
      if (!goodix_parse_reply_exact (dev, 8, 1, &payload, &length, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else
        {
          g_assert_cmpuint (length, ==, 150);
          for (guint i = 0; i < length; i++)
            g_assert_cmpuint (payload[i], ==, (guint8) (i * 7 + 3));
          fpi_ssm_mark_completed (ssm);
        }
    }
}

static void
send_response_command (FpiSsm *ssm, FpDevice *dev, guint8 command)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (command == 0x36)
    {
      goodix_cmd_fdt_manual (ssm, dev, TRUE, self->profile9_fdt.base_manual);
    }
  else
    {
      gsize len;
      const guint8 *config = goodix_device_get_default_config (&len);
      g_autofree guint8 *patched = g_memdup2 (config, len);
      goodix_device_patch_config (patched, len, &self->calib);
      goodix_cmd_upload_config (ssm, dev, patched, len);
    }
}

static void
response_handler (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case 0:
      goodix_cmd_set_sleep_mode (ssm, dev);
      break;

    case 1:
      goodix_cmd_ec_control (ssm, dev, FALSE);
      break;

    case 2:
      send_response_command (ssm, dev, io.scenario->standalone_arm);
      break;

    case 3:
      {
        const guint8 *payload;
        gsize length;
        g_autoptr(GError) error = NULL;

        if (io.command == 0x90)
          {
            if (!goodix_cmd_parse_config_reply (dev))
              g_test_fail ();
            if (io.scenario->schedule == RESPONSE_DUPLICATE)
              goodix_cmd_ec_control (ssm, dev, FALSE);
            else
              fpi_ssm_mark_completed (ssm);
          }
        else if (!goodix_cmd_parse_fdt_manual_reply (dev, &payload, &length, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          }
        else
          {
            g_assert_cmpuint (length, ==, io.command == 0x90 ? 1 : 4 + GOODIX_FDT_BASE_LEN);
            for (guint i = 0; i < length; i++)
              g_assert_cmpuint (payload[i], ==, i + 1);
            if (io.scenario->schedule == RESPONSE_DUPLICATE)
              goodix_cmd_ec_control (ssm, dev, FALSE);
            else
              fpi_ssm_mark_completed (ssm);
          }
      }
      break;

    case 4:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
alias_command (FpiSsm *ssm, FpDevice *dev)
{
  guint category = GPOINTER_TO_UINT (fpi_ssm_get_data (ssm));
  guint8 payload[2] = { 0, 0 };

  if (category)
    goodix_run_cmd (ssm, dev, category, 1, payload, sizeof (payload), TRUE);
  else
    goodix_cmd_read_fw_version (ssm, dev);
}

static void
alias_packet (guint8 category, guint8 command, const guint8 *payload, gsize len)
{
  gsize size;
  g_autofree guint8 *packet = goodix_proto_build_message (category, command, payload, len, TRUE, &size);
  gsize offset = 0;

  while (offset < size)
    {
      offset = fixture_fragment (packet, size, offset);
      fixture_complete (NULL);
    }
}

static void
test_shared_response (gconstpointer data)
{
  guint which = GPOINTER_TO_UINT (data);
  gboolean idle = which == 6;
  gboolean after_ack = which == 3 || which == 5 || which >= 7;
  guint category = which == 7 ? 8 : which == 8 ? 0x0e : 0;
  static const Scenario scenario = { .schedule = EVENT_CANCELLED };

  g_autoptr(FpDevice) dev = NULL;
  guint8 expected[64], payload[76], version[] = { 'v', 0 };
  const guint8 *cached = NULL;
  gsize len = 0;
  FpiSsm *ssm;

  memset (&io, 0, sizeof (io));
  io.scenario = &scenario;
  dev = fixture_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  memset (expected, 0x55, sizeof (expected));
  memcpy (self->shared_response, expected, sizeof (expected));

  ssm = fpi_ssm_new (dev, idle ? idle_test_ec : alias_command, 1);
  fpi_ssm_set_data (ssm, GUINT_TO_POINTER (category), NULL);
  fpi_ssm_start (ssm, idle_test_command_done);
  fixture_complete (NULL);
  if (idle || after_ack)
    {
      ack_reply (usb.pending, io.command);
      fixture_complete (NULL);
    }
  if (which >= 4 && which <= 6)
    {
      const guint8 categories[] = { 0x0a, 8, 0x0e, 0x0f };
      const guint8 commands[] = { 3, 1, 2, 0 };
      const guint sizes[] = { 16, 24, 76, 4 };

      for (guint i = 0; i < 4; i++)
        {
          memset (payload, 'B' + i, sizeof (payload));
          test_clock_us += 100000;
          alias_packet (categories[i], commands[i], payload, sizes[i]);
          if (i == 2)
            {
              const guint8 length[] = { 76, 0, 0, 0 };
              memcpy (expected, length, 4);
              memcpy (expected + 4, payload, 60);
            }
          else
            {
              memcpy (expected, payload, i == 3 ? 1 : sizes[i]);
            }
          g_assert_cmpmem (self->shared_response, 64, expected, 64);
          g_assert_cmpuint (self->command_response_ready & 4, ==, 0);
          g_assert_cmpuint (io.completions, ==, idle ? 1 : 0);
          g_assert_cmpuint (usb.timeout, ==, idle ? 0 : (after_ack ? 2000 : 500) - (i + 1) * 100);
        }
      if (idle)
        {
          /* The cache and physical IN survive command admission. */
          fpi_ssm_start (fpi_ssm_new (dev, alias_command, 1), idle_test_command_done);
          g_assert_cmpuint (usb.pending->endpoint, ==, GOODIX_EP_OUT);
          fixture_complete (NULL);
        }
    }
  if (category)
    {
      guint8 actual_category, actual_command;
      memset (payload, 'R', 12);
      alias_packet (category, 1, payload, 12);
      g_assert_true (goodix_proto_rx_parse (&self->rx, &actual_category, &actual_command, &cached, &len));
      g_assert_cmpuint (actual_category, ==, category);
      g_assert_cmpuint (actual_command, ==, 1);
      g_assert_cmpmem (cached, len, payload, 12);
    }
  else
    {
      guint command = which == 0 ? 0 : (which == 1 || which == 3) ? 1 : 4;
      alias_packet (0x0a, command, version, sizeof (version));
      memcpy (expected, version, sizeof (version));
      if (!after_ack)
        {
          g_assert_cmpuint (io.completions, ==, idle ? 1 : 0);
          ack_reply (usb.pending, 0xa8);
          fixture_complete (NULL);
        }
      g_assert_true (goodix_cmd_parse_fw_version_reply (dev, &cached, &len, NULL));
      g_assert_cmpmem (cached, len, expected, sizeof (expected));
    }
  g_assert_cmpuint (io.completions, ==, idle ? 2 : 1);
  fixture_join_reader (dev);
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  g_clear_pointer (&self->rx.buf, g_free);
  g_clear_object (&action_cancel_token);
}

static void
register_command_tests (void)
{
  static const Scenario up_retry = { 0x34, 1, 2, 1, TRUE, EVENT_CANCELLED };
  static const Scenario sleep_retry = { 0x60, 1, 1, 2, TRUE, EVENT_CANCELLED };
  static const Scenario terminal = { 0x60, 2, 1, 2, TRUE, EVENT_CANCELLED };
  static const Scenario ec_terminal = { 0xae, 1, 1, 1, TRUE, EVENT_CANCELLED };
  static const Scenario sleep_duplicate_ack = { 0x60, 1, 1, 2, TRUE, DUPLICATE_SLEEP_BEFORE_EC_ACK };
  static const Scenario deadline = { 0x60, 1, 1, 2, TRUE, LATE_ACK_DEADLINE };
  static const Scenario send_io = { 0, 0, 2, 1, TRUE, SEND_IO_RETRY };
  static const Scenario send_timeout = { 0, 0, 2, 1, TRUE, SEND_TIMEOUT_RETRY };
  static const Scenario disconnect = { 0, 0, 1, 1, FALSE, SEND_DISCONNECT };
  static const Scenario send_cancel = { 0, 0, 1, 1, FALSE, SEND_CANCELLED };
  static const Scenario multicell = { 0, 0, 0, 0, TRUE, MULTICELL_DATA, 0x82 };
  static const Scenario zero_ack = { 0x34, 0, 1, 1, TRUE, ACK_ZERO_THEN_ONE };
  static const Scenario two_ack = { 0x34, 0, 1, 1, TRUE, ACK_TWO_THEN_ONE };
  static const Scenario even_retry = { 0x60, 1, 1, 2, TRUE, ACK_EVEN_TIMEOUT };
  static const Scenario even_terminal = { 0x60, 2, 1, 2, TRUE, ACK_EVEN_TIMEOUT };
  static const Scenario even_ec = { 0xae, 1, 1, 1, TRUE, ACK_EVEN_TIMEOUT };
  static const Scenario even_malformed = { 0x34, 0, 1, 1, FALSE, ACK_EVEN_THEN_MALFORMED };
  static const Scenario late_even = { 0x60, 1, 1, 2, TRUE, LATE_EVEN_ACK };
  static const Scenario late_even_deadline = { 0x60, 1, 1, 2, TRUE, LATE_EVEN_DEADLINE };
  static const Scenario manual_budget = { 0x60, 1, 0, 2, TRUE, RESPONSE_BUDGET, 0x36 };
  static const Scenario config_budget = { 0x60, 1, 0, 2, TRUE, RESPONSE_BUDGET, 0x90 };
  static const Scenario manual_deadline = { 0x60, 1, 0, 2, FALSE, RESPONSE_DEADLINE, 0x36 };
  static const Scenario config_deadline = { 0x60, 1, 0, 2, FALSE, RESPONSE_DEADLINE, 0x90 };
  static const Scenario ec_zero_ack = { 0, 0, 0, 1, TRUE, EC_LATE_ACK, 0x36, 0 };
  static const Scenario ec_one_ack = { 0, 0, 0, 1, TRUE, EC_LATE_ACK, 0x36, 1 };
  static const Scenario ec_zero_data = { 0, 0, 0, 1, TRUE, EC_LATE_DATA, 0x36, 0 };
  static const Scenario ec_one_data = { 0, 0, 0, 1, TRUE, EC_LATE_DATA, 0x36, 1 };
  const char *alias_names[] = { "a0-before-ack", "a1-before-ack", "a4-before-ack", "a1-after-ack",
                                "writers-before-ack", "writers-after-ack", "writers-idle",
                                "register-response", "psk-response" };

  for (guint i = 0; i < G_N_ELEMENTS (alias_names); i++)
    {
      g_autofree char *name = g_strdup_printf ("shared-response/%s", alias_names[i]);
      add_transport_case (name, GUINT_TO_POINTER (i), test_shared_response);
    }
  static const Scenario writes[] = {
    { 0, 0, 2, 1, TRUE, SEND_FAILED_RETRY },
    { 0, 0, 2, 1, TRUE, SEND_STALL_RETRY },
    { 0, 0, 2, 1, TRUE, SEND_INTERNAL_RETRY },
    { 0, 0, 1, 1, FALSE, WRITE_STALLED_CANCEL },
  };
  const char *write_names[] = { "transfer-error", "stall", "internal", "stalled-cancel" };
  for (guint i = 0; i < G_N_ELEMENTS (writes); i++)
    {
      g_autofree char *name = g_strdup_printf ("write/%s", write_names[i]);
      add_transport_case (name, &writes[i], test_scenario);
    }
  static const Scenario responses[] = {
    { 0, 0, 0, 1, TRUE, RESPONSE_EARLY, 0x36 },
    { 0, 0, 0, 1, TRUE, RESPONSE_EARLY, 0x90 },
    { 0, 0, 0, 1, TRUE, RESPONSE_RETRY, 0x36 },
    { 0, 0, 0, 1, TRUE, RESPONSE_RETRY, 0x90 },
    { 0, 0, 0, 1, TRUE, RESPONSE_EARLY_RESET, 0x36 },
    { 0, 0, 0, 1, TRUE, RESPONSE_EARLY_RESET, 0x90 },
    { 0, 0, 0, 1, TRUE, RESPONSE_STATUS, 0x90, 0 },
    { 0, 0, 0, 1, TRUE, RESPONSE_STATUS, 0x90, 1 },
    { 0, 0, 0, 1, TRUE, RESPONSE_STATUS, 0x90, 2 },
    { 0, 0, 0, 1, TRUE, RESPONSE_DUPLICATE, 0x36 },
    { 0, 0, 0, 1, TRUE, RESPONSE_DUPLICATE, 0x90 },
    { 0x36, 0, 1, 1, TRUE, RESPONSE_HANDOFF },
    { 0x90, 0, 1, 1, TRUE, RESPONSE_HANDOFF },
  };
  const char *response_names[] = {
    "manual-early", "config-early", "manual-response-retry", "config-response-retry",
    "manual-ready-reset", "config-ready-reset", "config-status-zero", "config-status-one",
    "config-status-two",
    "manual-duplicate", "config-duplicate",
    "manual-reverse-up-handoff", "config-reverse-up-handoff",
  };
  for (guint i = 0; i < G_N_ELEMENTS (responses); i++)
    {
      g_autofree char *name = g_strdup_printf ("responses/%s", response_names[i]);
      add_transport_case (name, &responses[i], test_scenario);
    }
  add_transport_case ("up-ack-retry", &up_retry, test_scenario);
  add_transport_case ("sleep-ack-retry", &sleep_retry, test_scenario);
  add_transport_case ("terminal-sleep-timeout", &terminal, test_scenario);
  add_transport_case ("terminal-ec-timeout", &ec_terminal, test_scenario);
  add_transport_case ("late-sleep-ack-before-ec-ack", &sleep_duplicate_ack, test_scenario);
  add_transport_case ("late-ack-deadline", &deadline, test_scenario);
  add_transport_case ("send-io-retry", &send_io, test_scenario);
  add_transport_case ("send-timeout-retry", &send_timeout, test_scenario);
  add_transport_case ("send-disconnect-no-retry", &disconnect, test_scenario);
  add_transport_case ("send-cancel-no-retry", &send_cancel, test_scenario);
  add_transport_case ("ordinary-data-continuations", &multicell, test_scenario);
  add_transport_case ("ack-polling/zero-then-one", &zero_ack, test_scenario);
  add_transport_case ("ack-polling/two-then-one", &two_ack, test_scenario);
  add_transport_case ("ack-polling/exhaustion-retry", &even_retry, test_scenario);
  add_transport_case ("ack-polling/exhaustion-terminal", &even_terminal, test_scenario);
  add_transport_case ("ack-polling/ec-no-retry", &even_ec, test_scenario);
  add_transport_case ("ack-polling/malformed-no-retry", &even_malformed, test_scenario);
  add_transport_case ("ack-polling/late-even-ack", &late_even, test_scenario);
  add_transport_case ("ack-polling/late-even-deadline", &late_even_deadline, test_scenario);
  add_transport_case ("budgets/manual-response", &manual_budget, test_scenario);
  add_transport_case ("budgets/config-response", &config_budget, test_scenario);
  add_transport_case ("budgets/manual-deadline", &manual_deadline, test_scenario);
  add_transport_case ("budgets/config-deadline", &config_deadline, test_scenario);
  add_transport_case ("ec/late-zero-before-ack", &ec_zero_ack, test_scenario);
  add_transport_case ("ec/late-one-before-ack", &ec_one_ack, test_scenario);
  add_transport_case ("ec/late-zero-before-data", &ec_zero_data, test_scenario);
  add_transport_case ("ec/late-one-before-data", &ec_one_data, test_scenario);
}
