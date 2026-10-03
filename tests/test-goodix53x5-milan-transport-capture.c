/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* FDT delivery, arm repair, completed-capture and cancellation ownership. */

static void
capture_setup (FpDevice *dev, GoodixMilanGeneration *generation)
{
  g_assert_true (generation == FPI_DEVICE_GOODIX53X5 (dev)->milan_generation);
  GOODIX53X5_DEBUG_ONLY (
    g_assert_cmpuint (generation->use_count, ==, io.captures);
                        )
}

static gboolean
rearm_case (const Scenario *scenario)
{
  return scenario->schedule == EARLY_REARM_REVERSE ||
         scenario->schedule == TWO_EARLY_REVERSE;
}

static gboolean
down_drain_case (const Scenario *scenario)
{
  return scenario->schedule == DOWN_BEFORE_SLEEP_ACK ||
         scenario->schedule == REVERSE_BEFORE_SLEEP_ACK;
}

static gboolean
stop_state_case (const Scenario *scenario)
{
  return down_drain_case (scenario) || scenario->schedule == EVENT_BEFORE_SLEEP_ACK ||
         scenario->schedule == STOP_DRAIN_CONTROL;
}

static void
reverse_event (FpiUsbTransfer *transfer, guint ordinal)
{
  guint8 payload[4 + GOODIX_FDT_BASE_LEN] = { 0x80, 0, 0, 0 };

  for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
    payload[4 + 2 * i] = 100 + 2 * i + 2 * ordinal;
  reply (transfer, 3, 1, payload, sizeof (payload));
  io.events++;
}

static void
up_event (FpiUsbTransfer *transfer)
{
  guint8 payload[4 + GOODIX_FDT_BASE_LEN] = { 0, 2 };

  for (guint i = 0; i < GOODIX_FDT_BASE_LEN; i++)
    payload[4 + i] = 3 * i + 1;
  reply (transfer, 3, 2, payload, sizeof (payload));
  io.events++;
}

static void
stop_after_capture (FpDevice *dev)
{
  g_assert_cmpuint (io.captures, ==, 1);
  g_assert_false (io.disposition_sent);
  io.disposition_sent = TRUE;
  goodix_scan_set_disposition (dev, GOODIX_SCAN_DISPOSITION_AUTH_SUCCESS, NULL);
}

static gboolean
cancel_arm_case (const Scenario *scenario)
{
  return scenario->schedule == CANCEL_ARM_FIRST ||
         scenario->schedule == CANCEL_ARM_REPEAT ||
         scenario->schedule == CANCEL_ARM_CONFIG;
}

static GError *
capture_event_reply (FpiUsbTransfer *transfer, GCancellable *cancel)
{
  const Scenario *scenario = io.scenario;
  GError *error = NULL;

  if (scenario->standalone_arm)
    {
      if (io.duplicates == 0)
        {
          io.duplicates++;
          ack_reply (transfer, scenario->standalone_arm);
        }
      else
        {
          guint8 payload[4 + GOODIX_FDT_BASE_LEN] = { 0 };
          guint16 irq = scenario->standalone_arm == 0x32 ? 2 : 0x200;
          payload[0] = irq & 0xff;
          payload[1] = irq >> 8;
          for (guint i = 0; i < GOODIX_FDT_BASE_LEN; i++)
            payload[4 + i] = 3 * i + 1;
          reply (transfer, 3, (scenario->standalone_arm & 0xf) >> 1,
                 payload, sizeof (payload));
          io.events++;
        }
    }
  else if (scenario->schedule == EVENT_COMPLETES_DURING_CANCEL && io.events == 0)
    {
      up_event (transfer);
    }
  else
    {
      g_assert_nonnull (cancel);
      g_assert_true (g_cancellable_is_cancelled (cancel));
      io.cancellations++;
      error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Scheduled event cancellation");
    }
  return error;
}

static GError *
cancel_arm_reply (FpiUsbTransfer *transfer)
{
  const Scenario *scenario = io.scenario;
  GError *error = NULL;
  gboolean config = io.command == 0x90;
  gboolean cancel_now = !io.action_cancelled &&
                        ((io.command == 0x34 &&
                          (scenario->schedule == CANCEL_ARM_FIRST ||
                           (scenario->schedule == CANCEL_ARM_REPEAT && io.sends[0x90]))) ||
                         (config && io.ec_data && scenario->schedule == CANCEL_ARM_CONFIG));

  if (cancel_now)
    {
      io.action_cancelled = TRUE;
      g_cancellable_cancel (FPI_DEVICE_GOODIX53X5 (transfer->device)->cancel);
    }
  if (io.command == 0x60 && scenario->schedule != CANCEL_ARM_CONFIG && !io.events)
    {
      up_event (transfer);
    }
  else if (config && io.ec_data)
    {
      guint8 status = 0;
      reply (transfer, 9, 0, &status, 1);
    }
  else
    {
      guint8 ack[] = { io.command, io.command == 0x34 && !io.sends[0x90] ?
                       scenario->ec_status : 1 };
      reply (transfer, 0xb, 0, ack, sizeof (ack));
      io.ec_data = config;
    }
  return error;
}

static GError *
repair_arm_reply (FpiUsbTransfer *transfer)
{
  const Scenario *scenario = io.scenario;
  GError *error = NULL;
  gboolean config = io.command == 0x90;
  gboolean repeated = io.sends[0x90] != 0;

  if (config && scenario->schedule == ARM_CONFIG_PROTO)
    {
      reply (transfer, 0xb, 0, &io.command, 1);
    }
  else if (config && scenario->schedule == ARM_CONFIG_CANCEL)
    {
      io.action_cancelled = TRUE;
      g_cancellable_cancel (FPI_DEVICE_GOODIX53X5 (transfer->device)->cancel);
      g_cancellable_cancel (action_cancel_token);
      error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Scheduled repair cancellation");
    }
  else if (scenario->schedule == ARM_FIRST_FAIL ||
           (config && (scenario->schedule == ARM_CONFIG_FAIL ||
                       (scenario->schedule == ARM_CONFIG_DATA_FAIL && io.ec_data))) ||
           (!config && repeated && scenario->schedule == ARM_REPEAT_FAIL) ||
           (!config && scenario->schedule == ARM_MAX && (io.sends[io.command] & 1)))
    {
      test_clock_us += usb.timeout * 1000;
      error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                   "Scheduled arm recovery timeout");
    }
  else if (config && scenario->schedule == ARM_REFRESH && io.events < 2)
    {
      reverse_event (transfer, io.events);
    }
  else if (config && io.ec_data)
    {
      guint8 status = 0;
      reply (transfer, 9, 0, &status, 1);
    }
  else
    {
      guint8 ack[] = { io.command, config ? 1 :
                       repeated ? (scenario->schedule == ARM_REPEAT_STATUS ? 3 : 1) :
                       scenario->ec_status };
      reply (transfer, 0xb, 0, ack, sizeof (ack));
      io.ec_data = config;
    }
  return error;
}

static void
complete_usb (void)
{
  FpiUsbTransfer *transfer = usb.pending;

  g_autoptr(FpDevice) dev = g_object_ref (transfer->device);
  GCancellable *cancel = usb.cancel;
  GError *error = NULL;
  const Scenario *scenario = io.scenario;
  guint events_before = io.events;

  if (down_drain_case (scenario) && io.command == 0x32 &&
      transfer->endpoint == GOODIX_EP_IN && !io.disposition_sent)
    stop_after_capture (transfer->device);

  g_assert_nonnull (transfer);
  /* Request stop with the up-arm ACK still outstanding, except for the
   * separately controlled event-completion/cancellation boundary. */
  if (!scenario->standalone_arm && !rearm_case (scenario) && !io.disposition_sent &&
      !cancel_arm_case (scenario) &&
      scenario->schedule != RESPONSE_HANDOFF &&
      scenario->schedule != EVENT_BEFORE_ARM_ACK &&
      transfer->endpoint == GOODIX_EP_IN &&
      io.command == 0x34 &&
      (scenario->schedule != EVENT_COMPLETES_DURING_CANCEL || usb.timeout == 0))
    stop_after_capture (transfer->device);
  if (!io.disposition_sent && scenario->schedule == EVENT_BEFORE_ARM_ACK &&
      transfer->endpoint == GOODIX_EP_IN && io.command == 0x32)
    stop_after_capture (transfer->device);

  if (scenario->schedule == CANCEL_DURING_RETRY && io.command == 0x34 &&
      io.sends[0x34] == 2 && !io.action_cancelled)
    {
      io.action_cancelled = TRUE;
      g_cancellable_cancel (FPI_DEVICE_GOODIX53X5 (transfer->device)->cancel);
      g_cancellable_cancel (action_cancel_token);
    }

  if (!FPI_DEVICE_GOODIX53X5 (transfer->device)->transport)
    {
      g_assert_nonnull (cancel);
      g_assert_true (g_cancellable_is_cancelled (cancel));
      error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Scheduled idle receive join");
    }
  else if (transfer->endpoint == GOODIX_EP_OUT)
    {
      error = complete_write (transfer, cancel);
    }
  else if (usb.timeout == 0)
    {
      error = capture_event_reply (transfer, cancel);
    }
  else if (cancel_arm_case (scenario))
    {
      error = cancel_arm_reply (transfer);
    }
  else if (arm_repair_case (scenario))
    {
      error = repair_arm_reply (transfer);
    }
  else
    {
      error = command_reply (transfer);
    }

  fixture_complete (error);
  if (rearm_case (scenario) && io.events > events_before)
    {
      FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
      memcpy (io.packet_down[events_before], self->profile9_fdt.base_down, GOODIX_FDT_BASE_LEN);
      memcpy (io.packet_manual[events_before], self->profile9_fdt.base_manual, GOODIX_FDT_BASE_LEN);
    }
}

static void
capture_ready (FpDevice *dev, gpointer unused)
{
  (void) dev;
  (void) unused;
  io.captures++;
}

static void
boundary_handler (FpiSsm *ssm, FpDevice *dev)
{
  GoodixScanCoordinatorData *data = fpi_ssm_get_data (ssm);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gboolean handoff = io.scenario->schedule == RESPONSE_HANDOFF;

  if (fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_WAIT_CPU &&
      (rearm_case (io.scenario) || handoff))
    {
      io.wait_cpu_count++;
      memcpy (io.settled_down, self->profile9_fdt.base_down, sizeof (io.settled_down));
      memcpy (io.settled_manual, self->profile9_fdt.base_manual, sizeof (io.settled_manual));
      memcpy (io.settled_prior, data->prior_down, sizeof (io.settled_prior));
      g_assert_false (data->cpu_done);
      g_assert_true (data->cpu_outstanding);
    }
  if (fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_DISPATCH_EVENT)
    {
      io.dispatches++;
      if (handoff)
        {
          g_assert_cmpuint (self->profile9_fdt.wait_mode, ==, GOODIX_PROFILE9_FDT_WAIT_UP);
          g_assert_true (self->pending_fdt.event.pending);
        }
    }
  /* Model the completed-capture boundary after a response command. Both
   * reverse events arrive during that command; the real coordinator then
   * arms UP and consumes the latest DOWN notification, before CPU settlement. */
  if (handoff && fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_ENSURE_REFERENCE)
    {
      self->profile9_fdt.wait_mode = GOODIX_PROFILE9_FDT_WAIT_DOWN;
      send_response_command (ssm, dev, io.scenario->timeout_command);
      return;
    }
  if (handoff && fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_POWER_ON)
    {
      fpi_ssm_jump_to_state (ssm, GOODIX_SCAN_COORD_ARM_UP);
      return;
    }
  if (fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_ENSURE_REFERENCE)
    fpi_ssm_jump_to_state (ssm, (rearm_case (io.scenario) || down_drain_case (io.scenario)) ?
                           GOODIX_SCAN_COORD_REARM_DOWN : GOODIX_SCAN_COORD_ARM_UP);
  else
    goodix_scan_coordinator_handler (ssm, dev);
}

/* The two arm-event-wait cases use the public command/receive boundary rather
 * than inventing a second capture cycle to reach a down-arm wait. */
static void
arm_event_done (FpDevice *dev, const GoodixTransportResult *result,
                GError *error, gpointer data)
{
  if (error)
    fpi_ssm_mark_failed (data, error);
  else
    fpi_ssm_next_state (data);
}

static void
arm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gint state = fpi_ssm_get_cur_state (ssm);

  if (io.scenario->schedule == SAME_COMMAND_PRECEDENCE)
    {
      if (state == 1)
        {
          goodix_cmd_fdt_up_setup (ssm, dev, self->profile9_fdt.base_up);
          return;
        }
      if (state > 1)
        state--;
    }
  switch (state)
    {
    case 0:
      self->profile9_fdt.wait_mode = io.scenario->standalone_arm == 0x32 ?
                                     GOODIX_PROFILE9_FDT_WAIT_DOWN : GOODIX_PROFILE9_FDT_WAIT_UP;
      if (io.scenario->standalone_arm == 0x32)
        goodix_cmd_fdt_down_setup (ssm, dev, self->profile9_fdt.base_down);
      else
        goodix_cmd_fdt_up_setup (ssm, dev, self->profile9_fdt.base_up);
      break;

    case 1:
      if (arm_repair_case (io.scenario) && self->pending_fdt.event.pending)
        fpi_ssm_next_state (ssm);
      else
        goodix_transport_wait_event (dev, self->profile9_fdt.wait_mode, arm_event_done, ssm);
      break;

    case 2:
      {
        GoodixFdtEventType type;
        guint16 prior_down[GOODIX_PROFILE9_FDT_AREA_COUNT];
        GError *error = NULL;
        if (!goodix_recv_select_fdt (dev, &type, &self->profile9_fdt.event,
                                     prior_down, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
          }
        else
          {
            io.dispatches++;
            fpi_ssm_mark_completed (ssm);
          }
      }
      break;
    }
}

static void
arm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->profile9_fdt.owner = NULL;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED;
  boundary_done (ssm, dev, error);
}

static void
boundary_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  (void) ssm;
  /* The action returns as soon as its CPU work joined; the coordinator may
   * still own the hardware for the deactivation tail. */
  if (self->profile9_fdt.owner)
    g_assert_cmpuint (self->profile9_fdt.lifecycle, ==,
                      GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPING);
  else
    g_assert_cmpuint (self->profile9_fdt.lifecycle, ==,
                      GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED);
  io.completions++;
  g_assert_cmpuint (io.completions, ==, 1);
  io.error = error;
}

static void
parent_handler (FpiSsm *ssm, FpDevice *dev)
{
  (void) dev;
  if (fpi_ssm_get_cur_state (ssm) == 0)
    fpi_ssm_start (fpi_ssm_get_data (ssm), goodix_scan_coordinator_done);
  else
    fpi_ssm_mark_completed (ssm);
}

static void
idle_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_assert_null (self->transport);
}

static void
maintenance_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->profile9_fdt.owner = NULL;
  self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED;
  self->service_active = FALSE;
  if (!io.error)
    io.error = error;
  else
    g_clear_error (&error);
}

static void
test_scenario (gconstpointer user_data)
{
  const Scenario *scenario = user_data;

  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceGoodix53x5 *self;
  GoodixScanCoordinatorData *data;
  FpiSsm *ssm;
  FpiSsm *parent;

  memset (&io, 0, sizeof (io));
  io.scenario = scenario;
  dev = fixture_device_new ();
  self = FPI_DEVICE_GOODIX53X5 (dev);
  self->cancel = g_cancellable_new ();
  self->session_cancel = g_cancellable_new ();

  /* Explicit abstraction: an admitted frame has already been captured. No
   * preprocessing, extraction, match score or authentication is fabricated.
   * The test owns only the subsequent USB/scan scheduling and final status. */
  self->milan_sensor_subtype = 12;
  self->milan_generation = g_new0 (GoodixMilanGeneration, 1);
  self->milan_generation->admitted = TRUE;
  self->captured_raw_image = g_new0 (guint16, GOODIX_SENSOR_PIXELS);
  self->profile9_fdt.base_valid = TRUE;
  self->profile9_fdt.drift_anchor_empty = TRUE;
  self->calib.delta_down = 30;
  if (arm_repair_case (scenario))
    io.duplicates = 1; /* These controls need no synthetic late arm ACK. */
  if (stop_state_case (scenario))
    {
      self->profile9_fdt.drift_anchor_empty = FALSE;
      memset (self->profile9_fdt.base_down, 45, GOODIX_FDT_BASE_LEN);
      memset (self->profile9_fdt.base_up, 60, GOODIX_FDT_BASE_LEN);
      memset (self->profile9_fdt.base_manual, 70, GOODIX_FDT_BASE_LEN);
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        {
          self->fdt_prior_down[i] = 0x2222;
          self->profile9_fdt.drift_anchor[i] = 31 + i;
        }
    }
  if (scenario->standalone_arm)
    {
      ssm = scenario->schedule == MULTICELL_DATA ?
            fpi_ssm_new (dev, data_handler, 2) :
            response_case (scenario) ? fpi_ssm_new (dev, response_handler, 5) :
            fpi_ssm_new (dev, arm_handler,
                         scenario->schedule == SAME_COMMAND_PRECEDENCE ? 4 : 3);
      self->profile9_fdt.owner = ssm;
      self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
      fpi_ssm_start (ssm, arm_done);
    }
  else
    {
      data = g_new0 (GoodixScanCoordinatorData, 1);
      ssm = fpi_ssm_new_full (dev, boundary_handler, GOODIX_SCAN_COORD_NUM_STATES,
                              GOODIX_SCAN_COORD_CLEANUP_JOIN, "transport-boundary");
      data->ssm = ssm;
      parent = fpi_ssm_new (dev, parent_handler, 2);
      data->parent_ssm = parent;
      fpi_ssm_set_data (parent, ssm, NULL);
      data->capture_ready = capture_ready;
      data->dispatching = TRUE;
      data->action_cancel = g_object_ref (self->cancel);
      if (rearm_case (scenario) || down_drain_case (scenario))
        {
          /* Prior capture and up-release have completed; CPU publication has
          * not. B0 is a programmed base distinct from either early event. */
          data->cycle_active = TRUE;
          data->release_settled = TRUE;
          data->cpu_outstanding = TRUE;
          io.captures = 1;
          self->milan_generation->use_count = 1;
          memset (self->profile9_fdt.base_down, 45, GOODIX_FDT_BASE_LEN);
        }
      fpi_ssm_set_data (ssm, data, (GDestroyNotify) goodix_scan_coordinator_data_free);
      self->profile9_fdt.owner = ssm;
      self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
      fpi_ssm_start (parent, boundary_done);
      if (self->profile9_fdt.owner == ssm)
        data->action_cancel_id = g_cancellable_connect (
          data->action_cancel, G_CALLBACK (goodix_scan_action_cancelled), data, NULL);
    }
  /* Drive until the action boundary completes and, for coordinator cases,
   * the detached deactivation tail has released the hardware as well. */
  for (guint step = 0;
       (io.completions == 0 || (!scenario->standalone_arm && self->profile9_fdt.owner)) &&
       step < 48; step++)
    {
      if (!self->transport && cancel_arm_case (scenario) && !io.disposition_sent &&
          self->profile9_fdt.owner &&
          fpi_ssm_get_cur_state (self->profile9_fdt.owner) == GOODIX_SCAN_COORD_WAIT_CPU)
        stop_after_capture (dev);
      if (!self->transport && (rearm_case (scenario) || scenario->schedule == RESPONSE_HANDOFF) &&
          io.wait_cpu_count && !io.disposition_sent)
        stop_after_capture (dev);
      if (!self->transport && !scenario->standalone_arm && self->profile9_fdt.owner &&
          fpi_ssm_get_cur_state (self->profile9_fdt.owner) >= GOODIX_SCAN_COORD_CLEANUP_JOIN &&
          !io.disposition_sent)
        stop_after_capture (dev); /* Join the deferred CPU callback on failure. */
      if (io.completions && (scenario->standalone_arm || !self->profile9_fdt.owner))
        break;
      if (!self->transport && !self->reader->joined)
        {
          g_assert_true (g_main_context_pending (NULL));
          g_main_context_iteration (NULL, FALSE);
          continue;
        }
      complete_usb ();
    }

  g_assert_cmpuint (io.completions, ==, 1);
  g_assert_null (self->profile9_fdt.owner);
  g_assert_cmpuint (self->profile9_fdt.lifecycle, ==,
                    GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED);
  if (!scenario->standalone_arm && !stop_state_case (scenario) &&
      !cancel_arm_case (scenario) && self->pending_fdt.event.pending &&
      self->pending_fdt.type == GOODIX_FDT_EVENT_DEACTIVATE)
    {
      /* Foreground completion precedes the independent delayed EC worker.
       * Keep the original EC reply/deadline schedules on that actual owner. */
      data = g_new0 (GoodixScanCoordinatorData, 1);
      ssm = fpi_ssm_new_full (dev, goodix_scan_coordinator_handler,
                              GOODIX_SCAN_COORD_NUM_STATES,
                              GOODIX_SCAN_COORD_CLEANUP_JOIN, "deactivate-worker");
      data->ssm = ssm;
      data->idle = TRUE;
      self->service_active = TRUE;
      self->profile9_fdt.owner = ssm;
      self->profile9_fdt.lifecycle = GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE;
      fpi_ssm_set_data (ssm, data, (GDestroyNotify) goodix_scan_coordinator_data_free);
      fpi_ssm_start (ssm, maintenance_done);
      for (guint step = 0; self->profile9_fdt.owner && step < 32; step++)
        {
          if (fpi_ssm_get_cur_state (ssm) == GOODIX_SCAN_COORD_WAIT_EVENT)
            goodix_scan_join_service (dev);
          if (!self->transport)
            g_main_context_iteration (NULL, TRUE);
          else
            complete_usb ();
        }
      g_assert_null (self->profile9_fdt.owner);
    }
  if (self->reader)
    {
      /* Action completion no longer closes the handle-owned idle receiver.
       * Exercise its explicit join before retaining the original owner checks. */
      goodix_transport_quiesce (dev, idle_joined, NULL);
      fixture_refresh_wait ();
      complete_usb ();
    }
  g_assert_null (usb.pending);
  g_assert_null (self->transport);
  g_assert_cmpuint (io.captures, ==, scenario->standalone_arm ? 0 : 1);
  g_test_message ("up=%u sleep=%u cancel=%u events=%u final=%s",
                  io.sends[0x34], io.sends[0x60], io.cancellations, io.events,
                  io.error ? io.error->message : "success");
  /* Report contract differences without aborting, so every scheduled case
   * releases its owners and the complete suite can expose baseline failures. */
  gboolean cancelled = scenario->schedule == CANCEL_DURING_RETRY ||
                       scenario->schedule == WRITE_STALLED_CANCEL ||
                       cancel_arm_case (scenario) ||
                       scenario->schedule == ARM_CONFIG_CANCEL;
  gboolean delivered = (scenario->standalone_arm && !arm_repair_case (scenario) &&
                        scenario->schedule != MULTICELL_DATA &&
                        !response_case (scenario)) ||
                       scenario->schedule == EVENT_BEFORE_ARM_ACK ||
                       scenario->schedule == EVENT_COMPLETES_DURING_CANCEL;
  gboolean duplicate = (scenario->standalone_arm && scenario->schedule != MULTICELL_DATA &&
                        !(response_command_case (scenario) || arm_repair_case (scenario))) ||
                       scenario->schedule == DUPLICATE_SLEEP_BEFORE_EC_ACK;
  if (rearm_case (scenario))
    {
      gboolean two = scenario->schedule == TWO_EARLY_REVERSE;
      if (io.wait_cpu_count != 1 || io.dispatches != 1 ||
          io.events != (two ? 2 : 1) || io.sends[0x32] != (two ? 3 : 2) ||
          self->profile9_fdt.event.irq != 0x80 ||
          self->profile9_fdt.event.touch_flag != 0 ||
          fp_device_get_finger_status (dev) != FP_FINGER_STATUS_NONE)
        g_test_fail ();
      /* Native transform: ((sample / 2) * 0x101) modulo 16 bits. These
       * chosen samples stay below wrapping; both programmed bytes equal q.
       * R2's prior/manual snapshot must be transform(R1), not original B0. */
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        {
          guint8 prior = two ? 50 + i : 45;
          guint8 current = 50 + i + two;
          if (io.settled_prior[i] != prior ||
              io.settled_manual[2 * i] != prior ||
              io.settled_manual[2 * i + 1] != prior ||
              io.settled_down[2 * i] != current ||
              io.settled_down[2 * i + 1] != current ||
              io.last_down_payload[2 * i] != current ||
              io.last_down_payload[2 * i + 1] != current ||
              self->profile9_fdt.event.raw[2 * i] != 100 + 2 * i + 2 * two ||
              self->profile9_fdt.event.raw[2 * i + 1] != 0)
            g_test_fail ();
          for (guint packet = 0; packet < (two ? 2 : 1); packet++)
            {
              guint8 packet_prior = packet ? 50 + i : 45;
              guint8 packet_current = 50 + i + packet;
              if (io.packet_down[packet][2 * i] != packet_current ||
                  io.packet_down[packet][2 * i + 1] != packet_current ||
                  io.packet_manual[packet][2 * i] != packet_prior ||
                  io.packet_manual[packet][2 * i + 1] != packet_prior)
                g_test_fail ();
            }
        }
      g_test_message ("rearm events=%u dispatch=%u wait_cpu=%u down_sends=%u prior0=%u manual0=%u down0=%u",
                      io.events, io.dispatches, io.wait_cpu_count, io.sends[0x32],
                      io.settled_prior[0], io.settled_manual[0], io.settled_down[0]);
      g_test_message ("packet mutations R1 down/manual=%u/%u R2 down/manual=%u/%u",
                      io.packet_down[0][0], io.packet_manual[0][0],
                      io.packet_down[1][0], io.packet_manual[1][0]);
    }
  gboolean excluded_send = scenario->schedule == SEND_DISCONNECT ||
                           scenario->schedule == SEND_CANCELLED || scenario->schedule == EARLIER_CLEANUP_ERROR;
  if (cancel_arm_case (scenario))
    {
      gboolean armed = scenario->schedule != CANCEL_ARM_CONFIG;

      if (io.dispatches || io.events != armed ||
          io.sends[0x90] != (scenario->ec_status == 3) ||
          io.sends[0x32] || !self->pending_fdt.event.pending ||
          self->pending_fdt.type != (armed ? GOODIX_FDT_EVENT_UP : GOODIX_FDT_EVENT_DEACTIVATE))
        g_test_fail ();
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        {
          guint16 sample = (6 * i + 1) | ((6 * i + 4) << 8);
          guint16 expected = armed ? (sample / 2) * 0x101 : 0;

          if (self->profile9_fdt.base_down[2 * i] != (expected & 0xff) ||
              self->profile9_fdt.base_down[2 * i + 1] != (expected >> 8))
            g_test_fail ();
        }
    }
  gboolean malformed = scenario->schedule == ACK_EVEN_THEN_MALFORMED ||
                       scenario->schedule == ARM_CONFIG_PROTO ||
                       scenario->schedule == CLEANUP_LATE_PROTO;
  if (stop_state_case (scenario))
    {
      gboolean down = scenario->schedule == DOWN_BEFORE_SLEEP_ACK;
      gboolean reverse = scenario->schedule == REVERSE_BEFORE_SLEEP_ACK;
      gboolean up = scenario->schedule == EVENT_BEFORE_SLEEP_ACK;

      if (io.events != (down || reverse || up) || io.dispatches ||
          io.cancellations != 1 || self->profile9_fdt.event.pending ||
          !self->pending_fdt.event.pending || !self->profile9_fdt.base_valid ||
          self->profile9_fdt.drift_anchor_empty)
        g_test_fail ();
      g_assert_cmpint (self->pending_fdt.type, ==,
                       down ? GOODIX_FDT_EVENT_DOWN : reverse ? GOODIX_FDT_EVENT_REVERSE :
                       up ? GOODIX_FDT_EVENT_UP : GOODIX_FDT_EVENT_DEACTIVATE);
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        {
          /* Up uses the existing fixture's consecutive bytes; reverse/down
           * use samples 100,102,... . Expected words are independent formulas. */
          guint16 sample = (6 * i + 1) | ((6 * i + 4) << 8);
          guint16 expected_down = up ? (guint16) ((sample >> 1) * 257) :
                                  reverse ? (50 + i) * 257 : 45 * 257;
          guint16 expected_up = down ? (80 + i) * 257 : 60 * 257;
          guint8 expected_manual = reverse ? 45 : 70;

          if (self->profile9_fdt.base_down[2 * i] != (expected_down & 0xff) ||
              self->profile9_fdt.base_down[2 * i + 1] != (expected_down >> 8) ||
              self->profile9_fdt.base_up[2 * i] != (expected_up & 0xff) ||
              self->profile9_fdt.base_up[2 * i + 1] != (expected_up >> 8) ||
              self->profile9_fdt.base_manual[2 * i] != expected_manual ||
              self->profile9_fdt.base_manual[2 * i + 1] != expected_manual ||
              self->fdt_prior_down[i] != (reverse ? 45 : 0x2222) ||
              self->profile9_fdt.drift_anchor[i] != 31 + i)
            g_test_fail ();
        }
    }
  if (response_case (scenario) && !(response_command_case (scenario) || arm_repair_case (scenario)) &&
      (io.sends[scenario->standalone_arm] != (scenario->schedule == RESPONSE_DEADLINE ? 2 : 1) ||
       io.data_chunks != (scenario->schedule == RESPONSE_DEADLINE ? 2 : 1) || io.events || io.dispatches))
    g_test_fail ();
  if (response_command_case (scenario) &&
      scenario->schedule != RESPONSE_HANDOFF &&
      (io.sends[scenario->standalone_arm] !=
       (scenario->schedule == RESPONSE_RETRY || scenario->schedule == RESPONSE_EARLY_RESET ? 2 : 1) ||
       io.events || io.dispatches))
    g_test_fail ();
  if (scenario->schedule == RESPONSE_EARLY_RESET && io.data_chunks != 2)
    g_test_fail ();
  if (scenario->schedule == RESPONSE_HANDOFF)
    {
      if (io.events != 2 || io.dispatches != 1 || io.wait_cpu_count != 1 ||
          io.sends[scenario->timeout_command] != 1 || io.sends[0x32] != 1 ||
          self->pending_fdt.event.pending || self->profile9_fdt.event.irq != 0x80)
        g_test_fail ();
      for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
        if (io.settled_prior[i] != 50 + i ||
            io.settled_manual[2 * i] != 50 + i ||
            io.settled_manual[2 * i + 1] != 50 + i ||
            io.settled_down[2 * i] != 51 + i ||
            io.settled_down[2 * i + 1] != 51 + i ||
            io.last_down_payload[2 * i] != 51 + i ||
            io.last_down_payload[2 * i + 1] != 51 + i ||
            self->profile9_fdt.event.raw[2 * i] != 102 + 2 * i ||
            self->profile9_fdt.event.raw[2 * i + 1] != 0)
          g_test_fail ();
      g_test_message ("handoff dispatch=%u wait_cpu=%u prior/manual/down=%u/%u/%u",
                      io.dispatches, io.wait_cpu_count, io.settled_prior[0],
                      io.settled_manual[0], io.settled_down[0]);
    }
  if (polling_case (scenario) &&
      (io.even_followups != io.sends[scenario->timeout_command] ||
       (scenario->timeout_command == 0xae && io.sends[0xae] != 1)))
    g_test_fail ();
  if (scenario->schedule == LATE_EVEN_ACK &&
      (io.duplicates != 1 || io.expected_acks != 1 || io.sends[0xae] != 1))
    g_test_fail ();
  if (malformed && !scenario->standalone_arm && io.disposition_sent &&
      scenario->schedule != CLEANUP_LATE_PROTO)
    {
      /* A protocol failure after the comparison joins the same rule as a
       * failed send: the positive result stands, the session reconstructs.
       * The later independent EC worker still reports its own failure. */
      if (io.error || !self->needs_reinit)
        g_test_fail ();
    }
  else if (malformed && !g_error_matches (io.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO))
    g_test_fail ();
  if (delivered && io.dispatches == 1)
    for (guint i = 0; i < GOODIX_FDT_BASE_LEN; i++)
      if (self->profile9_fdt.event.raw[i] != 3 * i + 1)
        g_test_fail ();
  gboolean exhausted_arm = scenario->schedule == ARM_REPEAT_FAIL ||
                           scenario->schedule == ARM_FIRST_FAIL;
  if (scenario->schedule == WRITE_STALLED_CANCEL &&
      (io.started_writes != 3 || io.precancelled_writes != 0 || io.cancelled_writes != 0))
    g_test_fail ();
  if (arm_repair_case (scenario))
    {
      guint arms = malformed || cancelled ? 1 : scenario->schedule == ARM_MAX ? 4 :
                   scenario->schedule == ARM_REPEAT_FAIL ? 3 :
                   scenario->schedule == ARM_FIRST_FAIL ? 2 :
                   scenario->ec_status == 1 ? 1 : 2;
      guint configs = scenario->schedule == ARM_CONFIG_FAIL ||
                      scenario->schedule == ARM_CONFIG_DATA_FAIL ? 2 :
                      scenario->ec_status == 1 || scenario->schedule == ARM_FIRST_FAIL ? 0 : 1;
      if (io.sends[scenario->standalone_arm] != arms || io.sends[0x90] != configs ||
          io.events != (malformed || cancelled ? 0 : scenario->schedule == ARM_REFRESH ? 2 : 1))
        g_test_fail ();
      if (scenario->schedule == ARM_REFRESH)
        for (guint i = 0; i < GOODIX_PROFILE9_FDT_AREA_COUNT; i++)
          if (io.last_down_payload[2 * i] != 51 + i || io.last_down_payload[2 * i + 1] != 51 + i)
            g_test_fail ();
    }
  if (io.sends[0x34] != scenario->expected_up_sends ||
      io.sends[0x60] != scenario->expected_sleep_sends ||
      (scenario->standalone_arm == 0x32 && !arm_repair_case (scenario) && io.sends[0x32] != 2) ||
      (delivered && (io.events != 1 || io.dispatches != 1)) ||
      (duplicate && io.duplicates != 1) ||
      (scenario->schedule == MULTICELL_DATA && (io.data_chunks != 3 || io.sends[0x82] != 1)) ||
      (scenario->schedule == EVENT_BEFORE_ARM_ACK && io.sends[0x32] != 1) ||
      (scenario->schedule == EVENT_BEFORE_SLEEP_ACK && io.events != 1) ||
      ((scenario->schedule == LATE_ACK_DEADLINE ||
        scenario->schedule == LATE_EVEN_DEADLINE) &&
       (io.deadline_violation || io.expected_acks || io.duplicates != 1 ||
        test_clock_us - io.ec_ack_started != ack_budget (0xae) * 1000LL || io.sends[0xae] != 1)) ||
      (scenario->success && (io.error || (self->needs_reinit && !exhausted_arm))) ||
      (exhausted_arm && (io.error || self->needs_reinit)) ||
      (cancelled && (!io.action_cancelled ||
                     (self->needs_reinit != (io.cancelled_writes != 0)) ||
                     !g_error_matches (io.error, G_IO_ERROR, G_IO_ERROR_CANCELLED))) ||
      /* The up-arm failed after the comparison: the positive result stands and
       * the hardware session is marked for reconstruction. */
      (excluded_send && (io.error || !self->needs_reinit)) ||
      (!scenario->success && !exhausted_arm && !cancelled && !excluded_send && !malformed &&
       (!g_error_matches (io.error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_TIMED_OUT) || !self->needs_reinit)))
    {
      g_test_message ("expected up=%u sleep=%u success=%d; needs_reinit=%d",
                      scenario->expected_up_sends, scenario->expected_sleep_sends,
                      scenario->success, self->needs_reinit);
      g_test_fail ();
    }
  GOODIX53X5_DEBUG_ONLY (
    g_assert_cmpuint (self->milan_generation->use_count, ==, io.captures);
                        )
  g_clear_error (&io.error);
  g_clear_pointer (&io.first_up, g_bytes_unref);
  g_clear_pointer (&io.first_sleep, g_bytes_unref);
  g_clear_pointer (&io.first_down, g_bytes_unref);
  g_clear_pointer (&io.first_response, g_bytes_unref);
  g_clear_object (&action_cancel_token);
  g_clear_pointer (&self->captured_raw_image, g_free);
  g_clear_pointer (&self->rx.buf, g_free);
  goodix_milan_generation_invalidate (&self->milan_generation);
  g_clear_object (&self->cancel);
  g_clear_object (&self->session_cancel);
}

static void
register_capture_tests (void)
{
  static const Scenario drain = { 0, 0, 1, 1, TRUE, EVENT_BEFORE_SLEEP_ACK };
  static const Scenario event_race = { 0, 0, 1, 1, TRUE, EVENT_COMPLETES_DURING_CANCEL };
  static const Scenario before_arm = { 0, 0, 1, 1, TRUE, EVENT_BEFORE_ARM_ACK };
  static const Scenario up_duplicate = { 0x34, 1, 2, 0, TRUE, DUPLICATE_ARM_IN_EVENT_WAIT, 0x34 };
  static const Scenario down_duplicate = { 0x32, 1, 0, 0, TRUE, DUPLICATE_ARM_IN_EVENT_WAIT, 0x32 };
  static const Scenario cancel_retry = { 0x34, 1, 2, 1, FALSE, CANCEL_DURING_RETRY };
  static const Scenario early_rearm = { 0, 0, 0, 1, TRUE, EARLY_REARM_REVERSE };
  static const Scenario two_reverse = { 0x32, 1, 0, 1, TRUE, TWO_EARLY_REVERSE };
  static const Scenario precedence = { 0x34, 1, 3, 0, TRUE, SAME_COMMAND_PRECEDENCE, 0x34 };
  static const Scenario drain_down = { 0, 0, 0, 1, TRUE, DOWN_BEFORE_SLEEP_ACK };
  static const Scenario drain_reverse = { 0, 0, 0, 1, TRUE, REVERSE_BEFORE_SLEEP_ACK };
  static const Scenario drain_control = { 0, 0, 1, 1, TRUE, STOP_DRAIN_CONTROL };
  static const Scenario cleanup_earlier = { 0x60, 2, 1, 2, FALSE, EARLIER_CLEANUP_ERROR };
  static const Scenario cleanup_protocol = { 0x60, 2, 1, 2, FALSE, CLEANUP_LATE_PROTO };

  add_transport_case ("cleanup/earlier-error", &cleanup_earlier, test_scenario);
  add_transport_case ("cleanup/later-protocol", &cleanup_protocol, test_scenario);
  static const Scenario cancel_arms[] = {
    { 0, 0, 1, 1, FALSE, CANCEL_ARM_FIRST, 0, 1 },
    { 0, 0, 2, 1, FALSE, CANCEL_ARM_FIRST, 0, 3 },
    { 0, 0, 2, 1, FALSE, CANCEL_ARM_REPEAT, 0, 3 },
    { 0, 0, 2, 1, FALSE, CANCEL_ARM_CONFIG, 0, 3 },
  };
  const char *cancel_arm_names[] = { "first", "first-status-three", "repeat", "config" };
  for (guint i = 0; i < G_N_ELEMENTS (cancel_arms); i++)
    {
      g_autofree char *name = g_strdup_printf ("cancel-arm/%s",
                                               cancel_arm_names[i]);
      add_transport_case (name, &cancel_arms[i], test_scenario);
    }
  static const Scenario arms[] = {
    { 0, 0, 0, 0, TRUE, ARM_STATUS, 0x32, 1 },
    { 0, 0, 1, 0, TRUE, ARM_STATUS, 0x34, 1 },
    { 0, 0, 0, 0, TRUE, ARM_STATUS, 0x32, 3 },
    { 0, 0, 2, 0, TRUE, ARM_STATUS, 0x34, 3 },
    { 0, 0, 0, 0, TRUE, ARM_STATUS, 0x32, 7 },
    { 0, 0, 2, 0, TRUE, ARM_STATUS, 0x34, 7 },
    { 0, 0, 0, 0, TRUE, ARM_CONFIG_FAIL, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_REPEAT_FAIL, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_REPEAT_STATUS, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_REFRESH, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_MAX, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_CONFIG_DATA_FAIL, 0x32, 3 },
    { 0, 0, 0, 0, FALSE, ARM_CONFIG_PROTO, 0x32, 3 },
    { 0, 0, 0, 0, FALSE, ARM_CONFIG_CANCEL, 0x32, 3 },
    { 0, 0, 0, 0, TRUE, ARM_FIRST_FAIL, 0x32, 3 },
  };
  const char *arm_names[] = {
    "down-one", "up-one", "down-three", "up-three", "down-seven", "up-seven",
    "config-fails-still-rearm", "repeat-fails-still-wait", "repeat-three-no-reload",
    "fresh-base-after-config", "four-arm-bound",
    "config-data-fails-still-rearm", "config-protocol-no-rearm", "config-cancel-no-rearm",
    "first-fails-still-wait",
  };
  for (guint i = 0; i < G_N_ELEMENTS (arms); i++)
    {
      g_autofree char *name = g_strdup_printf ("arm-repair/%s", arm_names[i]);
      add_transport_case (name, &arms[i], test_scenario);
    }
  add_transport_case ("event-before-sleep-ack", &drain, test_scenario);
  add_transport_case ("event-completes-during-cancel", &event_race, test_scenario);
  add_transport_case ("event-before-arm-ack", &before_arm, test_scenario);
  add_transport_case ("duplicate-up-ack-in-event-wait", &up_duplicate, test_scenario);
  add_transport_case ("duplicate-down-ack-in-event-wait", &down_duplicate, test_scenario);
  add_transport_case ("cancel-during-retry", &cancel_retry, test_scenario);
  add_transport_case ("early-rearm-before-cpu", &early_rearm, test_scenario);
  add_transport_case ("two-early-reverse-before-retry", &two_reverse, test_scenario);
  add_transport_case ("same-command-ack-precedence", &precedence, test_scenario);
  add_transport_case ("stop-state/down", &drain_down, test_scenario);
  add_transport_case ("stop-state/reverse", &drain_reverse, test_scenario);
  add_transport_case ("stop-state/no-event", &drain_control, test_scenario);
}
