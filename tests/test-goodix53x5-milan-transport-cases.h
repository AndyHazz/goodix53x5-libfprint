/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

typedef enum {
  EVENT_CANCELLED,
  EVENT_BEFORE_SLEEP_ACK,
  EVENT_COMPLETES_DURING_CANCEL,
  EVENT_BEFORE_ARM_ACK,
  DUPLICATE_SLEEP_BEFORE_EC_ACK,
  DUPLICATE_ARM_IN_EVENT_WAIT,
  LATE_ACK_DEADLINE,
  CANCEL_DURING_RETRY,
  EARLY_REARM_REVERSE,
  TWO_EARLY_REVERSE,
  SEND_IO_RETRY,
  SEND_TIMEOUT_RETRY,
  SEND_DISCONNECT,
  SEND_CANCELLED,
  SEND_FAILED_RETRY,
  SEND_STALL_RETRY,
  SEND_INTERNAL_RETRY,
  WRITE_STALLED_CANCEL,
  EARLIER_CLEANUP_ERROR,
  CLEANUP_LATE_PROTO,
  SAME_COMMAND_PRECEDENCE,
  MULTICELL_DATA,
  ACK_ZERO_THEN_ONE,
  ACK_TWO_THEN_ONE,
  ACK_EVEN_TIMEOUT,
  ACK_EVEN_THEN_MALFORMED,
  LATE_EVEN_ACK,
  LATE_EVEN_DEADLINE,
  RESPONSE_BUDGET,
  RESPONSE_DEADLINE,
  EC_LATE_ACK,
  EC_LATE_DATA,
  DOWN_BEFORE_SLEEP_ACK,
  REVERSE_BEFORE_SLEEP_ACK,
  STOP_DRAIN_CONTROL,
  CANCEL_ARM_FIRST,
  CANCEL_ARM_REPEAT,
  CANCEL_ARM_CONFIG,
  RESPONSE_EARLY,
  RESPONSE_RETRY,
  RESPONSE_EARLY_RESET,
  RESPONSE_STATUS,
  RESPONSE_DUPLICATE,
  RESPONSE_HANDOFF,
  ARM_STATUS,
  ARM_CONFIG_FAIL,
  ARM_REPEAT_FAIL,
  ARM_REPEAT_STATUS,
  ARM_REFRESH,
  ARM_MAX,
  ARM_CONFIG_DATA_FAIL,
  ARM_CONFIG_PROTO,
  ARM_CONFIG_CANCEL,
  ARM_FIRST_FAIL,
} Schedule;

typedef struct {
  guint8 timeout_command;
  guint timeout_count;
  guint expected_up_sends;
  guint expected_sleep_sends;
  gboolean success;
  Schedule schedule;
  guint8 standalone_arm;
  guint8 ec_status;
} Scenario;

static struct {
  guint8 command;
  guint sends[256];
  guint captures;
  guint completions;
  guint cancellations;
  guint cancelled_writes;
  guint started_writes;
  guint precancelled_writes;
  guint events;
  guint dispatches;
  guint duplicates;
  guint expected_acks;
  guint                  even_attempt;
  guint                  even_followups;
  gint64 ec_ack_started;
  gboolean deadline_violation;
  gboolean action_cancelled;
  guint wait_cpu_count;
  guint8 settled_down[GOODIX_FDT_BASE_LEN];
  guint8 settled_manual[GOODIX_FDT_BASE_LEN];
  guint16 settled_prior[GOODIX_PROFILE9_FDT_AREA_COUNT];
  guint8 packet_down[2][GOODIX_FDT_BASE_LEN];
  guint8 packet_manual[2][GOODIX_FDT_BASE_LEN];
  guint8 last_down_payload[GOODIX_FDT_BASE_LEN];
  guint data_chunks;
  guint early_attempt;
  GBytes *first_response;
  gboolean disposition_sent;
  gboolean ec_data;
  GError *error;
  GBytes *first_up;
  GBytes *first_sleep;
  GBytes *first_down;
  const Scenario *scenario;
} io;

static void boundary_done (FpiSsm *, FpDevice *, GError *);
static void test_scenario (gconstpointer);
static void stop_after_capture (FpDevice *);
static gboolean rearm_case (const Scenario *);
static gboolean down_drain_case (const Scenario *);
static void reverse_event (FpiUsbTransfer *, guint);
static void up_event (FpiUsbTransfer *);
static void idle_test_command_done (FpiSsm *, FpDevice *, GError *);
static void idle_test_ec (FpiSsm *, FpDevice *);
