/*
 * Goodix 53x5 driver for libfprint — Private device state
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

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

#include "goodix53x5.h"
#include "device/proto.h"
#include "device/crypto.h"
#include "device/debug.h"
#include "device/base.h"
#include "device/health.h"
#include "milan/match/match.h"

/* USB interface claimed at open and released at close — interface 1,
 * CDC Data class. Endpoint and chunking details live in the transport
 * module. */
#define GOODIX_USB_INTERFACE 1

/* Sensor dimensions */
#define GOODIX_SENSOR_WIDTH 108
#define GOODIX_SENSOR_HEIGHT 88
#define GOODIX_SENSOR_PIXELS (GOODIX_SENSOR_WIDTH * GOODIX_SENSOR_HEIGHT)
#define GOODIX_SENSOR_RAW12_BYTES (((GOODIX_SENSOR_PIXELS + 3) / 4) * 6)

/* Enroll stages */
#define GOODIX_ENROLL_SAMPLES 12

/* PSK white box for writing the default all-zero PSK. */
#define GOODIX_PSK_WHITE_BOX_LEN 96

/* --- Calibration parameters (from OTP) --- */
typedef struct
{
  guint16  tcode;
  guint16  delta_fdt;
  guint16  delta_down;
  guint16  delta_up;
  guint16  delta_img;
  guint16  delta_nav;
  guint16  dac_h;
  guint16  dac_l;
  guint16  dac_delta;
  gboolean dac_from_otp;
} GoodixCalibParams;

/* Original OTP default and live adjustment history; current DAC is calib.dac_h. */
typedef struct
{
  guint16 default_dac;
  guint16 active;
  guint16 adjustments;
  guint16 high;
  guint16 low;
} GoodixDynamicDacState;

typedef enum
{
  GOODIX_FDT_EVENT_DOWN = 0,
  GOODIX_FDT_EVENT_UP,
  GOODIX_FDT_EVENT_REVERSE,
  GOODIX_FDT_EVENT_NONE,
  GOODIX_FDT_EVENT_CONFIG,
  GOODIX_FDT_EVENT_ESD,
  GOODIX_FDT_EVENT_WAKE,
  GOODIX_FDT_EVENT_DEACTIVATE,
} GoodixFdtEventType;

typedef struct
{
  /* Receive identity and reverse predecessor travel with the coalesced slot;
   * scan copies selected work before another packet can replace this slot. */
  GoodixProfile9FdtEvent event;
  GoodixFdtEventType type;
} GoodixFdtNotification;

typedef struct _GoodixTransport GoodixTransport;
typedef struct _GoodixReader GoodixReader;

/* HAL +0x1e0: requested mode, independent of coordinator and FDT wait state. */
typedef enum
{
  GOODIX_REQUESTED_MODE_CAPTURE = 0,
  GOODIX_REQUESTED_MODE_SLEEP = 2,
} GoodixRequestedMode;

/* Independent native response events; the first four retain their existing
 * readiness bits used by the named command consumers. */
typedef enum
{
  GOODIX_RESPONSE_NONE = -1,
  GOODIX_RESPONSE_MANUAL,
  GOODIX_RESPONSE_CONFIG,
  GOODIX_RESPONSE_SYSTEM,
  GOODIX_RESPONSE_IMAGE,
  GOODIX_RESPONSE_REGISTER,
  GOODIX_RESPONSE_OTP,
  GOODIX_RESPONSE_PRODUCTION,
  GOODIX_RESPONSE_FIRMWARE,
  GOODIX_RESPONSE_COUNT,
} GoodixResponseSlot;

/* --- Device struct --- */
struct _FpiDeviceGoodix53x5
{
  FpDevice      parent;

  GCancellable *cancel;
  /* Hardware service authority is independent of the current client action. */
  GCancellable *session_cancel;
  gboolean      session_open;
  /* Exactly one owner drives the hardware at a time: background maintenance
   * (idle service or a detached deactivation tail), a foreground action, or
   * the reader join requested by suspend/close. */
  gboolean      service_active;
  gboolean      foreground_active;
  gboolean      action_pending;
  gboolean      suspend_pending;
  gboolean      session_suspended;
  /* Physical stop in flight; service_joined remains owned until its callback. */
  gboolean      service_draining;
  void (*service_joined) (FpDevice *dev, gpointer data);
  gpointer service_joined_data;

  /* GTLS session (persists across captures) */
  GoodixGtlsCtx gtls;
  gboolean      image_error_history;
  gboolean      gtls_restart_pending;
  gboolean      gtls_restart_active;

  /* Calibration seeded from OTP; live reads update the current high DAC. */
  GoodixCalibParams calib;
  /* Per-device default and last live snapshot of module-owned DAC history. */
  GoodixDynamicDacState dynamic_dac;
  GoodixSensorHealth health;
  /* Latest admitted hardware TX-on plane, independent of consumed setup.
   * Owned until hardware teardown; recoverable base rejection retains it. */
  guint16 *hardware_reference;
  guint64  hardware_reference_id;
  gboolean hardware_refresh_pending;
  /* Installed hardware callback/count outlive an individual read attempt. */
  guint    capture_unread;
  gboolean captured_enroll_allowed;
  gboolean capture_callback_pending;

  /* Reassembly buffer for multi-chunk reads */
  GoodixReassembly rx;
  /* Validated borrowed view, consumed before the next receive/invalidation. */
  gboolean         reply_valid;
  guint8           reply_category;
  guint8           reply_command;
  const guint8    *reply_payload;
  gsize            reply_payload_len;
  /* Category-D stream and coalesced receive signal survive ACK ownership.
   * The selected view remains owned until the next receive or invalidation. */
  GByteArray      *mcu_rx;
  GBytes          *mcu_reply;
  gboolean         mcu_ready;
  /* One handle-owned IN reader and a separately owned command/event waiter. */
  GoodixReader    *reader;
  GoodixTransport *transport;

  /* Native response events reset per send; cached bytes survive reset.
   * The manual cache retains metadata for Linux touch-flag consumers. */
  guint8 command_response_ready;
  /* Category-9/command-2 status is separate from shared response-cache bytes. */
  guint8 config_response_status;
  /* Receiver-owned decoded image, independent of the command ACK and of the
   * captured frame handed to the runtime worker. Readiness resets per send. */
  guint16 *image_response;
  gboolean image_response_failed;
  guint8 manual_response[4 + GOODIX_FDT_BASE_LEN];
  /* Parser mutations precede coalesced notification. The latest reverse event
   * retains the down base installed by its predecessor, not the arm payload. */
  guint16 fdt_prior_down[GOODIX_PROFILE9_FDT_AREA_COUNT];
  GoodixFdtNotification pending_fdt;
  guint8 notice_irq[2];
  gboolean rx_idle_partial;
  GoodixRequestedMode requested_mode;

  /* Profile-9 FDT state persists across actions and hardware reinitialization. */
  GoodixProfile9FdtState profile9_fdt;

  gboolean               open_ref_powered;
  gboolean               open_usb_reset_required;
  gboolean               open_recovery_attempted;
  gboolean               open_gtls_failed;

  /* OTP raw data */
  guint8 *otp_data;
  gsize   otp_len;

  /* Firmware version string */
  gchar *fw_version;
  /* Shared native cache, including retained unwritten suffixes. Keep the
   * firmware consumer's 64-byte view while retaining complete framed replies. */
  union
  {
    guint8 shared_response[64];
    guint8 shared_response_storage[GOODIX_RX_BUF_SIZE];
  };
  /* Received lengths preserve Linux short-reply validation independently of
   * the native event grouping and shared byte overwrites. */
  gsize shared_response_lengths[GOODIX_RESPONSE_COUNT];

  /* Hardware identity and its validated Milan algorithm subtype. */
  guint32 chip_id;
  guint16 milan_sensor_subtype;

  /* Device-keyed identity for the persisted preprocessing subset. */
  guint8   milan_persistence_identity[32];
  gboolean milan_persistence_identity_valid;

  /* One admitted TX-on setup generation per valid hardware session. */
  GoodixMilanGeneration *milan_generation;
  /* Algorithm state surviving close/reset, released with this device object. */
  GoodixMilanGeneration *milan_retained_generation;
  guint64                last_milan_generation_id;

  /* Action-owned state to commit after post-scan hardware cleanup. */
  GoodixMilanPreprocessState *pending_persistence_state;

  /* TRUE while verifying a PSK write during open. */
  gboolean psk_write_verify_pending;

  /* GTLS PSK selected for this open. Imported keys are never provisioned by
   * this driver because the arbitrary-key white-box encoder is not available. */
  guint8   psk[GOODIX_PSK_LEN];
  gboolean psk_imported;

  /* USB interface state */
  gboolean usb_interface_claimed;

  /* A hardware fault requires cold reconstruction on resume or the next
   * action. Ordinary sleep retains host state and only re-keys GTLS. */
  gboolean needs_reinit;

  /* Retained for the open/reinitialization parent SSM. */
  FpiSsm *task_ssm;

  /* Result computed by the CPU worker, delivered when the action completes. */
  gboolean        pending_result_report;
  FpiDeviceAction pending_result_action;
  FpiMatchResult  pending_verify_result;
  FpPrint        *pending_identify_match;
  FpPrint        *pending_update_target;
  GVariant       *pending_update_data;
  GError         *pending_result_error;
  GError         *pending_learning_error;

  /* Native CPU work is isolated in one cancellable task. Only its callback on
   * the action's main context may commit generation state or publish results. */
  GTask  *milan_task;
  guint64 action_epoch;

#ifdef GOODIX53X5_DEBUG
  guint8 *captured_image;   /* native profile-9 diagnostic presentation */
#endif

  /* Canonical raw 12-bit live frame. Production owns this independently of
   * debug dumping until the current auth/enroll action consumes or clears it. */
  guint16 *captured_raw_image;

#ifdef GOODIX53X5_DEBUG
  GoodixDebugTiming debug_timing;
  gchar             debug_capture_session_id[37];
  guint64           debug_chronology;
#endif

  /* Enrollment tracking */
  GoodixMilanEnrollmentTransaction *enroll_transaction;
  gint                              enroll_stage;
  guint                             enroll_bad_record_count;
  guint                             enroll_bad_continue_count;
  gboolean                          pending_enroll_progress;
  gint                              pending_enroll_stage;
  GError                           *pending_enroll_error;
};
