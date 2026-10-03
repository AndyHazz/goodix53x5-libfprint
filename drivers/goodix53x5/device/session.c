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

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/transport.h"
#include "device/commands.h"
#include "device/calibration.h"
#include "device/base.h"
#include "device/persistence.h"
#include "device/scan.h"
#include "device/session.h"
#include "device/auth.h"
#include "device/enroll.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#define GOODIX_PSK_STATE_FILE "/var/lib/fprint/goodix53x5.psk"

/* ========================================================================
 * Hardware ownership
 *
 * The open session always has at most one hardware owner: background
 * maintenance (the idle service, or the deactivation tail a completed action
 * left behind), one foreground action, or the reader join that suspend and
 * close request. Every owner reports back through goodix_session_settle(),
 * which then starts whatever is waiting.
 * ======================================================================== */

GCancellable *
goodix_session_io_cancellable (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (self->profile9_fdt.owner || self->service_active ||
      self->suspend_pending || self->session_suspended)
    return self->session_cancel;
  return fpi_device_get_cancellable (dev);
}

static void
goodix_session_hardware_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  void (*joined) (FpDevice *, gpointer) = self->service_joined;
  gpointer joined_data = self->service_joined_data;

  /* Retire the stop owner only after the physical reader's callback joined.
   * The continuation may start power I/O or complete an outward request. */
  self->service_joined = NULL;
  self->service_joined_data = NULL;
  self->service_draining = FALSE;
  joined (dev, joined_data);
}

void
goodix_session_settle (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  /* Wait for the current owner; it reports back here when it stops. */
  if (self->foreground_active || self->service_active || self->service_draining)
    return;
  if (self->action_pending)
    {
      GError *error = NULL;

      self->action_pending = FALSE;
      if (self->session_suspended || self->suspend_pending)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                         "Hardware session is suspended");
      else if (self->service_joined || fpi_device_action_is_cancelled (dev))
        error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                    "Action cancelled during hardware handoff");
      if (error)
        {
          fpi_device_action_error (dev, error);
        }
      else
        {
          self->foreground_active = TRUE;
          if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
            goodix_enroll_start (dev);
          else
            goodix_auth_start (dev);
          return;
        }
    }
  if (self->service_joined)
    {
      /* Only hardware-stop boundaries cancel the request-independent IN. The
       * physical reader, partial reassembly and coalesced notifications survive
       * ordinary owner handoffs. */
      self->service_draining = TRUE;
      goodix_transport_quiesce (dev, goodix_session_hardware_joined, NULL);
      return;
    }
  if (self->session_open && !self->needs_reinit &&
      !self->suspend_pending && !self->session_suspended)
    goodix_scan_start_service (dev);
}

void
goodix_session_service_done (FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->service_active = FALSE;
  if (error &&
      !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
      !g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED))
    {
      /* Maintenance stays off until the next action reconstructs the
       * hardware session; nothing else retries in the background. */
      self->needs_reinit = TRUE;
      fp_warn ("Hardware maintenance stopped: %s", error->message);
    }
  g_clear_error (&error);
  goodix_session_settle (dev);
}

void
goodix_session_detach_action (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_assert (!self->service_active);
  self->service_active = TRUE;
}

void
goodix_session_start_action (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  /* Actions never queue behind power or close work; the core only blocks
   * them itself once suspend has completed. */
  if (self->suspend_pending || self->session_suspended)
    {
      fpi_device_action_error (dev, fpi_device_error_new_msg (
                                 FP_DEVICE_ERROR_BUSY, "Hardware session is suspended"));
      return;
    }
  if (self->service_joined)
    {
      fpi_device_action_error (dev, g_error_new_literal (
                                 G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                 "Hardware session is closing"));
      return;
    }
  self->action_pending = TRUE;
  if (self->service_active)
    goodix_scan_join_service (dev);
  else
    goodix_session_settle (dev);
}

gboolean
goodix_session_cancel_pending_action (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (!self->action_pending)
    return FALSE;

  /* Nothing was admitted yet. Detach only the request: the maintenance owner
   * keeps its selected command and settles servicing through its own join. */
  self->action_pending = FALSE;
  fpi_device_action_error (dev, g_error_new_literal (
                            G_IO_ERROR, G_IO_ERROR_CANCELLED,
                            "Action cancelled during hardware handoff"));
  return TRUE;
}

void
goodix_session_action_done (FpDevice *dev, GError *error,
                            void (*complete) (FpDevice *, GError *))
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED))
    {
      g_clear_error (&error);
      error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Action cancelled");
    }
  self->foreground_active = FALSE;
  /* The application callback may start the next action reentrantly; the
   * ownership state above is already consistent for that. */
  complete (dev, error);
  goodix_session_settle (dev);
}

void
goodix_session_quiesce (FpDevice *dev,
                        void (*joined) (FpDevice *, gpointer), gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_assert (!self->service_joined);
  self->service_joined = joined;
  self->service_joined_data = data;
  if (self->session_cancel)
    g_cancellable_cancel (self->session_cancel);
  if (self->service_active)
    goodix_scan_join_service (dev);
  else if (self->foreground_active)
    {
      GCancellable *io_cancel = fpi_device_get_cancellable (dev);

      /* An OUT submitted before suspend still owns the foreground token.
       * Revoke it as well as the CPU/scan token before awaiting the join. */
      if (io_cancel)
        g_cancellable_cancel (io_cancel);
      if (self->cancel)
        g_cancellable_cancel (self->cancel);
      goodix_scan_stop_coordinator (dev, NULL);
    }
  else
    goodix_session_settle (dev);
}

/* Open SSM — full device initialization */
typedef enum {
  GOODIX_OPEN_USB_RESET = 0,
  GOODIX_OPEN_CLAIM_INTERFACE,
  GOODIX_OPEN_PING,
  GOODIX_OPEN_RESET,
  GOODIX_OPEN_READ_OTP,
  GOODIX_OPEN_PARSE_OTP,
  GOODIX_OPEN_READ_PSK_HASH,
  GOODIX_OPEN_WRITE_PSK,
  GOODIX_OPEN_VERIFY_PSK_WRITE,
  GOODIX_OPEN_GTLS_CLIENT_HELLO,
  GOODIX_OPEN_UPLOAD_CONFIG,
  GOODIX_OPEN_VALIDATE_CONFIG,
  GOODIX_OPEN_CAPTURE_REF,
  GOODIX_OPEN_CAPTURE_REF_DONE,
  GOODIX_OPEN_FINAL_FIRMWARE,
  GOODIX_OPEN_FINAL_SLEEP,
  GOODIX_OPEN_SLEEP,
  GOODIX_OPEN_EC_POWER_OFF,
  GOODIX_OPEN_EC_POWER_OFF_DONE,
  GOODIX_OPEN_NUM_STATES,
} GoodixOpenState;


#ifdef GOODIX53X5_DEBUG
static const gchar *
goodix_open_state_name (GoodixOpenState state)
{
  switch (state)
    {
    case GOODIX_OPEN_USB_RESET:
      return "usb_reset";
    case GOODIX_OPEN_CLAIM_INTERFACE:
      return "claim_interface";
    case GOODIX_OPEN_PING:
      return "ping";
    case GOODIX_OPEN_RESET:
      return "reset";
    case GOODIX_OPEN_READ_OTP:
      return "read_otp";
    case GOODIX_OPEN_PARSE_OTP:
      return "parse_otp";
    case GOODIX_OPEN_READ_PSK_HASH:
      return "read_psk_hash";
    case GOODIX_OPEN_WRITE_PSK:
      return "write_psk";
    case GOODIX_OPEN_VERIFY_PSK_WRITE:
      return "verify_psk_write";
    case GOODIX_OPEN_GTLS_CLIENT_HELLO:
      return "gtls_client_hello";
    case GOODIX_OPEN_UPLOAD_CONFIG:
      return "upload_config";
    case GOODIX_OPEN_VALIDATE_CONFIG:
      return "validate_config";
    case GOODIX_OPEN_CAPTURE_REF:
      return "capture_ref";
    case GOODIX_OPEN_CAPTURE_REF_DONE:
      return "capture_ref_done";
    case GOODIX_OPEN_FINAL_FIRMWARE:
      return "final_firmware";
    case GOODIX_OPEN_FINAL_SLEEP:
      return "final_sleep";
    case GOODIX_OPEN_SLEEP:
      return "sleep";
    case GOODIX_OPEN_EC_POWER_OFF:
      return "ec_power_off";
    case GOODIX_OPEN_EC_POWER_OFF_DONE:
      return "ec_power_off_done";
    case GOODIX_OPEN_NUM_STATES:
    default:
      return "unknown";
    }
}
#endif

/* PSK white box for writing the default all-zero PSK. */
static const guint8 goodix_psk_white_box[GOODIX_PSK_WHITE_BOX_LEN] = {
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f,
  0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
  0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
  0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1,
  0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75,
  0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
  0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
  0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b,
  0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};

static gboolean
goodix_load_psk (FpiDeviceGoodix53x5 *self,
                 GError             **error)
{
  const gchar *path = GOODIX_PSK_STATE_FILE;
  gchar *contents = NULL;
  gsize length = 0;
  gsize hex_length;
  g_autoptr(GError) local_error = NULL;
  gboolean success = FALSE;

  memset (self->psk, 0, sizeof (self->psk));
  self->psk_imported = FALSE;

  if (!g_file_get_contents (path, &contents, &length, &local_error))
    {
      if (g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        return TRUE;

      g_propagate_prefixed_error (error, g_steal_pointer (&local_error),
                                  "Failed to read PSK file %s: ", path);
      return FALSE;
    }

  hex_length = length;
  while (hex_length > 0 && g_ascii_isspace (contents[hex_length - 1]))
    hex_length--;
  if (hex_length != GOODIX_PSK_LEN * 2)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "PSK file %s must contain exactly 64 hexadecimal characters",
                   path);
      goto out;
    }

  for (gsize i = 0; i < GOODIX_PSK_LEN; i++)
    {
      gint high = g_ascii_xdigit_value (contents[i * 2]);
      gint low = g_ascii_xdigit_value (contents[i * 2 + 1]);

      if (high < 0 || low < 0)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "PSK file %s contains non-hexadecimal data", path);
          goto out;
        }
      self->psk[i] = (high << 4) | low;
    }

  self->psk_imported = TRUE;
  fp_info ("Using imported GTLS PSK from %s", path);
  success = TRUE;

out:
  OPENSSL_cleanse (contents, length);
  g_free (contents);
  if (!success)
    OPENSSL_cleanse (self->psk, sizeof (self->psk));
  return success;
}

/* ========================================================================
 * Open SSM — full device initialization
 * ======================================================================== */

typedef enum {
  GOODIX_PROBE_PING,
  GOODIX_PROBE_FIRMWARE,
  GOODIX_PROBE_AFTER_DELAY,
  GOODIX_PROBE_NUM_STATES,
} GoodixProbeState;

static gboolean
goodix_probe_cancelled (FpiSsm *ssm, FpDevice *dev)
{
  GCancellable *cancel = goodix_session_io_cancellable (dev);
  gboolean removed = FALSE;

  g_object_get (dev, "removed", &removed, NULL);
  if (cancel && g_cancellable_is_cancelled (cancel))
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                    "Startup probe cancelled"));
      return TRUE;
    }
  if (removed)
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_USB_DEVICE_ERROR,
                                                    G_USB_DEVICE_ERROR_NO_DEVICE,
                                                    "Startup device removed"));
      return TRUE;
    }
  return FALSE;
}

static void
goodix_probe_result (FpiSsm *ssm, FpDevice *dev, guint8 status,
                     gboolean native_zero, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint *failures = fpi_ssm_get_data (ssm);

  if (goodix_probe_cancelled (ssm, dev))
    {
      g_clear_error (&error);
      return;
    }
  if (error && !native_zero)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (fpi_ssm_get_cur_state (ssm) == GOODIX_PROBE_PING)
    {
      g_clear_error (&error);
      fpi_ssm_next_state (ssm);
    }
  else if (!error)
    {
      /* Native getter copies 64 cache bytes. Keep that cache untouched and
       * give the Linux string consumer its own guaranteed terminator. */
      g_free (self->fw_version);
      self->fw_version = g_strndup ((const gchar *) self->shared_response,
                                    sizeof (self->shared_response));
      fpi_ssm_mark_completed (ssm);
    }
  else
    {
      g_clear_error (&error);
      (*failures)++;
      /* Native sleeps after every failed query, including iteration five. */
      fpi_ssm_jump_to_state_delayed (ssm, GOODIX_PROBE_AFTER_DELAY, 100);
    }
}

static void
goodix_probe_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  guint *failures = fpi_ssm_get_data (ssm);

  if (goodix_probe_cancelled (ssm, dev))
    return;
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_PROBE_PING:
    case GOODIX_PROBE_FIRMWARE:
      goodix_cmd_probe (ssm, dev, fpi_ssm_get_cur_state (ssm) == GOODIX_PROBE_FIRMWARE,
                        goodix_probe_result);
      break;
    case GOODIX_PROBE_AFTER_DELAY:
      if (*failures == 5)
        {
          fp_dbg ("Startup firmware query exhausted; continuing device initialization");
          fpi_ssm_mark_completed (ssm);
        }
      else
        fpi_ssm_jump_to_state (ssm, GOODIX_PROBE_PING);
      break;
    }
}

typedef enum {
  GOODIX_CHIP_INITIAL_RESET,
  GOODIX_CHIP_READ,
  GOODIX_CHIP_RECOVERY_RESET,
  GOODIX_CHIP_AFTER_DELAY,
  GOODIX_CHIP_NUM_STATES,
} GoodixChipState;

static void
goodix_chip_result (FpiSsm *ssm, FpDevice *dev, guint8 status,
                    gboolean native_zero, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint *failures = fpi_ssm_get_data (ssm);

  if (goodix_probe_cancelled (ssm, dev))
    {
      g_clear_error (&error);
      return;
    }
  if (error && !native_zero)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (fpi_ssm_get_cur_state (ssm) == GOODIX_CHIP_READ)
    {
      if (!error)
        {
          const guint8 *payload;
          gsize length;

          if (!goodix_cmd_parse_chip_id_reply (dev, &payload, &length, &error))
            {
              fpi_ssm_mark_failed (ssm, error);
              return;
            }
          if (length != 4)
            {
              fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                    FP_DEVICE_ERROR_PROTO,
                                    "Unexpected chip ID reply length: %zu", length));
              return;
            }

          self->chip_id = goodix_crypto_decode_u32 (payload);
          fp_dbg ("Chip ID: 0x%08x", self->chip_id);
          /* usbinterface!180017ef8 recognizes these four families. A valid
           * other family is unsupported by Linux, not failed identification. */
          switch (self->chip_id >> 8)
            {
            case 0x2202:
            case 0x2207:
            case 0x2208:
            case 0x220c:
              if (!goodix_milan_runtime_subtype_for_chip (
                    self->chip_id, &self->milan_sensor_subtype))
                fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                      FP_DEVICE_ERROR_NOT_SUPPORTED,
                                      "Native Milan runtime is unsupported for product 0x%04x chip 0x%08x",
                                      g_usb_device_get_pid (fpi_device_get_usb_device (dev)),
                                      self->chip_id));
              else
                fpi_ssm_mark_completed (ssm);
              return;

            default:
              break;
            }
        }
      g_clear_error (&error);
      (*failures)++;
      fpi_ssm_next_state (ssm);
      return;
    }

  /* device_enable ignores the first ordinary reset failure. The chip getter
   * also ignores recovery reset failure and its IRQ value. Both delays occur
   * after completion; the last failed read still resets and sleeps. */
  g_clear_error (&error);
  fpi_ssm_next_state_delayed (ssm,
                             fpi_ssm_get_cur_state (ssm) == GOODIX_CHIP_INITIAL_RESET ? 10 : 100);
}

static void
goodix_chip_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  guint *failures = fpi_ssm_get_data (ssm);

  if (goodix_probe_cancelled (ssm, dev))
    return;
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CHIP_INITIAL_RESET:
    case GOODIX_CHIP_RECOVERY_RESET:
      goodix_cmd_reset_sensor (ssm, dev,
                                fpi_ssm_get_cur_state (ssm) == GOODIX_CHIP_RECOVERY_RESET,
                                goodix_chip_result);
      break;

    case GOODIX_CHIP_READ:
      goodix_cmd_read_chip_id (ssm, dev, goodix_chip_result);
      break;

    case GOODIX_CHIP_AFTER_DELAY:
      if (*failures == 6)
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                              FP_DEVICE_ERROR_PROTO,
                              "Chip identification failed after six read cycles"));
      else
        fpi_ssm_jump_to_state (ssm, GOODIX_CHIP_READ);
      break;
    }
}

typedef enum {
  GOODIX_GTLS_HELLO,
  GOODIX_GTLS_IDENTITY,
  GOODIX_GTLS_VERIFY,
  GOODIX_GTLS_COMPLETION,
  GOODIX_GTLS_READY,
  GOODIX_GTLS_NUM_STATES,
} GoodixGtlsState;

typedef struct {
  guint attempt;
  GError *error;
  GoodixGtlsRestartDone restart_done;
  gpointer              restart_data;
} GoodixGtlsRetry;

static void
goodix_gtls_retry_free (GoodixGtlsRetry *retry)
{
  g_clear_error (&retry->error);
  g_free (retry);
}

static void
goodix_gtls_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  const guint8 *mcu_data;
  gsize mcu_len;
  g_autoptr(GError) error = NULL;

  if (g_cancellable_set_error_if_cancelled (goodix_session_io_cancellable (dev), &error))
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  switch ((GoodixGtlsState) fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_GTLS_HELLO:
      goodix_transport_reset_mcu (dev);
      goodix_crypto_gtls_init (&self->gtls, self->psk);
      if (RAND_bytes (self->gtls.client_random, 32) != 1)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                 FP_DEVICE_ERROR_PROTO, "GTLS client random generation failed"));
          return;
        }
      goodix_cmd_mcu_send (ssm, dev, 0xFF01, self->gtls.client_random, 32);
      break;

    case GOODIX_GTLS_IDENTITY:
      self->gtls.state = 2;
      goodix_recv_mcu (ssm, dev, 2000, 72);
      break;

    case GOODIX_GTLS_VERIFY:
      if (!goodix_cmd_parse_mcu_reply (dev, 0xFF02, &mcu_data, &mcu_len) || mcu_len != 64)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                FP_DEVICE_ERROR_PROTO, "Invalid GTLS server identity"));
          return;
        }
      memcpy (self->gtls.server_random, mcu_data, 32);
      memcpy (self->gtls.server_identity, mcu_data + 32, 32);
      goodix_crypto_gtls_derive_keys (&self->gtls);
      if (!goodix_crypto_gtls_verify_identity (&self->gtls))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                FP_DEVICE_ERROR_PROTO, "GTLS identity verification failed"));
          return;
        }
      {
        guint8 verify_data[36];

        memcpy (verify_data, self->gtls.client_identity, 32);
        memset (verify_data + 32, 0xEE, 4);
        goodix_cmd_mcu_send (ssm, dev, 0xFF03, verify_data, 36);
      }
      break;

    case GOODIX_GTLS_COMPLETION:
      self->gtls.state = 4;
      goodix_recv_mcu (ssm, dev, 2000, 12);
      break;

    case GOODIX_GTLS_READY:
      if (!goodix_cmd_parse_mcu_reply (dev, 0xFF04, &mcu_data, &mcu_len))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                FP_DEVICE_ERROR_PROTO, "Failed to parse GTLS done"));
          return;
        }
      /* The native completion is exactly twelve bytes including the MCU
       * header. Its four trailing bytes are not a result code. */
      if (mcu_len != 4)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                                FP_DEVICE_ERROR_PROTO, "Wrong GTLS done payload size: %zu", mcu_len));
          return;
        }
      self->gtls.hmac_client_counter = self->gtls.hmac_client_counter_init;
      self->gtls.hmac_server_counter = self->gtls.hmac_server_counter_init;
      self->gtls.state = 5;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_GTLS_NUM_STATES:
      g_assert_not_reached ();
    }
}

static void
goodix_gtls_attempt_done (FpiSsm *attempt, FpDevice *dev, GError *error)
{
  FpiSsm *ssm = fpi_ssm_get_data (attempt);
  GoodixGtlsRetry *retry = fpi_ssm_get_data (ssm);

  if (!error)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }
  /* Host cancellation, removal and ownership rejection are terminal. Ordinary
   * native send/read/protocol failure retries the selected-PSK handshake only. */
  if (!(g_error_matches (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO) ||
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO) ||
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED) ||
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NOT_SUPPORTED) ||
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_INTERNAL) ||
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT)))
    {
      if (!retry->restart_done)
        FPI_DEVICE_GOODIX53X5 (dev)->open_gtls_failed = TRUE;
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  retry->error = error;
  /* deviceInit calls the three-attempt wrapper once more after failure, without
   * reset or PSK reload. Linux has no production-item cache to clear between
   * those groups. Each failed attempt, including the last, sleeps ten ms. */
  fpi_ssm_jump_to_state_delayed (ssm,
                                 retry->attempt < (retry->restart_done ? 3 : 6) ? 0 : 1, 10);
}

static void
goodix_gtls_retry_handler (FpiSsm *ssm, FpDevice *dev)
{
  GoodixGtlsRetry *retry = fpi_ssm_get_data (ssm);
  g_autoptr(GError) error = NULL;

  if (g_cancellable_set_error_if_cancelled (goodix_session_io_cancellable (dev), &error))
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }
  if (fpi_ssm_get_cur_state (ssm) == 1)
    {
      if (retry->restart_done)
        {
          /* Ordinary restart exhaustion never retires the hardware worker,
           * whether or not an application currently owns a capture request. */
          fp_dbg ("GTLS restart failed: %s", retry->error->message);
          fpi_ssm_mark_completed (ssm);
          return;
        }
      FPI_DEVICE_GOODIX53X5 (dev)->open_gtls_failed = TRUE;
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&retry->error));
      return;
    }
  g_clear_error (&retry->error);
  retry->attempt++;
  FpiSsm *attempt = fpi_ssm_new (dev, goodix_gtls_ssm_handler, GOODIX_GTLS_NUM_STATES);

  fpi_ssm_set_data (attempt, ssm, NULL);
  fpi_ssm_start (attempt, goodix_gtls_attempt_done);
}

static void
goodix_gtls_restart_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixGtlsRetry *retry = fpi_ssm_get_data (ssm);

  self->gtls_restart_active = FALSE;
  /* Host cancellation/removal can interrupt key replacement. The next action
   * must not treat that incomplete session as an established one. */
  if (error)
    self->needs_reinit = TRUE;
  retry->restart_done (dev, error, retry->restart_data);
}

void
goodix_start_gtls_restart (FpDevice *dev, GoodixGtlsRestartDone done,
                           gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixGtlsRetry *retry = g_new0 (GoodixGtlsRetry, 1);
  FpiSsm *ssm = fpi_ssm_new (dev, goodix_gtls_retry_handler, 2);

  g_assert (!self->transport && !self->gtls_restart_active);
  self->gtls_restart_pending = FALSE;
  self->gtls_restart_active = TRUE;
  retry->restart_done = done;
  retry->restart_data = data;
  fpi_ssm_set_data (ssm, retry, (GDestroyNotify) goodix_gtls_retry_free);
  fpi_ssm_start (ssm, goodix_gtls_restart_done);
}

/* deviceInit ignores ordinary allbase, final-version and mode-2 results.
 * Configuration failure still exits allbase before its first manual/image;
 * only the cold owner continues to its common initialization tail. */
static void
goodix_open_native_result (FpiSsm *ssm, FpDevice *dev, guint8 status,
                           gboolean native_zero, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gboolean failed = error != NULL;

  if (error && !native_zero)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  g_clear_error (&error);
  if (goodix_probe_cancelled (ssm, dev))
    return;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_OPEN_UPLOAD_CONFIG:
      if (failed)
        {
          self->profile9_fdt.base_valid = FALSE;
          self->profile9_fdt.initial_recovery_pending = TRUE;
          fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_FINAL_FIRMWARE);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case GOODIX_OPEN_FINAL_FIRMWARE:
      if (!failed)
        {
          g_free (self->fw_version);
          self->fw_version = g_strndup ((const gchar *) self->shared_response,
                                        sizeof (self->shared_response));
        }
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_FINAL_SLEEP:
      /* Completed native mode request, including ordinary exhaustion. The
       * command owner has published requested mode 2; no EC-off belongs here. */
      fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_NUM_STATES);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
goodix_open_ssm_handler (FpiSsm   *ssm,
                         FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixOpenState state = fpi_ssm_get_cur_state (ssm);

  goodix_debug_timing_open_state (self, dev, goodix_open_state_name (state),
                                  g_get_monotonic_time ());

  switch (state)
    {
    case GOODIX_OPEN_USB_RESET:
      {
        GError *error = NULL;

        if (!self->open_usb_reset_required)
          {
            fpi_ssm_next_state (ssm);
            return;
          }

        if (!g_usb_device_reset (fpi_device_get_usb_device (dev), &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }

        self->open_usb_reset_required = FALSE;
      }

      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_CLAIM_INTERFACE:
      {
        GError *error = NULL;

        if (!g_usb_device_claim_interface (
                fpi_device_get_usb_device (dev), GOODIX_USB_INTERFACE,
                G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }

        self->usb_interface_claimed = TRUE;
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_PING:
      {
        FpiSsm *probe = fpi_ssm_new (dev, goodix_probe_ssm_handler, GOODIX_PROBE_NUM_STATES);
        fpi_ssm_set_data (probe, g_new0 (guint, 1), g_free);
        fpi_ssm_start_subsm (ssm, probe);
      }
      break;

    case GOODIX_OPEN_RESET:
      {
        /* Cold HAL construction deactivates the anchor before any reference
         * outcome. Ordinary actions and in-place repairs do not reset it. */
        self->profile9_fdt.drift_anchor_empty = TRUE;
        goodix_health_reset (&self->health);
        self->capture_callback_pending = FALSE;
        FpiSsm *chip = fpi_ssm_new (dev, goodix_chip_ssm_handler, GOODIX_CHIP_NUM_STATES);

        fpi_ssm_set_data (chip, g_new0 (guint, 1), g_free);
        fpi_ssm_start_subsm (ssm, chip);
      }
      break;

    case GOODIX_OPEN_READ_OTP:
      goodix_cmd_read_otp (ssm, dev);
      break;

    case GOODIX_OPEN_PARSE_OTP:
      {
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_otp_reply (dev, &pl, &pl_len, NULL))
          {
            fpi_ssm_mark_failed (ssm,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Failed to parse OTP response"));
            return;
          }

        g_clear_pointer (&self->otp_data, g_free);
        self->otp_data = g_memdup2 (pl, pl_len);
        self->otp_len = pl_len;

        if (!goodix_device_verify_otp (pl, pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "OTP hash verification failed"));
            return;
          }

        goodix_milan_persistence_prepare (dev);
        goodix_device_parse_otp (pl, pl_len, &self->calib);
        /* Sensor checking reseeds current/default; native static adjustment
         * history is owned by live capture, not HAL reconstruction. */
        self->dynamic_dac.default_dac = self->calib.dac_h;
        if (!goodix_load_psk (self, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_READ_PSK_HASH:
      /* read_psk_hash via production_read(0xB003) */
      goodix_cmd_production_read (ssm, dev, 0xB003);
      break;

    case GOODIX_OPEN_WRITE_PSK:
      {
        /* Check if the sensor PSK hash matches the selected PSK.
         * Parse the production_read response. */
        const guint8 *psk_data;
        gsize psk_data_len;

        if (!goodix_cmd_parse_production_read_reply (dev, 0xB003,
                                                     &psk_data, &psk_data_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to read PSK hash"));
            return;
          }

        /* Compute SHA256 of our PSK and compare */
        {
          g_autoptr(GChecksum) sha = g_checksum_new (G_CHECKSUM_SHA256);
          guint8 expected_hash[32];
          gsize hash_len = 32;

          g_checksum_update (sha, self->psk, GOODIX_PSK_LEN);
          g_checksum_get_digest (sha, expected_hash, &hash_len);

          if (psk_data_len >= 32 && memcmp (psk_data, expected_hash, 32) == 0)
            {
              fp_dbg ("PSK hash matches, no need to write");
              self->psk_write_verify_pending = FALSE;
              fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_GTLS_CLIENT_HELLO);
              return;
            }
        }

        if (self->psk_imported)
          {
            fpi_ssm_mark_failed (
              ssm,
              fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Sensor PSK does not match imported Windows PSK; refusing to overwrite it"));
            return;
          }

        fp_info ("Writing default PSK white box");
        self->psk_write_verify_pending = TRUE;
        goodix_cmd_production_write (ssm, dev, 0xB002, goodix_psk_white_box,
                                     GOODIX_PSK_WHITE_BOX_LEN);
      }
      break;

    case GOODIX_OPEN_VERIFY_PSK_WRITE:
      {
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_production_write_reply (dev, &pl, &pl_len) ||
            pl_len < 1)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse PSK write reply"));
            return;
          }

        if (pl[0] != 0)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "PSK write failed: %u",
                                                           pl[0]));
            return;
          }

        /* Re-read the PSK hash to verify the write before GTLS */
        goodix_cmd_production_read (ssm, dev, 0xB003);
      }
      break;

    case GOODIX_OPEN_GTLS_CLIENT_HELLO:
      {
        if (self->psk_write_verify_pending)
          {
            /* Parse the re-read PSK hash from the previous state */
            const guint8 *psk_data;
            gsize psk_data_len;
            g_autoptr(GChecksum) sha = g_checksum_new (G_CHECKSUM_SHA256);
            guint8 expected_hash[32];
            gsize hash_len = 32;

            if (!goodix_cmd_parse_production_read_reply (dev, 0xB003,
                                                         &psk_data,
                                                         &psk_data_len))
              {
                fpi_ssm_mark_failed (ssm,
                                     fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                               "Failed to re-read PSK hash"));
                return;
              }

            g_checksum_update (sha, self->psk, GOODIX_PSK_LEN);
            g_checksum_get_digest (sha, expected_hash, &hash_len);

            if (psk_data_len < 32 || memcmp (psk_data, expected_hash, 32) != 0)
              {
                fpi_ssm_mark_failed (ssm,
                                     fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                               "PSK hash mismatch after write"));
                return;
              }

            self->psk_write_verify_pending = FALSE;
          }

        FpiSsm *sub = fpi_ssm_new (dev, goodix_gtls_retry_handler, 2);

        self->open_gtls_failed = FALSE;
        fpi_ssm_set_data (sub, g_new0 (GoodixGtlsRetry, 1),
                          (GDestroyNotify) goodix_gtls_retry_free);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_OPEN_UPLOAD_CONFIG:
      {
        self->open_ref_powered = FALSE;

        fp_info ("GTLS handshake completed");
        goodix_cmd_restore_config (ssm, dev, goodix_open_native_result);
      }
      break;

    case GOODIX_OPEN_VALIDATE_CONFIG:
      {
        if (!goodix_cmd_parse_config_reply (dev))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Config upload failed"));
            return;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_CAPTURE_REF:
      goodix_milan_base_start_ensure_subsm (ssm, dev, FALSE);
      break;

    case GOODIX_OPEN_CAPTURE_REF_DONE:
      /* Ordinary allbase failure leaves recovery pending, not a valid image.
       * The cold owner still performs its final query and mode-2 publication. */
      self->open_ref_powered = self->milan_generation != NULL;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_FINAL_FIRMWARE:
      if (!goodix_probe_cancelled (ssm, dev))
        goodix_cmd_probe (ssm, dev, TRUE, goodix_open_native_result);
      break;

    case GOODIX_OPEN_FINAL_SLEEP:
      if (!goodix_probe_cancelled (ssm, dev))
        goodix_cmd_set_sleep_mode_result (ssm, dev, goodix_open_native_result);
      break;

    case GOODIX_OPEN_SLEEP:
      /* Defensive host-error cleanup is separate from the native cold tail. */
      if (self->open_ref_powered)
        goodix_cmd_set_sleep_mode (ssm, dev);
      else
        fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_NUM_STATES);
      break;

    case GOODIX_OPEN_EC_POWER_OFF:
      /* Native successful initialization ends after sleep. Retain the old
       * defensive EC shutdown only when that cleanup has failed. */
      if (fpi_ssm_get_error (ssm))
        goodix_cmd_ec_control (ssm, dev, FALSE);
      else
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_EC_POWER_OFF_DONE:
      self->open_ref_powered = FALSE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_NUM_STATES:
      g_assert_not_reached ();
      break;
    }
}

static void
goodix_cleanup_failed_open (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  g_autoptr(GError) cleanup_error = NULL;

  /* Transport is joined and this open will not retry. A failed open
   * will not receive the ordinary close callback. */
  g_clear_object (&self->cancel);
  g_clear_pointer (&self->otp_data, g_free);
  self->otp_len = 0;
  g_clear_pointer (&self->fw_version, g_free);
  g_clear_pointer (&self->rx.buf, g_free);
  self->reply_payload = NULL;
  self->reply_payload_len = 0;

  if (self->usb_interface_claimed)
    {
      if (!g_usb_device_release_interface (usb_dev, GOODIX_USB_INTERFACE, 0,
                                           &cleanup_error))
        fp_warn ("Failed to release USB interface after open failure: %s",
                 cleanup_error->message);

      self->usb_interface_claimed = FALSE;
      g_clear_error (&cleanup_error);
    }

  if (!g_usb_device_close (usb_dev, &cleanup_error))
    fp_warn ("Failed to close USB device after open failure: %s",
             cleanup_error->message);
}

static void
goodix_open_complete_after_idle (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GError *error = data;

  if (error)
    {
      /* Reset/close ends the transport that could complete retained data.
       * A completion winning idle cancellation may have just appended it. */
      goodix_transport_invalidate (dev);
      self->open_ref_powered = FALSE;
      goodix_milan_generation_retain_process (dev);
      g_clear_pointer (&self->hardware_reference, g_free);
      self->hardware_refresh_pending = FALSE;
      goodix_milan_persistence_clear (dev);
      OPENSSL_cleanse (self->psk, sizeof (self->psk));
      OPENSSL_cleanse (self->gtls.psk, sizeof (self->gtls.psk));
      self->psk_imported = FALSE;
      goodix_debug_timing_open_done (self, dev, error->message);
      fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);

      if (!self->open_recovery_attempted && !self->open_gtls_failed &&
          !fpi_device_action_is_cancelled (dev) &&
          !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          !g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE) &&
          error->domain != FP_DEVICE_RETRY)
        {
          self->open_recovery_attempted = TRUE;
          if (self->usb_interface_claimed)
            {
              g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                              GOODIX_USB_INTERFACE, 0, NULL);
              self->usb_interface_claimed = FALSE;
            }
          self->open_usb_reset_required = TRUE;
          g_clear_error (&error);
          goodix_start_open_ssm (dev);
          return;
        }

      fp_warn ("Device open failed: %s", error->message);
      goodix_cleanup_failed_open (dev);
      fpi_device_open_complete (dev, error);
      return;
    }

  fp_info ("Device initialization complete");
  self->open_ref_powered = FALSE;
  self->open_usb_reset_required = FALSE;
  goodix_debug_timing_open_done (self, dev, NULL);
  self->needs_reinit = FALSE;
  self->session_open = TRUE;
  goodix_session_settle (dev);
  fpi_device_open_complete (dev, NULL);
}

static void
goodix_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;
  /* The SSM is freed on return. Transfer only its completion error to the
   * join callback; the open action and idle owner retain the device. */
  if (error)
    goodix_transport_quiesce (dev, goodix_open_complete_after_idle, error);
  else
    goodix_open_complete_after_idle (dev, NULL);
}

void
goodix_start_open_ssm (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  self->open_gtls_failed = FALSE;
  ssm = fpi_ssm_new_full (dev, goodix_open_ssm_handler,
                          GOODIX_OPEN_NUM_STATES,
                          GOODIX_OPEN_SLEEP,
                          "goodix-open");
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_open_ssm_done);
}

/* ========================================================================
 * Cold hardware recovery
 * ======================================================================== */

static void
goodix_reinit_idle_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *sub;

  /* A USB reset ends the transport that could complete the retained packet. */
  goodix_transport_invalidate (dev);

  fp_info ("Reinitializing hardware session");
  self->action_epoch++;
  goodix_milan_generation_retain_process (dev);
  g_clear_pointer (&self->hardware_reference, g_free);
  self->hardware_refresh_pending = FALSE;
  self->open_recovery_attempted = FALSE;
  self->open_gtls_failed = FALSE;
  self->open_usb_reset_required = TRUE;

  if (self->usb_interface_claimed)
    {
      g_autoptr(GError) release_error = NULL;

      /* This is expected to fail with EINVAL after an S4 reset because the
       * kernel already dropped the claim; recovery proceeds either way. */
      if (!g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                           GOODIX_USB_INTERFACE,
                                           0, &release_error))
        fp_dbg ("Releasing stale USB interface before reinit failed "
                "(expected after S4 reset): %s", release_error->message);

      self->usb_interface_claimed = FALSE;
    }

  sub = fpi_ssm_new_full (dev, goodix_open_ssm_handler,
                          GOODIX_OPEN_NUM_STATES,
                          GOODIX_OPEN_SLEEP,
                          "goodix-reinit");
  fpi_ssm_start_subsm (data, sub);
}

/**
 * If the hardware session is invalid, join reception, release any stale
 * interface claim and run full initialization as a sub-SSM of @ssm. This is
 * also the once-only fallback from warm resume; successful re-keying after
 * system sleep does not enter this USB reset/calibration/reference path.
 * Returns TRUE if reinit was scheduled (caller returns and the parent advances
 * when it completes), FALSE if no reinit was needed.
 */
gboolean
goodix_maybe_start_reinit_subsm (FpiSsm *ssm, FpDevice *dev)
{
  if (!FPI_DEVICE_GOODIX53X5 (dev)->needs_reinit)
    return FALSE;

  /* Join before either interface release or USB reset, just as close does. */
  goodix_transport_quiesce (dev, goodix_reinit_idle_joined, ssm);
  return TRUE;
}

/**
 * TRUE for errors that indicate the USB device/claim is likely stale or
 * gone (e.g. system slept while the device was claimed but idle, so the
 * driver suspend hook never ran). Setting needs_reinit on these makes the
 * next action attempt self-heal with a full reinitialization.
 */
gboolean
goodix_error_indicates_stale_device (const GError *error)
{
  return g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_TIMED_OUT) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_NO_DEVICE) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_NOT_OPEN) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_IO) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_FAILED);
}

/* ========================================================================
 * Close
 * ======================================================================== */

static void
goodix_session_close_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GError *error = NULL;

  self->action_epoch++;
  if (self->cancel)
    g_cancellable_cancel (self->cancel);
  g_clear_object (&self->milan_task);
  g_clear_object (&self->cancel);
  g_clear_object (&self->session_cancel);
  self->session_suspended = FALSE;
  self->session_open = FALSE;
  goodix_clear_pending_result_report (self);
  g_clear_pointer (&self->otp_data, g_free);
  g_clear_pointer (&self->fw_version, g_free);
  goodix_transport_invalidate (dev);
  g_clear_pointer (&self->rx.buf, g_free);
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  g_clear_pointer (&self->pending_persistence_state, g_free);
  goodix_milan_generation_retain_process (dev);
  g_clear_pointer (&self->hardware_reference, g_free);
  self->hardware_refresh_pending = FALSE;
  g_clear_pointer (&self->enroll_transaction,
                   goodix_milan_enrollment_transaction_free);
  goodix_milan_persistence_clear (dev);
  g_clear_error (&self->pending_enroll_error);
  OPENSSL_cleanse (self->psk, sizeof (self->psk));
  OPENSSL_cleanse (self->gtls.psk, sizeof (self->gtls.psk));
  self->psk_imported = FALSE;

  g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                  GOODIX_USB_INTERFACE, 0, &error);
  self->usb_interface_claimed = FALSE;

  fpi_device_close_complete (dev, error);
}

void
goodix_session_close (FpDevice *dev)
{
  /* The paired core rejects close while a power task is pending and admits
   * it for a quiesced suspended session, which needs no hardware I/O here. */
  goodix_session_quiesce (dev, goodix_session_close_joined, NULL);
}

/* ========================================================================
 * Suspend / resume policy
 *
 * Suspend joins every hardware owner, sleeps the sensor and powers the EC
 * off, retaining the host calibration/reference/FDT tuple. Resume reclaims
 * USB and re-keys GTLS without resetting that tuple. Existing hardware faults
 * or failed warm reconstruction take the cold path once before completion.
 * ======================================================================== */

static void
goodix_suspend_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixRequestedMode requested_mode = self->requested_mode;

  /* Retire packets and notifications, not the retained HAL's mode or bases. */
  goodix_transport_invalidate (dev);
  self->requested_mode = requested_mode;
  if (data)
    self->needs_reinit = TRUE;
  self->suspend_pending = FALSE;
  self->session_suspended = TRUE;
  fpi_device_suspend_complete (dev, data);
}

static void
goodix_suspend_power_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FPI_DEVICE_GOODIX53X5 (dev)->task_ssm = NULL;
  goodix_transport_quiesce (dev, goodix_suspend_joined, error);
}

static void
goodix_suspend_power (FpiSsm *ssm, FpDevice *dev)
{
  if (fpi_ssm_get_cur_state (ssm) == 0)
    goodix_cmd_set_sleep_mode (ssm, dev);
  else
    goodix_cmd_ec_control (ssm, dev, FALSE);
}

static void
goodix_suspend_service_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->session_cancel);
  self->session_cancel = g_cancellable_new ();
  ssm = fpi_ssm_new (dev, goodix_suspend_power, 2);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_suspend_power_done);
}

void
goodix_session_suspend (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->suspend_pending = TRUE;
  goodix_session_quiesce (dev, goodix_suspend_service_joined, NULL);
}

typedef enum {
  GOODIX_RESUME_WARM,
  GOODIX_RESUME_COLD,
  GOODIX_RESUME_NUM_STATES,
} GoodixResumeState;

typedef struct
{
  gint64   started_us;
  gboolean cold;
} GoodixResumeData;

static void
goodix_resume_joined (FpDevice *dev, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GError *error = data;

  self->session_suspended = FALSE;
  if (error)
    {
      /* Neither cancellation nor failed reconstruction grants readiness. */
      self->needs_reinit = TRUE;
      goodix_transport_invalidate (dev);
      fp_warn ("Hardware reconstruction after resume failed: %s", error->message);
    }
  else
    {
      self->needs_reinit = FALSE;
    }
  goodix_session_settle (dev);
  fpi_device_resume_complete (dev, error);
}

static void
goodix_resume_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
#ifdef GOODIX53X5_DEBUG
  GoodixResumeData *data = fpi_ssm_get_data (ssm);

  g_message ("Hardware resume %s (%s): %.2f ms",
             error ? "failed" : "ready", data->cold ? "cold" : "warm",
             (g_get_monotonic_time () - data->started_us) / 1000.0);
#endif
  FPI_DEVICE_GOODIX53X5 (dev)->task_ssm = NULL;
  if (error)
    goodix_transport_quiesce (dev, goodix_resume_joined, error);
  else
    goodix_resume_joined (dev, NULL);
}

/* The physical reader is joined before either interface operation. Release
 * also clears libusb's remembered claim after the kernel reset-resumes S4. */
static void
goodix_resume_warm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (goodix_probe_cancelled (ssm, dev))
    return;
  if (fpi_ssm_get_cur_state (ssm) == 0)
    {
      g_autoptr(GError) error = NULL;

      if (self->usb_interface_claimed)
        {
          /* A stale release can return EINVAL after reset-resume. The fresh
          * claim with kernel-driver detach establishes actual ownership. */
          if (!g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                               GOODIX_USB_INTERFACE, 0, &error))
            fp_dbg ("Releasing USB interface before warm resume: %s", error->message);
          self->usb_interface_claimed = FALSE;
          g_clear_error (&error);
        }
      if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev),
                                         GOODIX_USB_INTERFACE,
                                         G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
                                         &error))
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      self->usb_interface_claimed = TRUE;
      fpi_ssm_next_state (ssm);
    }
  else
    {
      /* usbinterface!180020970 resume uses the same two three-attempt groups
       * as cold initialization, not the single group of the event restart.
       * Reuse only the handshake owner, with the already selected PSK. */
      FpiSsm *sub = fpi_ssm_new (dev, goodix_gtls_retry_handler, 2);

      fpi_ssm_set_data (sub, g_new0 (GoodixGtlsRetry, 1),
                        (GDestroyNotify) goodix_gtls_retry_free);
      fpi_ssm_start_subsm (ssm, sub);
    }
}

static void
goodix_resume_warm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiSsm *parent = fpi_ssm_get_data (ssm);

  if (!error)
    {
      fpi_ssm_mark_completed (parent);
    }
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
           g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED) ||
           g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE))
    {
      fpi_ssm_mark_failed (parent, error);
    }
  else
    {
      fp_warn ("Warm resume failed; reconstructing hardware once: %s", error->message);
      g_clear_error (&error);
      FPI_DEVICE_GOODIX53X5 (dev)->needs_reinit = TRUE;
      fpi_ssm_next_state (parent);
    }
}

static void
goodix_resume_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixResumeData *data = fpi_ssm_get_data (ssm);

  switch ((GoodixResumeState) fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_RESUME_WARM:
      if (self->needs_reinit)
        {
          fpi_ssm_next_state (ssm);
        }
      else
        {
          FpiSsm *warm = fpi_ssm_new (dev, goodix_resume_warm, 2);

          fpi_ssm_set_data (warm, ssm, NULL);
          fpi_ssm_start (warm, goodix_resume_warm_done);
        }
      break;

    case GOODIX_RESUME_COLD:
      data->cold = TRUE;
      if (!goodix_maybe_start_reinit_subsm (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_RESUME_NUM_STATES:
      g_assert_not_reached ();
    }
}

void
goodix_session_resume (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixResumeData *data = g_new0 (GoodixResumeData, 1);
  FpiSsm *ssm;

  data->started_us = g_get_monotonic_time ();
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  g_clear_object (&self->session_cancel);
  self->session_cancel = g_cancellable_new ();
  ssm = fpi_ssm_new (dev, goodix_resume_handler, GOODIX_RESUME_NUM_STATES);
  fpi_ssm_set_data (ssm, data, g_free);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_resume_done);
}
