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
#include "goodix53x5-private.h"
#include "goodix53x5-transport.h"
#include "goodix53x5-commands.h"
#include "goodix53x5-calibration.h"
#include "goodix53x5-session.h"

#include <string.h>
#include <openssl/rand.h>

#define GOODIX_OPEN_FDT_MAX_RETRIES 2

/* Open SSM — full device initialization */
typedef enum {
  GOODIX_OPEN_USB_RESET = 0,
  GOODIX_OPEN_CLAIM_INTERFACE,
  GOODIX_OPEN_PING,
  GOODIX_OPEN_READ_FW_VERSION,
  GOODIX_OPEN_RESET,
  GOODIX_OPEN_READ_CHIP_ID,
  GOODIX_OPEN_READ_OTP,
  GOODIX_OPEN_PARSE_OTP,
  GOODIX_OPEN_READ_PSK_HASH,
  GOODIX_OPEN_WRITE_PSK,
  GOODIX_OPEN_VERIFY_PSK_WRITE,
  GOODIX_OPEN_GTLS_CLIENT_HELLO,
  GOODIX_OPEN_GTLS_RECV_IDENTITY,
  GOODIX_OPEN_GTLS_SEND_VERIFY,
  GOODIX_OPEN_GTLS_RECV_DONE,
  GOODIX_OPEN_UPLOAD_CONFIG,
  GOODIX_OPEN_FDT_TX_ON,
  GOODIX_OPEN_VALIDATE_FDT,
  GOODIX_OPEN_FDT_TX_ON_2,
  GOODIX_OPEN_VALIDATE_FDT_2,
  GOODIX_OPEN_GENERATE_FDT_BASE,
  GOODIX_OPEN_SLEEP,
  GOODIX_OPEN_NUM_STATES,
} GoodixOpenState;


/* All-zero PSK */
static const guint8 goodix_psk[GOODIX_PSK_LEN] = { 0 };

/* PSK white box for writing all-zero PSK */
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

/* ========================================================================
 * Open SSM — full device initialization
 * ======================================================================== */

static void
goodix_open_ssm_handler (FpiSsm   *ssm,
                         FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixOpenState state = fpi_ssm_get_cur_state (ssm);

  switch (state)
    {
    case GOODIX_OPEN_USB_RESET:
      {
        GError *error = NULL;

        if (!g_usb_device_reset (fpi_device_get_usb_device (dev), &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
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
      goodix_cmd_ping (ssm, dev);
      break;

    case GOODIX_OPEN_READ_FW_VERSION:
      goodix_cmd_read_fw_version (ssm, dev);
      break;

    case GOODIX_OPEN_RESET:
      {
        /* Parse the firmware version reply before sending the reset */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_fw_version_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        g_clear_pointer (&self->fw_version, g_free);
        self->fw_version = g_strndup ((const gchar *) pl,
                                      strnlen ((const gchar *) pl, pl_len));

        goodix_cmd_reset_sensor (ssm, dev);
      }
      break;

    case GOODIX_OPEN_READ_CHIP_ID:
      goodix_cmd_read_chip_id (ssm, dev);
      break;

    case GOODIX_OPEN_READ_OTP:
      {
        /* Parse the chip ID reply before reading the OTP */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;
        guint32 chip_id;

        if (!goodix_cmd_parse_chip_id_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        if (pl_len != 4)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Unexpected chip ID reply length: %zu",
                                                           pl_len));
            return;
          }

        chip_id = goodix_crypto_decode_u32 (pl);
        fp_dbg ("Chip ID: 0x%08x", chip_id);

        goodix_cmd_read_otp (ssm, dev);
      }
      break;

    case GOODIX_OPEN_PARSE_OTP:
      {
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

        goodix_device_parse_otp (pl, pl_len, &self->calib);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_READ_PSK_HASH:
      /* read_psk_hash via production_read(0xB003) */
      goodix_cmd_production_read (ssm, dev, 0xB003);
      break;

    case GOODIX_OPEN_WRITE_PSK:
      {
        /* Check if PSK hash matches our all-zero PSK.
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

          g_checksum_update (sha, goodix_psk, GOODIX_PSK_LEN);
          g_checksum_get_digest (sha, expected_hash, &hash_len);

          if (psk_data_len >= 32 && memcmp (psk_data, expected_hash, 32) == 0)
            {
              fp_dbg ("PSK hash matches, no need to write");
              self->psk_write_verify_pending = FALSE;
              fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_GTLS_CLIENT_HELLO);
              return;
            }
        }

        /* Need to write PSK white box */
        fp_info ("Writing PSK white box");
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

            g_checksum_update (sha, goodix_psk, GOODIX_PSK_LEN);
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

        /* Generate client_random and send via MCU */
        RAND_bytes (self->gtls.client_random, 32);
        goodix_crypto_gtls_init (&self->gtls, goodix_psk);
        RAND_bytes (self->gtls.client_random, 32);
        self->gtls.state = 2;

        goodix_cmd_mcu_send (ssm, dev, 0xFF01, self->gtls.client_random, 32);
      }
      break;

    case GOODIX_OPEN_GTLS_RECV_IDENTITY:
      /* Receive MCU message with server random + identity */
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;

    case GOODIX_OPEN_GTLS_SEND_VERIFY:
      {
        /* Parse server identity response */
        const guint8 *mcu_data;
        gsize mcu_len;

        if (!goodix_cmd_parse_mcu_reply (dev, 0xFF02, &mcu_data, &mcu_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse GTLS server identity"));
            return;
          }

        if (mcu_len != 0x40)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Wrong GTLS identity payload size: %zu",
                                                           mcu_len));
            return;
          }

        memcpy (self->gtls.server_random, mcu_data, 32);
        memcpy (self->gtls.server_identity, mcu_data + 32, 32);

        /* Derive session keys */
        goodix_crypto_gtls_derive_keys (&self->gtls);

        /* Verify identity */
        if (!goodix_crypto_gtls_verify_identity (&self->gtls))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "GTLS identity verification failed"));
            return;
          }

        /* Send client identity + \xee\xee\xee\xee via MCU */
        {
          guint8 verify_data[36];
          memcpy (verify_data, self->gtls.client_identity, 32);
          memset (verify_data + 32, 0xEE, 4);

          goodix_cmd_mcu_send (ssm, dev, 0xFF03, verify_data, 36);
        }

        self->gtls.state = 4;
      }
      break;

    case GOODIX_OPEN_GTLS_RECV_DONE:
      /* Receive MCU done message */
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;

    case GOODIX_OPEN_UPLOAD_CONFIG:
      {
        /* First validate GTLS done response */
        {
          const guint8 *mcu_data;
          gsize mcu_len;

          if (!goodix_cmd_parse_mcu_reply (dev, 0xFF04, &mcu_data, &mcu_len))
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "Failed to parse GTLS done"));
              return;
            }

          if (mcu_len >= 4)
            {
              guint32 result = mcu_data[0] | ((guint32) mcu_data[1] << 8) |
                               ((guint32) mcu_data[2] << 16) |
                               ((guint32) mcu_data[3] << 24);
              if (result != 0)
                {
                  fpi_ssm_mark_failed (ssm,
                                       fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                 "GTLS handshake failed: %u",
                                                                 result));
                  return;
                }
            }
        }

        self->gtls.hmac_client_counter = self->gtls.hmac_client_counter_init;
        self->gtls.hmac_server_counter = self->gtls.hmac_server_counter_init;
        self->gtls.state = 5;
        self->open_fdt_retries = 0;

        fp_info ("GTLS handshake completed");

        /* Build and upload config */
        gsize cfg_len;
        const guint8 *def_cfg = goodix_device_get_default_config (&cfg_len);
        guint8 *cfg = g_memdup2 (def_cfg, cfg_len);

        goodix_device_patch_config (cfg, cfg_len, &self->calib);
        goodix_cmd_upload_config (ssm, dev, cfg, cfg_len);
        g_free (cfg);
      }
      break;

    case GOODIX_OPEN_FDT_TX_ON:
      {
        /* Validate the config upload reply before the first FDT TX-on */
        if (!goodix_cmd_parse_config_reply (dev))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Config upload failed"));
            return;
          }

        /* FDT manual operation with TX enabled */
        goodix_cmd_fdt_manual (ssm, dev, TRUE, self->calib.fdt_base_manual);
      }
      break;

    case GOODIX_OPEN_VALIDATE_FDT:
      {
        /* Parse FDT response and save */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_fdt_manual_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        /* FDT data is the payload after 4 bytes of irq+touch_flag */
        g_free (self->fdt_data_tx_on);
        self->fdt_data_tx_on = g_memdup2 (pl + 4, GOODIX_FDT_BASE_LEN);

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_FDT_TX_ON_2:
      /* Second FDT TX on */
      goodix_cmd_fdt_manual (ssm, dev, TRUE, self->calib.fdt_base_manual);
      break;

    case GOODIX_OPEN_VALIDATE_FDT_2:
      {
        /* Parse and validate second FDT */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_fdt_manual_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        /* Validate against the open-time FDT base we just recorded. */
        if (!goodix_device_is_fdt_base_valid (pl + 4,
                                              self->fdt_data_tx_on,
                                              GOODIX_FDT_BASE_LEN,
                                              self->calib.delta_fdt))
          {
            if (self->open_fdt_retries++ < GOODIX_OPEN_FDT_MAX_RETRIES)
              {
                fp_warn ("Open FDT validation unstable, retrying (%u/%u)",
                         self->open_fdt_retries,
                         GOODIX_OPEN_FDT_MAX_RETRIES);
                g_free (self->fdt_data_tx_on);
                self->fdt_data_tx_on = g_memdup2 (pl + 4,
                                                  GOODIX_FDT_BASE_LEN);
                fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_FDT_TX_ON_2);
                return;
              }

            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                           "Open FDT baseline did not stabilize"));
            return;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_GENERATE_FDT_BASE:
      {
        /* Generate FDT base from TX-on data */
        if (self->fdt_data_tx_on)
          {
            guint8 fdt_base[GOODIX_FDT_BASE_LEN];
            goodix_device_generate_fdt_base (self->fdt_data_tx_on,
                                             GOODIX_FDT_BASE_LEN, fdt_base);
            memcpy (self->calib.fdt_base_down, fdt_base, GOODIX_FDT_BASE_LEN);
            memcpy (self->calib.fdt_base_up, fdt_base, GOODIX_FDT_BASE_LEN);
            memcpy (self->calib.fdt_base_manual, fdt_base,
                    GOODIX_FDT_BASE_LEN);
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_SLEEP:
      goodix_cmd_set_sleep_mode (ssm, dev);
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
goodix_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;

  /* Clean up temp data */
  g_clear_pointer (&self->fdt_data_tx_on, g_free);

  if (error)
    {
      fp_warn ("Device open failed: %s", error->message);

      goodix_cleanup_failed_open (dev);
      fpi_device_open_complete (dev, error);
      return;
    }

  fp_info ("Device initialization complete");
  self->needs_reinit = FALSE;
  fpi_device_open_complete (dev, NULL);
}

void
goodix_start_open_ssm (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, goodix_open_ssm_handler,
                      GOODIX_OPEN_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_open_ssm_done);
}

/* ========================================================================
 * Post-sleep reinitialization
 * ======================================================================== */

/**
 * If the device needs reinitialization (system sleep happened while it was
 * open), release any stale interface claim and run the full open-time
 * initialization SSM as a sub-SSM of @ssm. The full sequence is required:
 * after an S4 reset/re-enumeration the kernel rebinds cdc_acm to our
 * interface, so recovery needs the same USB reset + claim-with-detach +
 * GTLS handshake as a fresh open.
 *
 * Returns TRUE if a reinit sub-SSM was started (caller returns and the
 * parent advances when it completes), FALSE if no reinit was needed.
 */
gboolean
goodix_maybe_start_reinit_subsm (FpiSsm   *ssm,
                                 FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *sub;

  if (!self->needs_reinit)
    return FALSE;

  fp_info ("Reinitializing device after system sleep");

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

  sub = fpi_ssm_new (dev, goodix_open_ssm_handler,
                     GOODIX_OPEN_NUM_STATES);
  fpi_ssm_start_subsm (ssm, sub);
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
 * Suspend / resume policy
 * ======================================================================== */

void
goodix_session_suspend (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  /* Any system sleep while the device is open may invalidate the USB claim
   * and GTLS session: S4 resets or re-enumerates the device and rebinds the
   * cdc_acm kernel driver to our interface. Force a full reinitialization at
   * the start of the next action regardless of what we were doing when sleep
   * hit. A successfully completed action clears this again. */
  self->needs_reinit = TRUE;

  if (action != FPI_DEVICE_ACTION_VERIFY &&
      action != FPI_DEVICE_ACTION_IDENTIFY)
    {
      fpi_device_suspend_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  if (self->blocking_ssm)
    {
      /* Cancel the pending read; suspend_complete called from rx callback */
      self->suspend_pending = TRUE;
      g_cancellable_cancel (self->cancel);
    }
  else
    {
      /* Not in a blocking read (e.g. mid-capture), complete immediately */
      fpi_device_suspend_complete (dev, NULL);
    }
}

void
goodix_session_resume (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action != FPI_DEVICE_ACTION_VERIFY &&
      action != FPI_DEVICE_ACTION_IDENTIFY)
    {
      fpi_device_resume_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  /* Restart the SSM from the re-arm state (resubmits USB reads). Only
   * reachable if suspend completed successfully mid-capture and the SSM
   * armed a blocking wait before the system actually slept. */
  if (self->blocking_ssm)
    {
      fpi_ssm_jump_to_state (self->blocking_ssm, self->blocking_resume_state);
      self->blocking_ssm = NULL;
    }

  fpi_device_resume_complete (dev, NULL);
}
