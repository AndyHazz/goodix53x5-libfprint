/*
 * Goodix 53x5 driver for libfprint
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
#include "goodix53x5.h"
#include "fpi-print.h"
#include "sigfm/sigfm.hpp"

#include <string.h>
#include <openssl/rand.h>

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

G_DEFINE_TYPE (FpiDeviceGoodix53x5, fpi_device_goodix53x5,
               FP_TYPE_DEVICE)

/* ========================================================================
 * USB I/O helpers
 * ======================================================================== */

static void
goodix_tx_cb (FpiUsbTransfer *transfer,
              FpDevice       *dev,
              gpointer        user_data,
              GError         *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

/**
 * Send a complete protocol message, splitting into USB chunks.
 * Advances the SSM on completion.
 */
static void
goodix_send_message (FpiSsm   *ssm,
                     FpDevice *dev,
                     guint8    category,
                     guint8    command,
                     const guint8 *payload,
                     gsize     payload_len,
                     gboolean  use_checksum)
{
  gsize msg_len;
  guint8 *msg;
  FpiUsbTransfer *transfer;
  guint8 cmd_byte;

  msg = goodix_proto_build_message (category, command, payload, payload_len,
                                    use_checksum, &msg_len);
  cmd_byte = msg[0];

  /* We need to send chunks of 64 bytes. The protocol pads writes to 64.
   * For the first chunk, send the message bytes.
   * For continuation chunks, prepend cmd_byte | 1. */
  /* Since libfprint transfers handle padding, we send the whole thing
   * as one bulk write if it fits, or chain if not.
   * Actually, looking at the Python: each chunk is exactly 64 bytes, padded.
   * The USB protocol.py write() pads to 64 bytes.
   * Let's build a single contiguous padded buffer with proper chunking. */

  gsize total_chunks = 0;
  gsize padded_len = 0;

  /* Calculate how many chunks we need */
  if (msg_len <= GOODIX_USB_CHUNK_SIZE)
    {
      total_chunks = 1;
      padded_len = GOODIX_USB_CHUNK_SIZE;
    }
  else
    {
      /* First chunk: 64 bytes of message data */
      gsize remaining = msg_len - GOODIX_USB_CHUNK_SIZE;
      /* Each continuation chunk carries 63 bytes of data (1 byte for marker) */
      gsize cont_chunks = (remaining + 62) / 63;
      total_chunks = 1 + cont_chunks;
      padded_len = total_chunks * GOODIX_USB_CHUNK_SIZE;
    }

  guint8 *chunked = g_malloc0 (padded_len);

  if (total_chunks == 1)
    {
      memcpy (chunked, msg, msg_len);
    }
  else
    {
      /* First chunk */
      memcpy (chunked, msg, GOODIX_USB_CHUNK_SIZE);

      gsize src_offset = GOODIX_USB_CHUNK_SIZE;
      gsize dst_offset = GOODIX_USB_CHUNK_SIZE;

      for (gsize chunk = 1; chunk < total_chunks; chunk++)
        {
          chunked[dst_offset] = cmd_byte | 1;
          gsize data_in_chunk = MIN (63, msg_len - src_offset);
          if (data_in_chunk > 0)
            memcpy (chunked + dst_offset + 1, msg + src_offset, data_in_chunk);
          src_offset += data_in_chunk;
          dst_offset += GOODIX_USB_CHUNK_SIZE;
        }
    }

  g_free (msg);

  transfer = fpi_usb_transfer_new (dev);
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX_EP_OUT,
                                   chunked, padded_len, g_free);
  fpi_usb_transfer_submit (transfer, GOODIX_CMD_TIMEOUT, NULL,
                           goodix_tx_cb, NULL);
}

/* Forward declarations */
static void goodix_rx_cb (FpiUsbTransfer *transfer,
                          FpDevice       *dev,
                          gpointer        user_data,
                          GError         *error);

/**
 * Start receiving a message. Submits a bulk IN read.
 * The callback handles reassembly and re-submits if more chunks needed.
 * Stores timeout/cancellable so continuation reads use the same parameters.
 */
static void
goodix_recv_start (FpiSsm       *ssm,
                   FpDevice     *dev,
                   guint         timeout_ms,
                   GCancellable *cancellable)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiUsbTransfer *transfer;

  goodix_proto_rx_reset (&self->rx);
  self->rx_timeout = timeout_ms;
  self->rx_cancellable = cancellable;

  transfer = fpi_usb_transfer_new (dev);
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX_EP_IN, GOODIX_USB_CHUNK_SIZE);
  fpi_usb_transfer_submit (transfer, timeout_ms, cancellable,
                           goodix_rx_cb, NULL);
}

static void
goodix_rx_cb (FpiUsbTransfer *transfer,
              FpDevice       *dev,
              gpointer        user_data,
              GError         *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiUsbTransfer *next;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* Skip zero-length reads — resubmit with same timeout/cancellable */
  if (transfer->actual_length == 0)
    {
      next = fpi_usb_transfer_new (dev);
      next->ssm = transfer->ssm;
      fpi_usb_transfer_fill_bulk (next, GOODIX_EP_IN, GOODIX_USB_CHUNK_SIZE);
      fpi_usb_transfer_submit (next, self->rx_timeout, self->rx_cancellable,
                               goodix_rx_cb, NULL);
      return;
    }

  if (!goodix_proto_rx_feed_chunk (&self->rx, transfer->buffer,
                                   transfer->actual_length))
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Protocol reassembly error"));
      return;
    }

  if (goodix_proto_rx_complete (&self->rx))
    {
      /* Message complete — advance SSM */
      fpi_ssm_next_state (transfer->ssm);
    }
  else
    {
      /* Need more chunks — use stored timeout/cancellable for continuations.
       * For finger-wait (timeout=0/infinite), once we start getting data
       * the remaining chunks should arrive quickly, so use DATA_TIMEOUT. */
      next = fpi_usb_transfer_new (dev);
      next->ssm = transfer->ssm;
      fpi_usb_transfer_fill_bulk (next, GOODIX_EP_IN, GOODIX_USB_CHUNK_SIZE);
      fpi_usb_transfer_submit (next, GOODIX_DATA_TIMEOUT, self->rx_cancellable,
                               goodix_rx_cb, NULL);
    }
}

/**
 * Receive with cancellable support (for finger wait).
 * Uses infinite timeout (0) so the read blocks until the sensor sends data.
 */
static void
goodix_recv_start_cancellable (FpiSsm       *ssm,
                               FpDevice     *dev,
                               GCancellable *cancellable)
{
  goodix_recv_start (ssm, dev, 0, cancellable);
}

/* ========================================================================
 * Command sub-SSM: send → recv ACK → recv data
 * ======================================================================== */

static void
goodix_cmd_ssm_handler (FpiSsm   *ssm,
                        FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixCmd *cmd = self->cmd;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CMD_SEND:
      goodix_send_message (ssm, dev, cmd->category, cmd->command,
                           cmd->payload, cmd->payload_len, cmd->use_checksum);
      break;

    case GOODIX_CMD_RECV_ACK:
      goodix_recv_start (ssm, dev, GOODIX_ACK_TIMEOUT, NULL);
      break;

    case GOODIX_CMD_RECV_DATA:
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;
    }
}


/**
 * Launch a command sub-SSM that sends a command and receives the ACK.
 * If expect_data is TRUE, also receives the data response.
 */
static void
goodix_run_cmd (FpiSsm       *parent_ssm,
                FpDevice     *dev,
                guint8        category,
                guint8        command,
                const guint8 *payload,
                gsize         payload_len,
                gboolean      expect_data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *cmd_ssm;
  GoodixCmd *cmd;

  cmd = g_new0 (GoodixCmd, 1);
  cmd->category = category;
  cmd->command = command;
  cmd->use_checksum = TRUE;

  if (payload_len > 0 && payload != NULL)
    {
      cmd->payload = g_memdup2 (payload, payload_len);
      cmd->payload_len = payload_len;
    }
  else
    {
      cmd->payload = NULL;
      cmd->payload_len = 0;
    }

  g_free (self->cmd ? self->cmd->payload : NULL);
  g_free (self->cmd);
  self->cmd = cmd;

  cmd_ssm = fpi_ssm_new_full (dev, goodix_cmd_ssm_handler,
                               expect_data ? GOODIX_CMD_NUM_STATES : GOODIX_CMD_RECV_DATA,
                               expect_data ? GOODIX_CMD_NUM_STATES : GOODIX_CMD_RECV_DATA,
                               "goodix-cmd");

  fpi_ssm_start_subsm (parent_ssm, cmd_ssm);
}

/**
 * Launch a command sub-SSM with a specific ACK timeout.
 * For FDT operations that need a long timeout, we handle it slightly
 * differently — send, then recv with custom timeout.
 */

/* ========================================================================
 * Helpers to build specific protocol payloads
 * ======================================================================== */

static void
goodix_build_fdt_payload (guint8  op_code,
                          guint8  fdt_op,
                          const guint8 *fdt_base,
                          guint8 **out_payload,
                          gsize   *out_len)
{
  gsize len = 2 + GOODIX_FDT_BASE_LEN;
  guint8 *payload = g_malloc (len);

  payload[0] = op_code;
  payload[1] = 1; /* always 1 */
  memcpy (payload + 2, fdt_base, GOODIX_FDT_BASE_LEN);

  *out_payload = payload;
  *out_len = len;
}

static void
goodix_build_image_request (gboolean  tx_enable,
                            gboolean  hv_enable,
                            gboolean  is_finger,
                            guint16   dac,
                            guint8   *out_request)
{
  guint8 op_code = tx_enable ? 0x01 : 0x81;
  guint8 hv_value = hv_enable ? GOODIX_HV_VALUE : 0x10;

  if (is_finger)
    op_code |= 0x40;

  out_request[0] = op_code;
  out_request[1] = hv_value;
  out_request[2] = dac & 0xFF;
  out_request[3] = (dac >> 8) & 0xFF;
}

/* ========================================================================
 * Open SSM — full device initialization
 * ======================================================================== */

/**
 * Callback for the empty-buffer drain read.
 * Timeout is expected (means buffer is empty) — advance either way.
 */
static void
goodix_empty_buf_cb (FpiUsbTransfer *transfer,
                     FpDevice       *dev,
                     gpointer        user_data,
                     GError         *error)
{
  g_clear_error (&error);
  fpi_ssm_next_state (transfer->ssm);
}

static void
goodix_open_ssm_handler (FpiSsm   *ssm,
                         FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint8 payload[8];
  guint8 *p;
  gsize plen;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_OPEN_CLAIM_INTERFACE:
      {
        GError *error = NULL;

        if (!g_usb_device_claim_interface (
                fpi_device_get_usb_device (dev),
                GOODIX_USB_INTERFACE, 0, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_EMPTY_BUFFER:
      /* Try to read any stale data with a short timeout.
       * If it times out, that's fine — buffer is empty, move on. */
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk (transfer, GOODIX_EP_IN,
                                    GOODIX_USB_CHUNK_SIZE);
        fpi_usb_transfer_submit (transfer, GOODIX_EMPTY_TIMEOUT, NULL,
                                 goodix_empty_buf_cb, NULL);
      }
      break;

    case GOODIX_OPEN_PING:
      /* ping: category=0, command=0, payload=\x00\x00 */
      payload[0] = 0x00;
      payload[1] = 0x00;
      goodix_run_cmd (ssm, dev, 0x0, 0x0, payload, 2, FALSE);
      break;

    case GOODIX_OPEN_READ_FW_VERSION:
      /* read_firmware_version: category=0xA, command=4, payload=\x00\x00 */
      payload[0] = 0x00;
      payload[1] = 0x00;
      goodix_run_cmd (ssm, dev, 0xA, 0x4, payload, 2, TRUE);
      break;

    case GOODIX_OPEN_RESET:
      /* reset type 0, irq_status=false: msg = 0b001 | (20<<8) = 0x1401 */
      {
        guint16 msg = 0x01 | (20 << 8);
        payload[0] = msg & 0xFF;
        payload[1] = (msg >> 8) & 0xFF;
        goodix_run_cmd (ssm, dev, 0xA, 0x1, payload, 2, FALSE);
      }
      break;

    case GOODIX_OPEN_READ_CHIP_ID:
      /* read_data(addr=0, size=4): category=0x8, command=0x1 */
      payload[0] = 0x00;                /* \x00 */
      payload[1] = 0x00; payload[2] = 0x00; /* addr LE */
      payload[3] = 0x04; payload[4] = 0x00; /* size LE */
      goodix_run_cmd (ssm, dev, 0x8, 0x1, payload, 5, TRUE);
      break;

    case GOODIX_OPEN_READ_OTP:
      /* read_otp: category=0xA, command=0x3, payload=\x00\x00 */
      payload[0] = 0x00;
      payload[1] = 0x00;
      goodix_run_cmd (ssm, dev, 0xA, 0x3, payload, 2, TRUE);
      break;

    case GOODIX_OPEN_PARSE_OTP:
      {
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse OTP response"));
            return;
          }

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
      {
        /* read_psk_hash via production_read(0xB003) */
        guint32 read_type = 0xB003;
        payload[0] = read_type & 0xFF;
        payload[1] = (read_type >> 8) & 0xFF;
        payload[2] = (read_type >> 16) & 0xFF;
        payload[3] = (read_type >> 24) & 0xFF;
        goodix_run_cmd (ssm, dev, 0xE, 0x2, payload, 4, TRUE);
      }
      break;

    case GOODIX_OPEN_WRITE_PSK:
      {
        /* Check if PSK hash matches our all-zero PSK.
         * Parse the production_read response. */
        guint8 cat, cmd;
        const guint8 *pl, *psk_data;
        gsize pl_len, psk_data_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
            !goodix_proto_parse_production_read (pl, pl_len, 0xB003,
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
              fpi_ssm_next_state (ssm);
              return;
            }
        }

        /* Need to write PSK white box */
        fp_info ("Writing PSK white box");
        {
          gsize wb_payload_len = 4 + 4 + GOODIX_PSK_WHITE_BOX_LEN;
          g_autofree guint8 *wb_payload = g_malloc (wb_payload_len);
          guint32 data_type = 0xB002;
          guint32 data_size = GOODIX_PSK_WHITE_BOX_LEN;

          wb_payload[0] = data_type & 0xFF;
          wb_payload[1] = (data_type >> 8) & 0xFF;
          wb_payload[2] = (data_type >> 16) & 0xFF;
          wb_payload[3] = (data_type >> 24) & 0xFF;
          wb_payload[4] = data_size & 0xFF;
          wb_payload[5] = (data_size >> 8) & 0xFF;
          wb_payload[6] = (data_size >> 16) & 0xFF;
          wb_payload[7] = (data_size >> 24) & 0xFF;
          memcpy (wb_payload + 8, goodix_psk_white_box,
                  GOODIX_PSK_WHITE_BOX_LEN);

          goodix_run_cmd (ssm, dev, 0xE, 0x1, wb_payload, wb_payload_len,
                          TRUE);
        }
      }
      break;

    case GOODIX_OPEN_GTLS_CLIENT_HELLO:
      {
        /* Generate client_random and send via MCU */
        RAND_bytes (self->gtls.client_random, 32);
        goodix_crypto_gtls_init (&self->gtls, goodix_psk);
        RAND_bytes (self->gtls.client_random, 32);
        self->gtls.state = 2;

        goodix_proto_build_mcu_message (0xFF01, self->gtls.client_random, 32,
                                        &p, &plen);
        goodix_run_cmd (ssm, dev, 0xD, 0x1, p, plen, FALSE);
        g_free (p);
      }
      break;

    case GOODIX_OPEN_GTLS_RECV_IDENTITY:
      /* Receive MCU message with server random + identity */
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;

    case GOODIX_OPEN_GTLS_SEND_VERIFY:
      {
        /* Parse server identity response */
        guint8 cat, cmd;
        const guint8 *pl, *mcu_data;
        gsize pl_len, mcu_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
            !goodix_proto_parse_mcu_message (pl, pl_len, 0xFF02,
                                             &mcu_data, &mcu_len))
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

          goodix_proto_build_mcu_message (0xFF03, verify_data, 36, &p, &plen);
          goodix_run_cmd (ssm, dev, 0xD, 0x1, p, plen, FALSE);
          g_free (p);
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
          guint8 cat, cmd;
          const guint8 *pl, *mcu_data;
          gsize pl_len, mcu_len;

          if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
              !goodix_proto_parse_mcu_message (pl, pl_len, 0xFF04,
                                               &mcu_data, &mcu_len))
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

        fp_info ("GTLS handshake completed");

        /* Build and upload config */
        gsize cfg_len;
        const guint8 *def_cfg = goodix_device_get_default_config (&cfg_len);
        guint8 *cfg = g_memdup2 (def_cfg, cfg_len);

        goodix_device_patch_config (cfg, cfg_len, &self->calib);
        goodix_run_cmd (ssm, dev, 0x9, 0x0, cfg, cfg_len, TRUE);
        g_free (cfg);
      }
      break;

    case GOODIX_OPEN_FDT_TX_ON:
      {
        /* FDT manual operation with TX enabled: op_code=0x0D */
        guint8 manual_payload[1 + GOODIX_FDT_BASE_LEN];
        manual_payload[0] = 0x0D;
        memcpy (manual_payload + 1, self->calib.fdt_base_manual,
                GOODIX_FDT_BASE_LEN);

        goodix_build_fdt_payload (manual_payload[0], 3, manual_payload + 1,
                                  &p, &plen);
        /* Send as FDT MANUAL: category=3, command=3 (MANUAL=3) */
        goodix_run_cmd (ssm, dev, 0x3, 0x3, p, plen, TRUE);
        g_free (p);
      }
      break;

    case GOODIX_OPEN_IMAGE_TX_ON:
      {
        /* Parse FDT response and save */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse FDT response"));
            return;
          }

        /* FDT data is the payload after 4 bytes of irq+touch_flag */
        if (pl_len >= 4 + GOODIX_FDT_BASE_LEN)
          {
            g_free (self->fdt_data_tx_on);
            self->fdt_data_tx_on = g_memdup2 (pl + 4, GOODIX_FDT_BASE_LEN);
          }

        /* Get image with TX enabled */
        guint8 img_req[4];
        goodix_build_image_request (TRUE, TRUE, FALSE, self->calib.dac_l,
                                    img_req);
        goodix_run_cmd (ssm, dev, 0x2, 0x0, img_req, 4, TRUE);
      }
      break;

    case GOODIX_OPEN_FDT_TX_OFF:
      {
        /* Parse image response, decrypt, and save */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse image response"));
            return;
          }

        {
          gsize dec_len;
          guint8 *decrypted = goodix_crypto_gtls_decrypt_sensor_data (
              &self->gtls, pl, pl_len, &dec_len);

          if (decrypted == NULL)
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "Image decryption failed"));
              return;
            }

          g_free (self->image_tx_on);
          self->image_tx_on = goodix_device_decode_image (decrypted, dec_len);
          g_free (decrypted);
        }

        /* FDT manual with TX disabled: op_code=0x8D */
        guint8 manual_payload[1 + GOODIX_FDT_BASE_LEN];
        manual_payload[0] = 0x8D;
        memcpy (manual_payload + 1, self->calib.fdt_base_manual,
                GOODIX_FDT_BASE_LEN);

        goodix_build_fdt_payload (manual_payload[0], 3, manual_payload + 1,
                                  &p, &plen);
        goodix_run_cmd (ssm, dev, 0x3, 0x3, p, plen, TRUE);
        g_free (p);
      }
      break;

    case GOODIX_OPEN_VALIDATE_FDT:
      {
        /* Parse FDT response (TX off) and save */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse FDT TX-off response"));
            return;
          }

        if (pl_len >= 4 + GOODIX_FDT_BASE_LEN)
          {
            g_free (self->fdt_data_tx_off);
            self->fdt_data_tx_off = g_memdup2 (pl + 4, GOODIX_FDT_BASE_LEN);
          }

        /* Validate FDT: tx_on vs tx_off */
        if (self->fdt_data_tx_on && self->fdt_data_tx_off &&
            !goodix_device_is_fdt_base_valid (self->fdt_data_tx_on,
                                              self->fdt_data_tx_off,
                                              GOODIX_FDT_BASE_LEN,
                                              self->calib.delta_fdt))
          {
            fp_warn ("FDT validation failed, continuing anyway");
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_IMAGE_TX_OFF:
      {
        /* Get image with TX disabled */
        guint8 img_req[4];
        goodix_build_image_request (FALSE, TRUE, FALSE, self->calib.dac_l,
                                    img_req);
        goodix_run_cmd (ssm, dev, 0x2, 0x0, img_req, 4, TRUE);
      }
      break;

    case GOODIX_OPEN_VALIDATE_IMG:
      {
        /* Parse and decrypt image, validate against TX-on image */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse TX-off image"));
            return;
          }

        {
          gsize dec_len;
          guint8 *decrypted = goodix_crypto_gtls_decrypt_sensor_data (
              &self->gtls, pl, pl_len, &dec_len);

          if (decrypted == NULL)
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "TX-off image decryption failed"));
              return;
            }

          g_free (self->image_tx_off);
          self->image_tx_off = goodix_device_decode_image (decrypted, dec_len);
          g_free (decrypted);
        }

        /* Validate base images */
        if (self->image_tx_on && self->image_tx_off)
          {
            gboolean valid;
            goodix_device_validate_base_img (self->image_tx_on,
                                             self->image_tx_off,
                                             self->calib.delta_img, &valid);
            if (!valid)
              fp_warn ("Base image validation failed, continuing anyway");
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_FDT_TX_ON_2:
      {
        /* Second FDT TX on */
        guint8 manual_payload[1 + GOODIX_FDT_BASE_LEN];
        manual_payload[0] = 0x0D;
        memcpy (manual_payload + 1, self->calib.fdt_base_manual,
                GOODIX_FDT_BASE_LEN);

        goodix_build_fdt_payload (manual_payload[0], 3, manual_payload + 1,
                                  &p, &plen);
        goodix_run_cmd (ssm, dev, 0x3, 0x3, p, plen, TRUE);
        g_free (p);
      }
      break;

    case GOODIX_OPEN_VALIDATE_FDT_2:
      {
        /* Parse and validate second FDT */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse second FDT"));
            return;
          }

        /* Validate against tx_off */
        if (pl_len >= 4 + GOODIX_FDT_BASE_LEN && self->fdt_data_tx_off)
          {
            if (!goodix_device_is_fdt_base_valid (pl + 4,
                                                  self->fdt_data_tx_off,
                                                  GOODIX_FDT_BASE_LEN,
                                                  self->calib.delta_fdt))
              fp_warn ("Second FDT validation failed, continuing anyway");
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

        /* Save calibration image */
        g_free (self->calib_image);
        self->calib_image = self->image_tx_on;
        self->image_tx_on = NULL;

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_SLEEP:
      {
        /* set_sleep_mode: category=0x6, command=0, payload=\x01\x00 */
        payload[0] = 0x01;
        payload[1] = 0x00;
        goodix_run_cmd (ssm, dev, 0x6, 0x0, payload, 2, FALSE);
      }
      break;
    }
}

static void
goodix_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;

  /* Clean up temp data */
  g_clear_pointer (&self->fdt_data_tx_on, g_free);
  g_clear_pointer (&self->fdt_data_tx_off, g_free);
  g_clear_pointer (&self->image_tx_off, g_free);

  if (error)
    {
      fp_warn ("Device open failed: %s", error->message);
      fpi_device_open_complete (dev, error);
      return;
    }

  fp_info ("Device initialization complete");
  fpi_device_open_complete (dev, NULL);
}

/* Forward declarations for SSM handlers used as sub-SSMs */
static void goodix_finger_wait_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_capture_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_finger_up_ssm_handler (FpiSsm *ssm, FpDevice *dev);

/* ========================================================================
 * Finger-wait SSM (waiting for finger down)
 * ======================================================================== */

static void
goodix_finger_wait_ssm_handler (FpiSsm   *ssm,
                                FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_FINGER_WAIT_EC_POWER_ON:
      {
        /* Power on sensor (idempotent if already on) */
        guint8 payload[3] = { 0x01, 0x01, 0x00 };
        goodix_run_cmd (ssm, dev, 0xA, 0x7, payload, 3, TRUE);
      }
      break;

    case GOODIX_FINGER_WAIT_FDT_DOWN_SETUP:
      {
        /* Set up finger-down detection (re-arms the sensor) */
        guint8 *p;
        gsize plen;

        goodix_build_fdt_payload (0x0C, 1, self->calib.fdt_base_down,
                                  &p, &plen);
        goodix_run_cmd (ssm, dev, 0x3, 0x1, p, plen, FALSE);
        g_free (p);
      }
      break;

    case GOODIX_FINGER_WAIT_RECV_EVENT:
      /* Wait for FDT DOWN event with cancellable */
      goodix_recv_start_cancellable (ssm, dev, self->cancel);
      break;

    case GOODIX_FINGER_WAIT_GEN_UP_BASE:
      {
        /* Parse FDT event */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
            pl_len < 28)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse FDT event"));
            return;
          }

        /* irq_status = pl[0:2], touch_flag = pl[2:4], fdt_data = pl[4:28] */
        self->fdt_touch_flag = pl[2] | ((guint16) pl[3] << 8);
        g_free (self->fdt_event_data);
        self->fdt_event_data = g_memdup2 (pl + 4, GOODIX_FDT_BASE_LEN);

        /* Generate FDT up base */
        goodix_device_generate_fdt_up_base (self->fdt_event_data,
                                            self->fdt_touch_flag,
                                            &self->calib,
                                            self->calib.fdt_base_up);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_FINGER_WAIT_FDT_CHECK:
      {
        /* FDT manual TX-off to verify it's a real touch, not temperature */
        guint8 manual_payload[1 + GOODIX_FDT_BASE_LEN];
        guint8 *p;
        gsize plen;

        manual_payload[0] = 0x8D;
        memcpy (manual_payload + 1, self->calib.fdt_base_manual,
                GOODIX_FDT_BASE_LEN);

        goodix_build_fdt_payload (manual_payload[0], 3, manual_payload + 1,
                                  &p, &plen);
        goodix_run_cmd (ssm, dev, 0x3, 0x3, p, plen, TRUE);
        g_free (p);
      }
      break;

    case GOODIX_FINGER_WAIT_VALIDATE:
      {
        /* Parse manual FDT response and check if it's a temperature event */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
            pl_len < 4 + GOODIX_FDT_BASE_LEN)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse FDT check"));
            return;
          }

        /* If fdt_base_valid == TRUE, it's a temperature event (false alarm) */
        if (goodix_device_is_fdt_base_valid (self->fdt_event_data,
                                             pl + 4,
                                             GOODIX_FDT_BASE_LEN,
                                             self->calib.delta_fdt))
          {
            fp_dbg ("Temperature event detected, retrying finger wait");
            /* Re-arm FDT down detection and wait again */
            fpi_ssm_jump_to_state (ssm, GOODIX_FINGER_WAIT_FDT_DOWN_SETUP);
            return;
          }

        /* Real finger detected! */
        fp_dbg ("Finger detected");
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

/* finger_wait is used as a sub-SSM — no standalone run/done needed */

/* ========================================================================
 * Capture SSM
 * ======================================================================== */

static void
goodix_capture_ssm_handler (FpiSsm   *ssm,
                            FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CAPTURE_GET_IMAGE:
      {
        guint8 img_req[4];
        goodix_build_image_request (TRUE, TRUE, TRUE, self->calib.dac_h,
                                    img_req);
        goodix_run_cmd (ssm, dev, 0x2, 0x0, img_req, 4, TRUE);
      }
      break;

    case GOODIX_CAPTURE_DECRYPT:
      {
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len, dec_len;
        guint8 *decrypted;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse capture response"));
            return;
          }

        decrypted = goodix_crypto_gtls_decrypt_sensor_data (&self->gtls,
                                                             pl, pl_len,
                                                             &dec_len);
        if (decrypted == NULL)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Capture image decryption failed"));
            return;
          }

        /* Decode 12-bit and convert to 8-bit */
        {
          guint16 *img12 = goodix_device_decode_image (decrypted, dec_len);

          /* No background subtraction: calibration image uses dac_l/is_finger=FALSE
           * while finger captures use dac_h/is_finger=TRUE. Subtraction with
           * mismatched DAC settings destroys fingerprint contrast. */
          guint8 *img8 = goodix_device_image_to_8bit (img12, NULL);

          g_free (img12);
          g_free (decrypted);

          /* Store native 8-bit image for SIGFM matching */
          g_free (self->captured_image);
          self->captured_image = img8;
        }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_CAPTURE_DECODE:
      /* Already decoded in previous state, just advance */
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_CAPTURE_STORE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* capture is used as a sub-SSM — no standalone run/done needed */

/* ========================================================================
 * Finger-up SSM
 * ======================================================================== */

static void
goodix_finger_up_ssm_handler (FpiSsm   *ssm,
                              FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint8 payload[2];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_FINGER_UP_FDT_UP_SETUP:
      {
        /* Set up finger-up detection before waiting */
        guint8 *p;
        gsize plen;

        goodix_build_fdt_payload (0x0E, 2, self->calib.fdt_base_up, &p, &plen);
        goodix_run_cmd (ssm, dev, 0x3, 0x2, p, plen, FALSE);
        g_free (p);
      }
      break;

    case GOODIX_FINGER_UP_RECV_EVENT:
      goodix_recv_start_cancellable (ssm, dev, self->cancel);
      break;

    case GOODIX_FINGER_UP_UPDATE_DOWN_BASE:
      {
        /* Parse FDT UP event and update fdt_base_down */
        guint8 cat, cmd;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_proto_rx_parse (&self->rx, &cat, &cmd, &pl, &pl_len) ||
            pl_len < 4 + GOODIX_FDT_BASE_LEN)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse finger-up event"));
            return;
          }

        goodix_device_generate_fdt_base (pl + 4, GOODIX_FDT_BASE_LEN,
                                         self->calib.fdt_base_down);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_FINGER_UP_SLEEP:
      payload[0] = 0x01;
      payload[1] = 0x00;
      goodix_run_cmd (ssm, dev, 0x6, 0x0, payload, 2, FALSE);
      break;

    case GOODIX_FINGER_UP_EC_POWER_OFF:
      {
        guint8 ec_payload[3] = { 0x00, 0x00, 0x00 };
        goodix_run_cmd (ssm, dev, 0xA, 0x7, ec_payload, 3, TRUE);
      }
      break;
    }
}

/* finger_up is used as a sub-SSM — no standalone run/done needed */

/* ========================================================================
 * Enroll SSM
 * ======================================================================== */

static void
goodix_enroll_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_ENROLL_WAIT_FINGER:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_wait_ssm_handler,
                                     GOODIX_FINGER_WAIT_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_ENROLL_CAPTURE:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_capture_ssm_handler,
                                     GOODIX_CAPTURE_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_ENROLL_PROCESS:
      {
        /* Store captured image in enrollment array */
        g_ptr_array_add (self->enroll_images, self->captured_image);
        self->captured_image = NULL;
        self->enroll_stage++;

        fp_dbg ("Enrollment stage %d/%d complete",
                self->enroll_stage, GOODIX_ENROLL_SAMPLES);

        fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_ENROLL_WAIT_FINGER_UP:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_up_ssm_handler,
                                     GOODIX_FINGER_UP_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_ENROLL_NEXT:
      if (self->enroll_stage < GOODIX_ENROLL_SAMPLES)
        fpi_ssm_jump_to_state (ssm, GOODIX_ENROLL_WAIT_FINGER);
      else
        fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
goodix_enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;

  if (error)
    {
      g_clear_pointer (&self->enroll_images, g_ptr_array_unref);
      g_clear_pointer (&self->captured_image, g_free);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  /* Build print from enrollment images */
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);

  /* Build GVariant "aay" — array of byte arrays, one per enrollment sample */
  GVariantBuilder builder;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

  for (guint i = 0; i < self->enroll_images->len; i++)
    {
      guint8 *img = g_ptr_array_index (self->enroll_images, i);
      g_variant_builder_add (&builder, "@ay",
                             g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                        img,
                                                        GOODIX_SENSOR_PIXELS,
                                                        1));
    }

  GVariant *data = g_variant_builder_end (&builder);

  g_object_set (G_OBJECT (print), "fpi-data", data, NULL);

  g_clear_pointer (&self->enroll_images, g_ptr_array_unref);

  fp_info ("Enrollment complete with %d samples", GOODIX_ENROLL_SAMPLES);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

/* ========================================================================
 * Verify / Identify SSM (shared — checks current action for dispatch)
 * ======================================================================== */

static void
goodix_verify_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_VERIFY_WAIT_FINGER:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_wait_ssm_handler,
                                     GOODIX_FINGER_WAIT_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_VERIFY_CAPTURE:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_capture_ssm_handler,
                                     GOODIX_CAPTURE_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;

    case GOODIX_VERIFY_MATCH:
      {
        FpiDeviceAction action = fpi_device_get_current_action (dev);

        if (action == FPI_DEVICE_ACTION_IDENTIFY)
          {
            /* Identify: match against gallery of enrolled prints */
            GPtrArray *gallery = NULL;
            FpPrint *match = NULL;
            int best_score = 0;
            SigfmImgInfo *probe_info;

            fpi_device_get_identify_data (dev, &gallery);

            /* Extract SIFT features from live capture */
            probe_info = sigfm_extract (self->captured_image,
                                         GOODIX_SENSOR_WIDTH,
                                         GOODIX_SENSOR_HEIGHT);
            fp_dbg ("SIGFM probe keypoints: %d",
                    sigfm_keypoints_count (probe_info));

            for (guint i = 0; i < gallery->len; i++)
              {
                FpPrint *tmpl = g_ptr_array_index (gallery, i);
                GVariant *tmpl_data = NULL;

                g_object_get (G_OBJECT (tmpl), "fpi-data", &tmpl_data, NULL);
                if (tmpl_data == NULL)
                  continue;

                GVariantIter iter;
                GVariant *child;
                int sample_idx = 0;

                g_variant_iter_init (&iter, tmpl_data);
                while ((child = g_variant_iter_next_value (&iter)))
                  {
                    gsize len;
                    const guint8 *img;

                    img = g_variant_get_fixed_array (child, &len, 1);
                    if (len == GOODIX_SENSOR_PIXELS)
                      {
                        SigfmImgInfo *tmpl_info;

                        tmpl_info = sigfm_extract (img,
                                                    GOODIX_SENSOR_WIDTH,
                                                    GOODIX_SENSOR_HEIGHT);
                        int score = sigfm_match_score (probe_info, tmpl_info);
                        fp_dbg ("identify: gallery[%u] sample %d sigfm_score %d",
                                i, sample_idx, score);
                        sigfm_free_info (tmpl_info);

                        if (score > best_score)
                          {
                            best_score = score;
                            match = tmpl;
                          }
                        sample_idx++;
                      }
                    g_variant_unref (child);
                  }
                g_variant_unref (tmpl_data);
              }

            sigfm_free_info (probe_info);

            fp_dbg ("Identify best SIGFM score: %d (threshold: %d)",
                    best_score, GOODIX_SIGFM_THRESHOLD);

            if (best_score >= GOODIX_SIGFM_THRESHOLD)
              fpi_device_identify_report (dev, match, NULL, NULL);
            else
              fpi_device_identify_report (dev, NULL, NULL, NULL);
          }
        else
          {
            /* Verify: match against single enrolled print */
            FpPrint *print = NULL;
            GVariant *data = NULL;
            int best_score = 0;
            SigfmImgInfo *probe_info;
            int sample_idx = 0;

            fpi_device_get_verify_data (dev, &print);
            g_object_get (G_OBJECT (print), "fpi-data", &data, NULL);

            /* Extract SIFT features from live capture */
            probe_info = sigfm_extract (self->captured_image,
                                         GOODIX_SENSOR_WIDTH,
                                         GOODIX_SENSOR_HEIGHT);
            fp_dbg ("SIGFM probe keypoints: %d",
                    sigfm_keypoints_count (probe_info));

            if (data != NULL)
              {
                GVariantIter iter;
                GVariant *child;

                g_variant_iter_init (&iter, data);
                while ((child = g_variant_iter_next_value (&iter)))
                  {
                    gsize len;
                    const guint8 *img;

                    img = g_variant_get_fixed_array (child, &len, 1);
                    if (len == GOODIX_SENSOR_PIXELS)
                      {
                        SigfmImgInfo *tmpl_info;

                        tmpl_info = sigfm_extract (img,
                                                    GOODIX_SENSOR_WIDTH,
                                                    GOODIX_SENSOR_HEIGHT);
                        int score = sigfm_match_score (probe_info, tmpl_info);
                        fp_dbg ("verify: sample %d sigfm_score %d",
                                sample_idx, score);
                        sigfm_free_info (tmpl_info);

                        if (score > best_score)
                          best_score = score;

                        sample_idx++;
                      }
                    g_variant_unref (child);
                  }
                g_variant_unref (data);
              }

            sigfm_free_info (probe_info);

            fp_dbg ("Verify best SIGFM score: %d (threshold: %d)",
                    best_score, GOODIX_SIGFM_THRESHOLD);

            if (best_score >= GOODIX_SIGFM_THRESHOLD)
              fpi_device_verify_report (dev, FPI_MATCH_SUCCESS, NULL, NULL);
            else
              fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
          }

        g_clear_pointer (&self->captured_image, g_free);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_VERIFY_WAIT_FINGER_UP:
      {
        FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_up_ssm_handler,
                                     GOODIX_FINGER_UP_NUM_STATES);
        fpi_ssm_start_subsm (ssm, sub);
      }
      break;
    }
}

static void
goodix_verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  self->task_ssm = NULL;
  g_clear_pointer (&self->captured_image, g_free);

  if (error)
    {
      /* If error occurred after match was already reported (during finger_up),
       * treat it as non-fatal — the match result is what matters. */
      gint failed_state = fpi_ssm_get_cur_state (ssm);

      if (failed_state >= GOODIX_VERIFY_WAIT_FINGER_UP &&
          !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fp_warn ("Post-match finger-up error (non-fatal): %s",
                   error->message);
          g_clear_error (&error);
        }
    }

  if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_complete (dev, error);
  else
    fpi_device_verify_complete (dev, error);
}

/* ========================================================================
 * FpDevice virtual methods
 * ======================================================================== */

static void
goodix_open (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, goodix_open_ssm_handler,
                      GOODIX_OPEN_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_open_ssm_done);
}

static void
goodix_close (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GError *error = NULL;

  g_clear_object (&self->cancel);
  g_clear_pointer (&self->calib_image, g_free);
  g_clear_pointer (&self->fdt_event_data, g_free);
  g_clear_pointer (&self->fdt_data_tx_on, g_free);
  g_clear_pointer (&self->fdt_data_tx_off, g_free);
  g_clear_pointer (&self->image_tx_on, g_free);
  g_clear_pointer (&self->image_tx_off, g_free);
  g_clear_pointer (&self->otp_data, g_free);
  g_clear_pointer (&self->fw_version, g_free);
  g_clear_pointer (&self->psk_hash, g_free);
  g_clear_pointer (&self->rx.buf, g_free);
  g_clear_pointer (&self->captured_image, g_free);
  g_clear_pointer (&self->enroll_images, g_ptr_array_unref);

  if (self->cmd)
    {
      g_free (self->cmd->payload);
      g_clear_pointer (&self->cmd, g_free);
    }

  g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                  GOODIX_USB_INTERFACE, 0, &error);

  fpi_device_close_complete (dev, error);
}

static void
goodix_enroll (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  self->enroll_stage = 0;
  g_clear_pointer (&self->enroll_images, g_ptr_array_unref);
  self->enroll_images = g_ptr_array_new_with_free_func (g_free);

  ssm = fpi_ssm_new (dev, goodix_enroll_ssm_handler,
                      GOODIX_ENROLL_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_enroll_ssm_done);
}

static void
goodix_verify (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  ssm = fpi_ssm_new (dev, goodix_verify_ssm_handler,
                      GOODIX_VERIFY_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_verify_ssm_done);
}

static void
goodix_identify (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  ssm = fpi_ssm_new (dev, goodix_verify_ssm_handler,
                      GOODIX_VERIFY_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_verify_ssm_done);
}

static void
goodix_cancel (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (self->cancel)
    g_cancellable_cancel (self->cancel);
}

/* ========================================================================
 * GObject boilerplate
 * ======================================================================== */

static void
fpi_device_goodix53x5_init (FpiDeviceGoodix53x5 *self)
{
}

static const FpIdEntry goodix53x5_id_table[] = {
  { .vid = 0x27c6, .pid = 0x5385, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_goodix53x5_class_init (FpiDeviceGoodix53x5Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = "goodix53x5";
  dev_class->full_name = "Goodix HTK32 Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = goodix53x5_id_table;
  dev_class->nr_enroll_stages = GOODIX_ENROLL_SAMPLES;
  dev_class->temp_hot_seconds = -1; /* Disable thermal throttling — small sensor */
  dev_class->features = FP_DEVICE_FEATURE_VERIFY | FP_DEVICE_FEATURE_IDENTIFY;

  dev_class->open = goodix_open;
  dev_class->close = goodix_close;
  dev_class->enroll = goodix_enroll;
  dev_class->verify = goodix_verify;
  dev_class->identify = goodix_identify;
  dev_class->cancel = goodix_cancel;
}
