/*
 * Goodix 53x5 driver for libfprint — USB transport and command execution
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

#include <string.h>

/* USB endpoints — interface 1, CDC Data class */
#define GOODIX_EP_OUT (0x03 | FPI_USB_ENDPOINT_OUT)
#define GOODIX_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)

/* USB chunk size */
#define GOODIX_USB_CHUNK_SIZE 64

#define GOODIX_PROTO_CATEGORY_ACK     0x0B
#define GOODIX_PROTO_CMD_ACK          0x00
#define GOODIX_PROTO_ACK_FLAG_VALID   0x01
#define GOODIX_PROTO_CMD_BYTE(category, command) \
  (((category) << 4) | ((command) << 1))

/* Command sub-SSM */
typedef enum {
  GOODIX_CMD_SEND = 0,
  GOODIX_CMD_RECV_ACK,
  GOODIX_CMD_VALIDATE_ACK,
  GOODIX_CMD_RECV_DATA,
  GOODIX_CMD_NUM_STATES,
} GoodixCmdState;

static gboolean
goodix_validate_ack_for_cmd (FpDevice        *dev,
                             const GoodixCmd *cmd,
                             GError         **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint8 category, command;
  const guint8 *payload;
  gsize payload_len;
  guint8 expected_cmd_byte = GOODIX_PROTO_CMD_BYTE (cmd->category, cmd->command);

  if (!goodix_proto_rx_parse (&self->rx, &category, &command,
                              &payload, &payload_len))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Failed to parse ACK");
      return FALSE;
    }

  if (category != GOODIX_PROTO_CATEGORY_ACK ||
      command != GOODIX_PROTO_CMD_ACK ||
      payload_len < 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected ACK: expected cmd_byte=0x%02x, got cat=0x%02x cmd=0x%02x len=%zu",
                   expected_cmd_byte, category, command, payload_len);
      return FALSE;
    }

  if (payload[0] != expected_cmd_byte ||
      (payload[1] & GOODIX_PROTO_ACK_FLAG_VALID) == 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected ACK: expected cmd_byte=0x%02x, got ack_cmd=0x%02x flags=0x%02x",
                   expected_cmd_byte, payload[0], payload[1]);
      return FALSE;
    }

  return TRUE;
}

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

  /* The transport uses 64-byte USB writes. Continuation chunks prepend
   * cmd_byte | 1 and carry up to 63 more bytes of message data. */

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

void
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
      if (!self->suspend_pending &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          self->action_result_reported &&
          !self->verify_wait_finger_up &&
          transfer->ssm == self->blocking_ssm)
        {
          /* Once verify/identify has reported a result, libfprint may cancel
           * the action immediately. Finish the sensor shutdown sequence rather
           * than bailing out and leaving the MCU armed for the next open.
           * The shutdown state was recorded by the scan flow when it armed
           * this blocking read. */
          g_clear_error (&error);
          self->blocking_ssm = NULL;
          fpi_ssm_jump_to_state (transfer->ssm, self->blocking_shutdown_state);
          return;
        }

      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          self->suspend_pending)
        {
          /* Do not carry an armed FDT wait across system sleep. The USB device
           * may disappear and re-enumerate during S4, leaving fprintd with a
           * stale open device. Abort the active auth so the greeter starts a
           * fresh operation after resume. */
          g_clear_error (&error);
          self->suspend_pending = FALSE;
          self->blocking_ssm = NULL;
          fpi_device_suspend_complete (dev,
              fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                                         "Cannot run while suspended."));
          return;
        }

      self->blocking_ssm = NULL;

      if (self->suspend_pending)
        {
          /* Non-cancellation error during suspend — report it and fail SSM */
          self->suspend_pending = FALSE;
          fpi_device_suspend_complete (dev, g_error_copy (error));
        }

      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (self->suspend_pending && transfer->ssm == self->blocking_ssm)
    {
      /* Data (e.g. an FDT touch event) raced with the suspend cancellation
       * and the transfer completed before the cancel took effect. Treat it
       * exactly like the cancelled case above; otherwise the pending suspend
       * request would never be completed and system sleep would block until
       * logind times out. */
      self->suspend_pending = FALSE;
      self->blocking_ssm = NULL;
      fpi_device_suspend_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                                     "Cannot run while suspended."));
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

void
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

    case GOODIX_CMD_VALIDATE_ACK:
      {
        g_autoptr(GError) error = NULL;

        if (!goodix_validate_ack_for_cmd (dev, cmd, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_CMD_RECV_DATA:
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;
    }
}

void
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

gboolean
goodix_parse_reply (FpDevice      *dev,
                    guint8        *out_category,
                    guint8        *out_command,
                    const guint8 **out_payload,
                    gsize         *out_payload_len,
                    GError       **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (goodix_proto_rx_parse (&self->rx, out_category, out_command,
                             out_payload, out_payload_len))
    return TRUE;

  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Failed to parse device reply");
  return FALSE;
}

gboolean
goodix_parse_reply_exact (FpDevice      *dev,
                          guint8         expected_category,
                          guint8         expected_command,
                          const guint8 **out_payload,
                          gsize         *out_payload_len,
                          GError       **error)
{
  guint8 category, command;

  if (!goodix_parse_reply (dev, &category, &command, out_payload,
                           out_payload_len, error))
    return FALSE;

  if (category != expected_category || command != expected_command)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected reply: cat=0x%02x cmd=0x%02x",
                   category, command);
      return FALSE;
    }

  return TRUE;
}
