/*
 * Goodix 53x5 driver for libfprint — Protocol layer
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

/*
 * Message format: [cmd_byte(1)][size(2 LE)][payload(N)][checksum(1)]
 *   cmd_byte = category<<4 | command<<1
 *   size = len(payload) + 1 (for the checksum byte)
 *   checksum = (0xAA - sum(cmd_byte, size_lo, size_hi, payload...)) & 0xFF
 *              or 0x88 for handshake messages
 */

/**
 * goodix_proto_build_message:
 *
 * Build a complete protocol message ready for chunked USB transmission.
 * Returns a newly allocated buffer. The caller must free it with g_free().
 */
guint8 *
goodix_proto_build_message (guint8        category,
                            guint8        command,
                            const guint8 *payload,
                            gsize         payload_len,
                            gboolean      use_checksum,
                            gsize        *out_len)
{
  guint8 cmd_byte = (category << 4) | (command << 1);
  guint16 size_field = (guint16) (payload_len + 1); /* +1 for checksum */
  gsize total = 1 + 2 + payload_len + 1;            /* cmd + size(2) + payload + checksum */
  guint8 *msg = g_malloc (total);
  guint8 checksum;
  guint sum;

  msg[0] = cmd_byte;
  msg[1] = size_field & 0xFF;
  msg[2] = (size_field >> 8) & 0xFF;

  if (payload_len > 0)
    memcpy (msg + 3, payload, payload_len);

  if (use_checksum)
    {
      sum = 0;
      for (gsize i = 0; i < total - 1; i++)
        sum += msg[i];
      checksum = (0xAA - sum) & 0xFF;
    }
  else
    {
      checksum = 0x88;
    }

  msg[total - 1] = checksum;

  *out_len = total;
  return msg;
}

/**
 * goodix_proto_validate_checksum:
 *
 * Validate checksum of a complete received message.
 * data must include the full message including the checksum byte.
 */
gboolean
goodix_proto_validate_checksum (const guint8 *data,
                                gsize         len)
{
  guint8 msg_checksum;
  guint sum;
  guint8 computed;

  if (len < 4)
    return FALSE;

  msg_checksum = data[len - 1];

  /* 0x88 = no-checksum marker (handshake) */
  if (msg_checksum == 0x88)
    return TRUE;

  sum = 0;
  for (gsize i = 0; i < len - 1; i++)
    sum += data[i];

  computed = (0xAA - sum) & 0xFF;
  return computed == msg_checksum;
}

/**
 * goodix_proto_rx_reset:
 *
 * Reset the reassembly buffer for a new message.
 */
void
goodix_proto_rx_reset (GoodixReassembly *rx)
{
  if (rx->buf == NULL)
    rx->buf = g_malloc (GOODIX_RX_BUF_SIZE);
  rx->len = 0;
  rx->expected = 0;
  rx->cmd_byte = 0;
}

/**
 * goodix_proto_rx_feed_chunk:
 *
 * Feed a USB chunk into the reassembly buffer.
 * Returns TRUE if the chunk was accepted, FALSE on protocol error.
 */
gboolean
goodix_proto_rx_feed_chunk (GoodixReassembly *rx,
                            const guint8     *chunk,
                            gsize             chunk_len)
{
  if (chunk_len == 0)
    return TRUE;

  if (rx->len == 0)
    {
      /* First chunk of a new message */
      if (chunk_len < 3)
        return FALSE;

      rx->cmd_byte = chunk[0];

      guint16 msg_size = chunk[1] | ((guint16) chunk[2] << 8);

      /* Total expected: 1(cmd) + 2(size) + msg_size(payload+checksum)
       * But the size field already accounts for payload + checksum,
       * and the header (cmd+size) is 3 bytes.
       * Actually, looking at the Python: data = data[:message_size + 3]
       * So total = message_size + 3 where message_size is the 2-byte LE field.
       * BUT len(data) - 1 < message_size is the condition, and data includes
       * the cmd_byte. So total bytes to collect = message_size + 3.
       * Wait: the Python code: message_size = struct.unpack("<H", data[1:3])[0]
       * then: while len(data) - 1 < message_size: ...
       * then: data = data[:message_size + 3]
       * So total = message_size + 3 bytes (cmd + size_field(2) is already 3,
       * plus message_size more, minus the fact that len(data)-1 < message_size
       * means we need message_size+1 total data bytes... let me recheck.
       *
       * Actually: data starts with one chunk. Then for continued chunks,
       * the first byte is the continued cmd_byte (stripped), rest appended.
       * data[0] = cmd_byte, data[1:3] = size field, data[3:] = payload+checksum
       * message_size = size field value = payload_len + 1 (checksum)
       * Total message bytes: 3 + message_size = 3 + payload_len + 1
       *
       * The loop: while len(data) - 1 < message_size
       *   i.e. len(data) < message_size + 1
       * After trimming: data = data[:message_size + 3]
       * So total expected = message_size + 3.
       *
       * But the reassembly buffer stores everything linearly.
       * First chunk: all bytes go into buffer.
       * Continuation chunks: skip byte 0 (continued cmd_byte), rest goes in.
       */
      rx->expected = (gsize) msg_size + 3;

      /* Copy the entire first chunk */
      if (rx->len + chunk_len > GOODIX_RX_BUF_SIZE)
        return FALSE;
      memcpy (rx->buf + rx->len, chunk, chunk_len);
      rx->len += chunk_len;
    }
  else
    {
      /* Continuation chunk */
      if (chunk_len < 1)
        return FALSE;

      guint8 contd_cmd = chunk[0];

      /* Continuation marker: bit 0 set, and upper bits match */
      if ((contd_cmd & 1) == 0 || (contd_cmd & 0xFE) != rx->cmd_byte)
        {
          fp_warn ("Wrong continuation chunk: got 0x%02x, expected 0x%02x|1",
                   contd_cmd, rx->cmd_byte);
          return FALSE;
        }

      /* Skip the continuation cmd byte, copy rest */
      if (rx->len + chunk_len - 1 > GOODIX_RX_BUF_SIZE)
        return FALSE;
      memcpy (rx->buf + rx->len, chunk + 1, chunk_len - 1);
      rx->len += chunk_len - 1;
    }

  return TRUE;
}

/**
 * goodix_proto_rx_complete:
 *
 * Check if the reassembly buffer has a complete message.
 */
gboolean
goodix_proto_rx_complete (GoodixReassembly *rx)
{
  if (rx->expected == 0)
    return FALSE;

  /* We need at least 'expected' bytes. We may have more due to
   * USB padding in the last chunk. */
  return rx->len >= rx->expected;
}

/**
 * goodix_proto_rx_parse:
 *
 * Parse the complete reassembled message.
 * out_payload points into the rx buffer — valid until rx is reset.
 */
gboolean
goodix_proto_rx_parse (GoodixReassembly *rx,
                       guint8           *out_category,
                       guint8           *out_command,
                       const guint8    **out_payload,
                       gsize            *out_payload_len)
{
  gsize msg_len;

  if (!goodix_proto_rx_complete (rx))
    return FALSE;

  msg_len = rx->expected;

  /* Trim to actual message length */
  if (msg_len < 4)
    return FALSE;

  /* Validate checksum */
  if (!goodix_proto_validate_checksum (rx->buf, msg_len))
    {
      fp_warn ("Message checksum validation failed");
      return FALSE;
    }

  *out_category = rx->buf[0] >> 4;
  *out_command = (rx->buf[0] & 0x0F) >> 1;

  /* Payload starts at offset 3, ends before checksum */
  *out_payload = rx->buf + 3;
  *out_payload_len = msg_len - 4; /* minus cmd(1) + size(2) + checksum(1) */

  return TRUE;
}

/**
 * goodix_proto_build_mcu_message:
 *
 * Build an MCU envelope payload.
 * Format: [data_type(4 LE)][total_size(4 LE)][data]
 * where total_size = len(data) + 8 (includes the header).
 */
void
goodix_proto_build_mcu_message (guint32       data_type,
                                const guint8 *data,
                                gsize         data_len,
                                guint8      **out_payload,
                                gsize        *out_payload_len)
{
  gsize total = 4 + 4 + data_len;
  guint8 *buf = g_malloc (total);
  guint32 size_val = (guint32) (data_len + 8);

  buf[0] = data_type & 0xFF;
  buf[1] = (data_type >> 8) & 0xFF;
  buf[2] = (data_type >> 16) & 0xFF;
  buf[3] = (data_type >> 24) & 0xFF;

  buf[4] = size_val & 0xFF;
  buf[5] = (size_val >> 8) & 0xFF;
  buf[6] = (size_val >> 16) & 0xFF;
  buf[7] = (size_val >> 24) & 0xFF;

  if (data_len > 0)
    memcpy (buf + 8, data, data_len);

  *out_payload = buf;
  *out_payload_len = total;
}

/**
 * goodix_proto_parse_mcu_message:
 *
 * Parse an MCU envelope from a received message payload.
 * The received payload (from category=0xD, command=1) has format:
 * [data_type(4 LE)][payload_size(4 LE)][data]
 * where payload_size = total including the 8-byte header.
 */
gboolean
goodix_proto_parse_mcu_message (const guint8  *payload,
                                gsize          payload_len,
                                guint32        expected_type,
                                const guint8 **out_data,
                                gsize         *out_data_len)
{
  guint32 msg_type, msg_size;

  if (payload_len < 8)
    return FALSE;

  msg_type = payload[0] | ((guint32) payload[1] << 8) |
             ((guint32) payload[2] << 16) | ((guint32) payload[3] << 24);

  if (msg_type != expected_type)
    {
      fp_warn ("MCU message type mismatch: expected 0x%x, got 0x%x",
               expected_type, msg_type);
      return FALSE;
    }

  msg_size = payload[4] | ((guint32) payload[5] << 8) |
             ((guint32) payload[6] << 16) | ((guint32) payload[7] << 24);

  if (msg_size != (guint32) payload_len)
    {
      fp_warn ("MCU message size mismatch: header says %u, got %zu",
               msg_size, payload_len);
      return FALSE;
    }

  *out_data = payload + 8;
  *out_data_len = payload_len - 8;
  return TRUE;
}

/**
 * goodix_proto_parse_production_read:
 *
 * Parse a production_read reply payload.
 * Format: [status(1)][read_type(4 LE)][data_size(4 LE)][data]
 */
gboolean
goodix_proto_parse_production_read (const guint8  *payload,
                                    gsize          payload_len,
                                    guint32        expected_type,
                                    const guint8 **out_data,
                                    gsize         *out_data_len)
{
  guint32 msg_type, data_size;

  if (payload_len < 9)
    return FALSE;

  if (payload[0] != 0)
    {
      fp_warn ("Production read MCU failed, status: %d", payload[0]);
      return FALSE;
    }

  msg_type = payload[1] | ((guint32) payload[2] << 8) |
             ((guint32) payload[3] << 16) | ((guint32) payload[4] << 24);

  if (msg_type != expected_type)
    {
      fp_warn ("Production read type mismatch: expected 0x%x, got 0x%x",
               expected_type, msg_type);
      return FALSE;
    }

  data_size = payload[5] | ((guint32) payload[6] << 8) |
              ((guint32) payload[7] << 16) | ((guint32) payload[8] << 24);

  if (data_size != payload_len - 9)
    {
      fp_warn ("Production read size mismatch: %u != %zu",
               data_size, payload_len - 9);
      return FALSE;
    }

  *out_data = payload + 9;
  *out_data_len = data_size;
  return TRUE;
}
