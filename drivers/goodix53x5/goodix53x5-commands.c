/*
 * Goodix 53x5 driver for libfprint — Named device commands and reply parsers
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

#include <string.h>

#define GOODIX_PROTO_CATEGORY_FDT     0x03
#define GOODIX_PROTO_CMD_FDT_DOWN     0x01
#define GOODIX_PROTO_CMD_FDT_UP       0x02
#define GOODIX_PROTO_CMD_FDT_MANUAL   0x03

/* HV value for image capture */
#define GOODIX_HV_VALUE 6

/* ========================================================================
 * Payload builders
 * ======================================================================== */

static void
goodix_build_fdt_payload (guint8  op_code,
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

static void
goodix_encode_u32_le (guint8 *out, guint32 value)
{
  out[0] = value & 0xFF;
  out[1] = (value >> 8) & 0xFF;
  out[2] = (value >> 16) & 0xFF;
  out[3] = (value >> 24) & 0xFF;
}

/* ========================================================================
 * Named device commands
 * ======================================================================== */

void
goodix_cmd_ping (FpiSsm *ssm, FpDevice *dev)
{
  /* ping: category=0, command=0, payload=\x00\x00 */
  guint8 payload[2] = { 0x00, 0x00 };

  goodix_run_cmd (ssm, dev, 0x0, 0x0, payload, 2, FALSE);
}

void
goodix_cmd_read_fw_version (FpiSsm *ssm, FpDevice *dev)
{
  /* read_firmware_version: category=0xA, command=4, payload=\x00\x00 */
  guint8 payload[2] = { 0x00, 0x00 };

  goodix_run_cmd (ssm, dev, 0xA, 0x4, payload, 2, TRUE);
}

void
goodix_cmd_reset_sensor (FpiSsm *ssm, FpDevice *dev)
{
  /* reset type 0, irq_status=false: msg = 0b001 | (20<<8) = 0x1401 */
  guint16 msg = 0x01 | (20 << 8);
  guint8 payload[2] = { msg & 0xFF, (msg >> 8) & 0xFF };

  goodix_run_cmd (ssm, dev, 0xA, 0x1, payload, 2, FALSE);
}

void
goodix_cmd_read_chip_id (FpiSsm *ssm, FpDevice *dev)
{
  /* read_data(addr=0, size=4): category=0x8, command=0x1 */
  guint8 payload[5] = {
    0x00,       /* \x00 */
    0x00, 0x00, /* addr LE */
    0x04, 0x00, /* size LE */
  };

  goodix_run_cmd (ssm, dev, 0x8, 0x1, payload, 5, TRUE);
}

void
goodix_cmd_read_otp (FpiSsm *ssm, FpDevice *dev)
{
  /* read_otp: category=0xA, command=0x3, payload=\x00\x00 */
  guint8 payload[2] = { 0x00, 0x00 };

  goodix_run_cmd (ssm, dev, 0xA, 0x3, payload, 2, TRUE);
}

void
goodix_cmd_production_read (FpiSsm *ssm, FpDevice *dev, guint32 read_type)
{
  guint8 payload[4];

  goodix_encode_u32_le (payload, read_type);
  goodix_run_cmd (ssm, dev, 0xE, 0x2, payload, 4, TRUE);
}

void
goodix_cmd_production_write (FpiSsm *ssm, FpDevice *dev,
                             guint32 data_type,
                             const guint8 *data, gsize data_len)
{
  gsize payload_len = 4 + 4 + data_len;
  g_autofree guint8 *payload = g_malloc (payload_len);

  goodix_encode_u32_le (payload, data_type);
  goodix_encode_u32_le (payload + 4, (guint32) data_len);
  memcpy (payload + 8, data, data_len);

  goodix_run_cmd (ssm, dev, 0xE, 0x1, payload, payload_len, TRUE);
}

void
goodix_cmd_mcu_send (FpiSsm *ssm, FpDevice *dev, guint32 data_type,
                     const guint8 *data, gsize data_len)
{
  guint8 *payload;
  gsize payload_len;

  goodix_proto_build_mcu_message (data_type, data, data_len,
                                  &payload, &payload_len);
  goodix_run_cmd (ssm, dev, 0xD, 0x1, payload, payload_len, FALSE);
  g_free (payload);
}

void
goodix_cmd_upload_config (FpiSsm *ssm, FpDevice *dev,
                          const guint8 *config, gsize config_len)
{
  goodix_run_cmd (ssm, dev, 0x9, 0x0, config, config_len, TRUE);
}

void
goodix_cmd_fdt_down_setup (FpiSsm *ssm, FpDevice *dev,
                           const guint8 *fdt_base)
{
  guint8 *payload;
  gsize payload_len;

  goodix_build_fdt_payload (0x0C, fdt_base, &payload, &payload_len);
  goodix_run_cmd (ssm, dev, GOODIX_PROTO_CATEGORY_FDT,
                  GOODIX_PROTO_CMD_FDT_DOWN, payload, payload_len, FALSE);
  g_free (payload);
}

void
goodix_cmd_fdt_up_setup (FpiSsm *ssm, FpDevice *dev,
                         const guint8 *fdt_base)
{
  guint8 *payload;
  gsize payload_len;

  goodix_build_fdt_payload (0x0E, fdt_base, &payload, &payload_len);
  goodix_run_cmd (ssm, dev, GOODIX_PROTO_CATEGORY_FDT,
                  GOODIX_PROTO_CMD_FDT_UP, payload, payload_len, FALSE);
  g_free (payload);
}

void
goodix_cmd_fdt_manual (FpiSsm *ssm, FpDevice *dev,
                       gboolean tx_enable, const guint8 *fdt_base)
{
  /* Manual FDT op code: 0x0D with TX enabled, 0x8D with TX disabled */
  guint8 op_code = tx_enable ? 0x0D : 0x8D;
  guint8 *payload;
  gsize payload_len;

  goodix_build_fdt_payload (op_code, fdt_base, &payload, &payload_len);
  goodix_run_cmd (ssm, dev, GOODIX_PROTO_CATEGORY_FDT,
                  GOODIX_PROTO_CMD_FDT_MANUAL, payload, payload_len, TRUE);
  g_free (payload);
}

void
goodix_cmd_request_image (FpiSsm *ssm, FpDevice *dev,
                          gboolean tx_enable, gboolean hv_enable,
                          gboolean is_finger, guint16 dac)
{
  guint8 img_req[4];

  goodix_build_image_request (tx_enable, hv_enable, is_finger, dac, img_req);
  goodix_run_cmd (ssm, dev, 0x2, 0x0, img_req, sizeof (img_req), TRUE);
}

void
goodix_cmd_set_sleep_mode (FpiSsm *ssm, FpDevice *dev)
{
  /* set_sleep_mode: category=0x6, command=0, payload=\x01\x00 */
  guint8 payload[2] = { 0x01, 0x00 };

  goodix_run_cmd (ssm, dev, 0x6, 0x0, payload, 2, FALSE);
}

void
goodix_cmd_ec_control (FpiSsm *ssm, FpDevice *dev, gboolean on)
{
  guint8 payload_on[3] = { 0x01, 0x01, 0x00 };
  guint8 payload_off[3] = { 0x00, 0x00, 0x00 };

  goodix_run_cmd (ssm, dev, 0xA, 0x7, on ? payload_on : payload_off, 3, TRUE);
}

/* ========================================================================
 * Named reply parsers
 * ======================================================================== */

gboolean
goodix_cmd_parse_fw_version_reply (FpDevice      *dev,
                                   const guint8 **out_payload,
                                   gsize         *out_payload_len,
                                   GError       **error)
{
  return goodix_parse_reply_exact (dev, 0xA, 0x4, out_payload,
                                   out_payload_len, error);
}

gboolean
goodix_cmd_parse_chip_id_reply (FpDevice      *dev,
                                const guint8 **out_payload,
                                gsize         *out_payload_len,
                                GError       **error)
{
  return goodix_parse_reply_exact (dev, 0x8, 0x1, out_payload,
                                   out_payload_len, error);
}

gboolean
goodix_cmd_parse_otp_reply (FpDevice      *dev,
                            const guint8 **out_payload,
                            gsize         *out_payload_len,
                            GError       **error)
{
  return goodix_parse_reply_exact (dev, 0xA, 0x3, out_payload,
                                   out_payload_len, error);
}

gboolean
goodix_cmd_parse_production_read_reply (FpDevice      *dev,
                                        guint32        read_type,
                                        const guint8 **out_data,
                                        gsize         *out_data_len)
{
  const guint8 *payload;
  gsize payload_len;

  return goodix_parse_reply_exact (dev, 0xE, 0x2, &payload, &payload_len,
                                   NULL) &&
         goodix_proto_parse_production_read (payload, payload_len, read_type,
                                             out_data, out_data_len);
}

gboolean
goodix_cmd_parse_production_write_reply (FpDevice      *dev,
                                         const guint8 **out_payload,
                                         gsize         *out_payload_len)
{
  return goodix_parse_reply_exact (dev, 0xE, 0x1, out_payload,
                                   out_payload_len, NULL);
}

gboolean
goodix_cmd_parse_mcu_reply (FpDevice      *dev,
                            guint32        expected_type,
                            const guint8 **out_data,
                            gsize         *out_data_len)
{
  guint8 category, command;
  const guint8 *payload;
  gsize payload_len;

  return goodix_parse_reply (dev, &category, &command, &payload,
                             &payload_len, NULL) &&
         goodix_proto_parse_mcu_message (payload, payload_len, expected_type,
                                         out_data, out_data_len);
}

gboolean
goodix_cmd_parse_config_reply (FpDevice *dev)
{
  const guint8 *payload;
  gsize payload_len;

  return goodix_parse_reply_exact (dev, 0x9, 0x0, &payload, &payload_len,
                                   NULL) &&
         payload_len > 0 && payload[0] == 1;
}

gboolean
goodix_cmd_parse_ec_control_reply (FpDevice *dev)
{
  const guint8 *payload;
  gsize payload_len;

  return goodix_parse_reply_exact (dev, 0xA, 0x7, &payload, &payload_len,
                                   NULL) &&
         payload_len > 0 && payload[0] == 1;
}

gboolean
goodix_cmd_parse_fdt_manual_reply (FpDevice      *dev,
                                   const guint8 **out_payload,
                                   gsize         *out_payload_len,
                                   GError       **error)
{
  if (!goodix_parse_reply_exact (dev, GOODIX_PROTO_CATEGORY_FDT,
                                 GOODIX_PROTO_CMD_FDT_MANUAL,
                                 out_payload, out_payload_len, error))
    return FALSE;

  if (*out_payload_len < 4 + GOODIX_FDT_BASE_LEN)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Manual FDT reply is too short: %zu", *out_payload_len);
      return FALSE;
    }

  return TRUE;
}

gboolean
goodix_cmd_parse_fdt_event (FpDevice      *dev,
                            gboolean       up,
                            const guint8 **out_payload,
                            gsize         *out_payload_len,
                            GError       **error)
{
  guint8 category, command;
  guint8 expected_command =
    up ? GOODIX_PROTO_CMD_FDT_UP : GOODIX_PROTO_CMD_FDT_DOWN;
  const gchar *event_name = up ? "finger-up" : "FDT down";

  if (!goodix_parse_reply (dev, &category, &command, out_payload,
                           out_payload_len, NULL))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Failed to parse %s event", event_name);
      return FALSE;
    }

  /* [irq_status(2)][touch_flag(2)][fdt_data(GOODIX_FDT_BASE_LEN)] */
  if (category != GOODIX_PROTO_CATEGORY_FDT ||
      command != expected_command ||
      *out_payload_len < 4 + GOODIX_FDT_BASE_LEN)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected %s event: cat=0x%02x cmd=0x%02x len=%zu",
                   event_name, category, command, *out_payload_len);
      return FALSE;
    }

  return TRUE;
}
