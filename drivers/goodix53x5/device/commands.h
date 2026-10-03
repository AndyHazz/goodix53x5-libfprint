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

#pragma once

#include "driver-private.h"

/* ========================================================================
 * Named device commands
 *
 * These wrap goodix_run_cmd() so action modules read as device operations
 * instead of category/command bytes and hand-built payloads. Commands that
 * expect a data reply have a matching named reply parser below; commands
 * documented as "ACK only" advance the parent SSM after ACK validation.
 * ======================================================================== */

/* Ping the MCU. ACK only. */
void goodix_cmd_ping (FpiSsm *ssm, FpDevice *dev);

/* Composite owners distinguish ordinary exhausted transactions from terminal
 * protocol/host errors. Callback takes error ownership and resolves ssm. */
typedef void (*GoodixCmdResultCallback) (FpiSsm *ssm, FpDevice *dev,
                                        guint8 status, gboolean native_zero,
                                        GError *error);

/* Read the firmware version string. Expects data. */
void goodix_cmd_read_fw_version (FpiSsm *ssm, FpDevice *dev);
void goodix_cmd_probe (FpiSsm *ssm, FpDevice *dev, gboolean firmware,
                       GoodixCmdResultCallback callback);

/* Reset type 0. With @request_irq, wait for the shared reset/version response
 * event as well as ACK; startup recovery discards the returned IRQ bytes. */
void goodix_cmd_reset_sensor (FpiSsm *ssm, FpDevice *dev, gboolean request_irq,
                              GoodixCmdResultCallback callback);

/* Read 4 bytes of chip ID from register address 0. Expects data. */
void goodix_cmd_read_chip_id (FpiSsm *ssm, FpDevice *dev,
                              GoodixCmdResultCallback callback);

/* Read the OTP calibration block. Expects data. */
void goodix_cmd_read_otp (FpiSsm *ssm, FpDevice *dev);

/* Production read of @read_type (e.g. 0xB003 = PSK hash). Expects data. */
void goodix_cmd_production_read (FpiSsm *ssm, FpDevice *dev,
                                 guint32 read_type);

/* Production write of @data under @data_type (e.g. 0xB002 = PSK white box).
 * Expects data (a one-byte status reply). */
void goodix_cmd_production_write (FpiSsm *ssm, FpDevice *dev,
                                  guint32 data_type,
                                  const guint8 *data, gsize data_len);

/* Send an MCU envelope of @data_type (GTLS handshake traffic). ACK only;
 * the device replies asynchronously via a plain receive. */
void goodix_cmd_mcu_send (FpiSsm *ssm, FpDevice *dev, guint32 data_type,
                          const guint8 *data, gsize data_len);

/* Post-MCU-ACK GTLS wait; consume the bounded stream after its receive signal. */
void goodix_recv_mcu (FpiSsm *ssm, FpDevice *dev, guint timeout, gsize length);

/* Upload the (patched) sensor config blob. Waits for the configuration event;
 * its payload is not a success flag. */
void goodix_cmd_upload_config (FpiSsm *ssm, FpDevice *dev,
                               const guint8 *config, gsize config_len);

/* Native mode 4: restore the profile configuration using retained calibration. */
void goodix_cmd_restore_config (FpiSsm *ssm, FpDevice *dev,
                                GoodixCmdResultCallback callback);

/* Category-C/0 GFESD repair, native missing-saved-file/RAM continuation. */
void goodix_cmd_repair_esd (FpiSsm *ssm, FpDevice *dev);

/* Arm finger-down detection with @fdt_base. ACK only; the FDT event arrives
 * later via a cancellable receive. */
void goodix_cmd_fdt_down_setup (FpiSsm *ssm, FpDevice *dev,
                                const guint8 *fdt_base);

/* Arm finger-up detection with @fdt_base. ACK only; the FDT event arrives
 * later via a cancellable receive. */
void goodix_cmd_fdt_up_setup (FpiSsm *ssm, FpDevice *dev,
                              const guint8 *fdt_base);

/* Run a manual FDT check against @fdt_base, with sensor TX on or off.
 * Expects data (irq status, touch flag and live FDT data). */
void goodix_cmd_fdt_manual (FpiSsm *ssm, FpDevice *dev,
                            gboolean tx_enable, const guint8 *fdt_base);
void goodix_cmd_fdt_manual_result (FpiSsm *ssm, FpDevice *dev,
                                   gboolean tx_enable, const guint8 *fdt_base,
                                   GoodixCmdResultCallback callback);

/* Request an image frame. Expects data (the encrypted frame). */
void goodix_cmd_request_image (FpiSsm *ssm, FpDevice *dev,
                               gboolean tx_enable, gboolean hv_enable,
                               gboolean is_finger, guint16 dac);
void goodix_cmd_request_image_result (FpiSsm *ssm, FpDevice *dev,
                                      gboolean tx_enable, gboolean hv_enable,
                                      gboolean is_finger, guint16 dac,
                                      GoodixCmdResultCallback callback);

/* Put the MCU into sleep mode. ACK only. */
void goodix_cmd_set_sleep_mode (FpiSsm *ssm, FpDevice *dev);
void goodix_cmd_set_sleep_mode_result (FpiSsm *ssm, FpDevice *dev,
                                       GoodixCmdResultCallback callback);

/* Switch sensor EC power on or off. ACK only; off enables idle tail servicing. */
void goodix_cmd_ec_control (FpiSsm *ssm, FpDevice *dev, gboolean on);

/* ========================================================================
 * Named reply parsers
 *
 * Payload pointers borrow the transport's validated reply view. Shared-response
 * commands consume parser cache bytes, even when data arrived before ACK.
 * Firmware uses that same cache; manual FDT uses its own. Consume borrowed
 * views before the next receive/invalidation can replace them.
 * ======================================================================== */

gboolean goodix_cmd_parse_fw_version_reply (FpDevice      *dev,
                                            const guint8 **out_payload,
                                            gsize         *out_payload_len,
                                            GError       **error);

gboolean goodix_cmd_parse_chip_id_reply (FpDevice      *dev,
                                         const guint8 **out_payload,
                                         gsize         *out_payload_len,
                                         GError       **error);

gboolean goodix_cmd_parse_otp_reply (FpDevice      *dev,
                                     const guint8 **out_payload,
                                     gsize         *out_payload_len,
                                     GError       **error);

gboolean goodix_cmd_parse_production_read_reply (FpDevice      *dev,
                                                 guint32        read_type,
                                                 const guint8 **out_data,
                                                 gsize         *out_data_len);

gboolean goodix_cmd_parse_production_write_reply (FpDevice      *dev,
                                                  const guint8 **out_payload,
                                                  gsize         *out_payload_len);

gboolean goodix_cmd_parse_mcu_reply (FpDevice      *dev,
                                     guint32        expected_type,
                                     const guint8 **out_data,
                                     gsize         *out_data_len);

/* TRUE if the configuration response event has been published for this send. */
gboolean goodix_cmd_parse_config_reply (FpDevice *dev);

/* Parse a manual FDT reading returned by goodix_cmd_fdt_manual(). */
gboolean goodix_cmd_parse_fdt_manual_reply (FpDevice      *dev,
                                             const guint8 **out_payload,
                                             gsize         *out_payload_len,
                                             GError       **error);

/* Copy the receiver-decoded frame selected by goodix_cmd_request_image().
 * The caller owns the copy; subsequent reception cannot replace its bytes. */
guint16 *goodix_cmd_dup_image_reply (FpDevice *dev,
                                     GError  **error);

/* Parse an FDT down/up event delivered after goodix_cmd_fdt_down_setup() /
 * goodix_cmd_fdt_up_setup(). The payload layout is
 * [irq_status(2)][touch_flag(2)][fdt_data(GOODIX_FDT_BASE_LEN)]. Decoding does
 * not apply base mutations or select the worker's pending notification.
 * NONE writes only pending=FALSE; CONFIG writes irq/pending, with no sample. */
gboolean goodix_cmd_parse_fdt_event (FpDevice      *dev,
                                     GoodixProfile9FdtWaitMode armed_mode,
                                     GoodixFdtEventType       *out_type,
                                     GoodixProfile9FdtEvent   *out_event,
                                     GError       **error);
