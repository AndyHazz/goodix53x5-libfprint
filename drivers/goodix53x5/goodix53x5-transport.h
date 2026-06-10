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

#pragma once

#include "goodix53x5-private.h"

/* Timeouts in ms */
#define GOODIX_CMD_TIMEOUT    1000
#define GOODIX_ACK_TIMEOUT    2000
#define GOODIX_DATA_TIMEOUT   5000

/**
 * Start receiving a message. Submits a bulk IN read; the RX callback handles
 * chunk reassembly and resubmits until the message is complete, then advances
 * @ssm. Zero-length reads are accepted by resubmitting.
 */
void goodix_recv_start (FpiSsm       *ssm,
                        FpDevice     *dev,
                        guint         timeout_ms,
                        GCancellable *cancellable);

/**
 * Receive with cancellable support (for finger wait).
 * Uses infinite timeout (0) so the read blocks until the sensor sends data.
 */
void goodix_recv_start_cancellable (FpiSsm       *ssm,
                                    FpDevice     *dev,
                                    GCancellable *cancellable);

/**
 * Launch a command sub-SSM that sends a command and receives + validates the
 * ACK. If @expect_data is TRUE, the command also receives the data response,
 * which the caller parses with goodix_parse_reply() / goodix_parse_reply_exact()
 * once the parent SSM advances.
 */
void goodix_run_cmd (FpiSsm       *parent_ssm,
                     FpDevice     *dev,
                     guint8        category,
                     guint8        command,
                     const guint8 *payload,
                     gsize         payload_len,
                     gboolean      expect_data);

/* Parsed reply payloads point into the current RX buffer and are valid only
 * until the next receive reset. */
gboolean goodix_parse_reply (FpDevice      *dev,
                             guint8        *out_category,
                             guint8        *out_command,
                             const guint8 **out_payload,
                             gsize         *out_payload_len,
                             GError       **error);

gboolean goodix_parse_reply_exact (FpDevice      *dev,
                                   guint8         expected_category,
                                   guint8         expected_command,
                                   const guint8 **out_payload,
                                   gsize         *out_payload_len,
                                   GError       **error);
