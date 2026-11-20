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

#include "driver-private.h"

/* Command bytes are copied when the request is accepted. */
typedef struct
{
  guint8   category;
  guint8   command;
  guint8  *payload;
  gsize    payload_len;
  gboolean use_checksum;
} GoodixCmd;

typedef struct
{
  GoodixCmd cmd;
  /* A2 reset with data uses the shared A/0,A/1,A/4 event, ACK 500 ms,
   * response 1000 ms, one attempt. Type-zero IRQ payload is {5,20}; its
   * completed reply view contains the little-endian three-byte IRQ value.
   * Without data the type-zero payload is {1,20}, ACK-only. */
  gboolean expect_data;
  /* Retained caller hint; IN now survives every command until quiesce. */
  gboolean idle_after_ack;
} GoodixTransportRequest;

typedef struct
{
  /* Last accepted odd ACK; ordinary exhaustion follows native retry policy. */
  guint8 ack_status;
  gboolean ordinary_exhaustion;
  gboolean write_cancelled;
  gboolean restart_gtls;
} GoodixTransportResult;

/* Error ownership transfers to done. Result is borrowed for that call only.
 * The completed operation is detached before caller code can submit another. */
typedef void (*GoodixTransportDone) (FpDevice *dev,
                                    const GoodixTransportResult *result,
                                    GError *error, gpointer data);
typedef void (*GoodixTransportJoined) (FpDevice *dev, gpointer data);

/* Copy the request before returning. The independent IN remains posted. */
void goodix_transport_command (FpDevice *dev, const GoodixTransportRequest *request,
                                GoodixTransportDone done, gpointer data);
void goodix_transport_wait_event (FpDevice *dev, GoodixProfile9FdtWaitMode mode,
                                   GoodixTransportDone done, gpointer data);
void goodix_transport_wait_mcu (FpDevice *dev, guint timeout, gsize length,
                                GoodixTransportDone done, gpointer data);
void goodix_transport_reset_mcu (FpDevice *dev);
void goodix_transport_cancel_event (FpDevice *dev);
/* Foreground and CPU work must already be settled. Join the continuous IN;
 * this is not a policy to cancel outstanding commands or CPU work. */
void goodix_transport_quiesce (FpDevice *dev, GoodixTransportJoined joined,
                               gpointer data);

/* Timeouts in ms */
#define GOODIX_ACK_TIMEOUT    2000
#define GOODIX_DATA_TIMEOUT   5000

/* Commit the native parser-side base updates before publishing a notification.
 * Dispatch must not apply these updates again for a selected notification. */
void goodix_recv_apply_fdt_event (FpDevice                     *dev,
                                 GoodixFdtEventType             type,
                                 const GoodixProfile9FdtEvent  *event);

/* Copy the validated notification selected by wait_event. Mode was used at
 * decode time; selected type/event/predecessor are independent of later RX. */
gboolean goodix_recv_select_fdt (FpDevice *dev, GoodixFdtEventType *type,
                                 GoodixProfile9FdtEvent *event,
                                 guint16 *prior_down, GError **error);

/* Invalidate transport-local reception only after its owners have joined. */
void goodix_transport_invalidate (FpDevice *dev);

/* Access the transport's validated response view. Generic command completion
 * selects the retained shared cache (and awaited selector), including data
 * received before ACK. Other packets borrow RX storage. Consume either view
 * before starting another receive; this does not reparse the wire bytes. */
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
