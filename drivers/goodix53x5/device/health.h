/*
 * Goodix 53x5 driver for libfprint - profile-9 sensor health
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fpi-device.h"

/* Per-HAL owners. The module's previous estimate and enrollment-check count
 * deliberately survive reset; operation also survives a same-owner reset.
 * All access to this struct belongs to the device's serialized main context. */
typedef struct
{
  guint16  history[30];
  guint32  operation;
  gboolean initialized;
  gboolean boot_seeded;
  gboolean enroll_allowed;
  gboolean study_allowed;
  gboolean complete;
  gboolean pair_active;
} GoodixSensorHealth;

typedef struct
{
  gboolean available;
  guint16  broken_pixels;
} GoodixHealthMeasurement;

typedef enum {
  GOODIX_HEALTH_PAIR_BASE,
  GOODIX_HEALTH_PAIR_UP,
} GoodixHealthPairPurpose;

/* Measurement is borrowed for this callback; copy it if BASE admission follows
 * later. Error ownership transfers to the callback. An ordinary failed pair
 * returns !available with no error; terminal host failures return an error. */
typedef void (*GoodixHealthDone) (FpDevice                      *dev,
                                  const GoodixHealthMeasurement *measurement,
                                  GError                        *error,
                                  gpointer                       user_data);

/* Actual cold HAL construction only, never a claim/capture/refresh boundary.
 * Selects the compiled enabled defaults and native missing-history-file branch.
 * No disk I/O. Zero-initialize a newly allocated owner before its first reset.
 * Reset/destruction requires the caller to join any outstanding pair first. */
void goodix_health_reset (GoodixSensorHealth *health);

/* Request admission, not hardware-read retry: retain zero for enrollment,
 * one for identify/verify. Request completion/cancellation does not clear it. */
void goodix_health_note_capture (GoodixSensorHealth *health,
                                 gboolean            enroll);

/* Call before the selected down handler's manual validation, even false down. */
void goodix_health_note_down (GoodixSensorHealth *health);

/* Caller serializes this child with all other hardware work and keeps the HAL
 * owner alive through done. BASE belongs after TX-off manual FDT, before its
 * comparison. UP belongs after the reference decision and before down-arm;
 * caller must check retained image validity (not FDT-base validity).
 * The child owns/frees both frames and never changes reference/generation/DAC.
 * Ordinary UP failure still signals complete; terminal interruption does not. */
void goodix_health_start_pair (FpDevice               *dev,
                               GoodixHealthPairPurpose purpose,
                               GoodixHealthDone        done,
                               gpointer                user_data);

/* Only after complete reference admission. A rejected base never seeds, and
 * ordinary pair failure must not reject an otherwise admitted reference. */
void goodix_health_seed_base (GoodixSensorHealth            *health,
                              const GoodixHealthMeasurement *measurement);

/* Snapshot at completed live callback publication, before that cycle's UP. */
gboolean goodix_health_enroll_allowed (const GoodixSensorHealth *health);

/* Deactivation owns one bounded wait, not a polling loop. Inspect complete at
 * entry: if false, wait for the UP done callback or 1500 ms, then finish below
 * before sleep. The caller must also join selected hardware work before issuing
 * another command. finish re-signals completion and resets the module counter
 * even on timeout, returning the retained study byte (not a study-work gate). */
#define GOODIX_HEALTH_DEACTIVATE_TIMEOUT_MS 1500
gboolean goodix_health_is_complete (const GoodixSensorHealth *health);
gboolean goodix_health_finish_deactivation (GoodixSensorHealth *health);
