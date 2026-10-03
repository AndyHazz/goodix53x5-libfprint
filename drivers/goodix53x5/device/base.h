/*
 * Goodix 53x5 driver for libfprint - native Milan base generation
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <glib.h>

#include "milan/milan.h"

#define GOODIX_FDT_BASE_LEN                        24
#define GOODIX_PROFILE9_FDT_AREA_COUNT             12
#define GOODIX_MILAN_PROFILE9_CHIP_FAMILY_MASK    0xffffff00u
#define GOODIX_MILAN_PROFILE9_CHIP_FAMILY_PREFIX  0x00220c00u
#define GOODIX_MILAN_VALIDATED_CHIP_ID             0x00220ca1u
#define GOODIX_MILAN_VALIDATED_SUBTYPE             12
#define GOODIX_MILAN_BASE_BORDER                   2
#define GOODIX_MILAN_BASE_MAD_LIMIT                200

typedef struct _FpiSsm FpiSsm;
typedef struct _FpDevice FpDevice;
typedef struct _GoodixMilanSetupSave GoodixMilanSetupSave;

typedef enum
{
  GOODIX_PROFILE9_FDT_WAIT_NONE = 0,
  GOODIX_PROFILE9_FDT_WAIT_DOWN,
  GOODIX_PROFILE9_FDT_WAIT_UP,
} GoodixProfile9FdtWaitMode;

typedef enum
{
  GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPED = 0,
  GOODIX_PROFILE9_FDT_LIFECYCLE_ACTIVE,
  GOODIX_PROFILE9_FDT_LIFECYCLE_STOPPING,
} GoodixProfile9FdtLifecycle;

typedef enum
{
  GOODIX_PROFILE9_FDT_REFRESH_NONE = 0,
  GOODIX_PROFILE9_FDT_REFRESH_FALSE_DOWN,
  GOODIX_PROFILE9_FDT_REFRESH_REVERSE,
  GOODIX_PROFILE9_FDT_REFRESH_UP,
  GOODIX_PROFILE9_FDT_REFRESH_INVALID_BASE,
  GOODIX_PROFILE9_FDT_REFRESH_UP_INVALID_BASE,
} GoodixProfile9FdtRefreshReason;

typedef enum
{
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_NONE = 0,
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_IN_PROGRESS,
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_PUBLISHED,
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_VALIDATION_FAILED,
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_CANCELLED,
  GOODIX_PROFILE9_FDT_REFRESH_OUTCOME_FATAL,
} GoodixProfile9FdtRefreshOutcome;

typedef struct
{
  guint16  irq;
  guint16  touch_flag;
  guint8   raw[GOODIX_FDT_BASE_LEN];
  gboolean pending;
} GoodixProfile9FdtEvent;

typedef struct
{
  GoodixProfile9FdtWaitMode       wait_mode;
  GoodixProfile9FdtLifecycle      lifecycle;
  FpiSsm                         *owner;
  gboolean                        base_valid;
  guint16                         drift_anchor[GOODIX_PROFILE9_FDT_AREA_COUNT];
  gboolean                        drift_anchor_empty;
  guint8                          base_down[GOODIX_FDT_BASE_LEN];
  guint8                          base_up[GOODIX_FDT_BASE_LEN];
  guint8                          base_manual[GOODIX_FDT_BASE_LEN];
  GoodixProfile9FdtEvent          event;
  gboolean                        initial_recovery_pending;
  GoodixProfile9FdtRefreshReason  refresh_reason;
  GoodixProfile9FdtRefreshOutcome refresh_outcome;
} GoodixProfile9FdtState;

typedef enum
{
  GOODIX_MILAN_BASE_STAGE_IDLE = 0,
  GOODIX_MILAN_BASE_STAGE_FDT_TX_ON_BEFORE,
  GOODIX_MILAN_BASE_STAGE_CAPTURE_TX_ON,
  GOODIX_MILAN_BASE_STAGE_FDT_TX_OFF,
  GOODIX_MILAN_BASE_STAGE_CAPTURE_TX_OFF,
  GOODIX_MILAN_BASE_STAGE_ADMIT_PAIR,
  GOODIX_MILAN_BASE_STAGE_FDT_TX_ON_AFTER,
  GOODIX_MILAN_BASE_STAGE_PUBLISH,
  GOODIX_MILAN_BASE_STAGE_REJECTED,
  GOODIX_MILAN_BASE_STAGE_CANCELLED,
  GOODIX_MILAN_BASE_STAGE_COUNT,
} GoodixMilanBaseStage;

typedef struct
{
  GoodixMilanBaseStage stage;
  guint16             *tx_on;
  guint16             *tx_off;
  gsize                tx_on_values;
  gsize                tx_off_values;
  guint64              mad;
  gint32               admission_status;
  gboolean             admitted;
} GoodixMilanBaseAttempt;

typedef struct
{
  guint64                    generation_id;
  /* Reference consumed by preprocessing; unmarked hardware recovery retains it. */
  guint16                   *setup_tx_on;
  GoodixMilanPreprocessState state;
  GoodixMilanProfileState    profile_state;
  gboolean                   admitted;
  gboolean                   identify_prelude_seen;
  guint                      identify_prelude_count;
  /* Debug sample delivery count for generation_id/setup_tx_on, independent
   * of the preprocessing state retained when the hardware reference changes. */
  guint64                    use_count;
  gboolean                   process_state_retained;
  GoodixMilanSetupSave       *setup_save;
} GoodixMilanGeneration;

typedef enum
{
  GOODIX_MILAN_BASE_ERROR_INVALID_FRAME,
  GOODIX_MILAN_BASE_ERROR_INCOMPLETE,
  GOODIX_MILAN_BASE_ERROR_ID_EXHAUSTED,
} GoodixMilanBaseError;

#define GOODIX_MILAN_BASE_ERROR (goodix_milan_base_error_quark ())
GQuark goodix_milan_base_error_quark (void);

gboolean goodix_milan_runtime_subtype_for_chip (guint32  chip_id,
                                                 guint16 *subtype);

gboolean goodix_milan_base_pair_mad (const guint16 *tx_on,
                                     gsize          tx_on_values,
                                     const guint16 *tx_off,
                                     gsize          tx_off_values,
                                     guint64       *mad,
                                     GError       **error);

void goodix_milan_base_attempt_init (GoodixMilanBaseAttempt *attempt);
void goodix_milan_base_attempt_reset (GoodixMilanBaseAttempt *attempt);
void goodix_milan_base_attempt_cancel (GoodixMilanBaseAttempt *attempt);
void goodix_milan_base_attempt_take_frame (GoodixMilanBaseAttempt *attempt,
                                           gboolean                tx_on,
                                           guint16               **frame,
                                           gsize                   values);
gboolean goodix_milan_base_attempt_admit (GoodixMilanBaseAttempt *attempt,
                                          GError                **error);

gboolean goodix_milan_generation_allocate_id (guint64  *last_generation_id,
                                               guint64  *generation_id,
                                               GError  **error);
gboolean goodix_milan_base_attempt_publish (GoodixMilanBaseAttempt  *attempt,
                                             guint64                  generation_id,
                                             GoodixMilanGeneration **generation,
                                             GError                 **error);

void goodix_milan_generation_reset_preprocess (GoodixMilanGeneration *generation);
void goodix_milan_generation_prepare_setup (FpDevice              *dev,
                                            GoodixMilanGeneration *generation);
void goodix_milan_generation_free (GoodixMilanGeneration *generation);
void goodix_milan_generation_invalidate (GoodixMilanGeneration **generation);
void goodix_milan_generation_retain_process (FpDevice *dev);
guint64 goodix_milan_generation_note_use (GoodixMilanGeneration *generation);
void goodix_milan_generation_note_identify_prelude (GoodixMilanGeneration *generation);

gboolean goodix_milan_replace_raw_frame (guint16 **owner,
                                         guint16 **frame,
                                         gsize     values,
                                         GError  **error);

void goodix_milan_base_start_ensure_subsm (FpiSsm   *parent_ssm,
                                           FpDevice *dev,
                                           gboolean  manage_ec_power);
void goodix_milan_base_start_forced_refresh_subsm (
  FpiSsm                        *parent_ssm,
  FpDevice                      *dev,
  GoodixProfile9FdtRefreshReason reason);
