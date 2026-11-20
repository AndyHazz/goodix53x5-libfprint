/*
 * Goodix 53x5 driver for libfprint - profile-9 sensor health
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/commands.h"
#include "device/health.h"
#include "device/transport.h"

#include <float.h>
#include <math.h>
#include <openssl/rand.h>
#include <string.h>

#define GOODIX_HEALTH_ENROLL_THRESHOLD 600
#define GOODIX_HEALTH_STUDY_THRESHOLD 300
#define GOODIX_HEALTH_TOLERANCE 200
#define GOODIX_HEALTH_INTERIOR ((GOODIX_SENSOR_WIDTH - 2) * (GOODIX_SENSOR_HEIGHT - 2))

/* usbinterface!0615d0/0615d4: neither health init nor destroy clears these.
 * Serialize module owners when different device contexts run concurrently. */
static GMutex goodix_health_lock;
static guint16 goodix_health_estimate;
static guint16 goodix_health_enroll_checks;

static guint16
goodix_health_difference (guint16 first, guint16 second)
{
  guint16 difference = first - second;

  return (gint16) difference > 0 ? difference : (guint16) (second - first);
}

/* usbinterface!013578: strict 800/1200 window for the mean, inclusive
 * mean +/- tolerance window for the subsequent broken-pixel count. */
static guint16
goodix_health_measure (const guint16 *first, const guint16 *second)
{
  guint32 sum = 0;
  guint16 count = 0;
  guint16 broken = 0;
  guint16 low, high;

  for (guint row = 1; row < GOODIX_SENSOR_HEIGHT - 1; row++)
    for (guint col = 1; col < GOODIX_SENSOR_WIDTH - 1; col++)
      {
        guint i = row * GOODIX_SENSOR_WIDTH + col;
        guint16 difference = goodix_health_difference (first[i], second[i]);

        if (difference > 800 && difference < 1200)
          {
            sum += difference;
            count++;
          }
      }
  if (!count)
    return GOODIX_HEALTH_INTERIOR;

  low = sum / count - GOODIX_HEALTH_TOLERANCE;
  high = sum / count + GOODIX_HEALTH_TOLERANCE;
  for (guint row = 1; row < GOODIX_SENSOR_HEIGHT - 1; row++)
    for (guint col = 1; col < GOODIX_SENSOR_WIDTH - 1; col++)
      {
        guint i = row * GOODIX_SENSOR_WIDTH + col;
        guint16 difference = goodix_health_difference (first[i], second[i]);

        broken += difference < low || difference > high;
      }
  return broken;
}

/* usbinterface!0137cc calls this a mean-square error, but returns its rounded
 * square root. Mean rounding precedes squared distances; the native square is
 * signed 32-bit after multiplication. The length-zero masked-x86 path returns
 * mean zero/root zero, reached when the enrollment counter wraps. */
static gint16
goodix_health_statistic (const guint16 *history, guint length, guint16 *mean)
{
  double sum = 0.0;
  double variance = 0.0;
  double root = 0.0;

  if (!length)
    {
      *mean = 0;
      return 0;
    }
  for (guint i = 0; i < length; i++)
    sum += history[i];
  *mean = (guint16) (sum / length + 0.5);
  for (guint i = 0; i < length; i++)
    {
      gint32 delta = ABS ((gint32) history[i] - *mean);
      gint32 square = (gint32) ((guint32) delta * (guint32) delta);

      variance += square;
    }
  variance /= length;
  if (variance > 0.0)
    {
      double previous = variance;

      do
        {
          root = (previous + variance / previous) * 0.5;
          if (fabs (previous - root) <= FLT_MIN)
            break;
          previous = root;
        }
      while (TRUE);
    }
  return (gint16) (gint32) (root + 0.5);
}

/* usbinterface!0138bc: estimate OLD history, first greatest cluster wins. */
static guint16
goodix_health_lookup (const guint16 history[30], guint16 previous)
{
  guint16 mean;
  gint16 statistic = goodix_health_statistic (history, 8, &mean);
  guint16 counts[30] = { 0 };
  guint32 sums[30] = { 0 };
  guint best = 0;

  if (history[0] == history[1] && history[1] == history[2] &&
      history[2] == history[3])
    return history[0];
  if (statistic < 5 && statistic != -1)
    return mean;
  for (guint i = 0; i < 30; i++)
    {
      for (guint j = 0; j < 30; j++)
        if (ABS ((gint32) history[i] - history[j]) < 5)
          {
            counts[i]++;
            sums[i] += history[j];
          }
      if (counts[i] > counts[best])
        best = i;
    }
  mean = sums[best] / counts[best];
  return counts[best] >= 10 && (guint32) previous >= mean + 600u ? mean : previous;
}

/* usbinterface!013b1c changes only the inserted value, never measured c. */
static void
goodix_health_insert (guint16 history[30], guint16 measured)
{
  guint16 limit = (guint16) (GOODIX_HEALTH_INTERIOR * 0.9);

  if (measured > limit)
    {
      guint8 random[2] = { 0 };
      guint16 word;

      /* Native initializes the destination and ignores generate_random's
       * result. Unlike handshake entropy this does not establish a key. */
      (void) RAND_bytes (random, sizeof (random));
      word = random[0] | ((guint16) random[1] << 8);
      measured = 601 + word % (limit - 600);
    }
  memmove (history + 1, history, 29 * sizeof (*history));
  history[0] = measured;
}

static void
goodix_health_evaluate (GoodixSensorHealth *health, guint32 operation,
                        guint16 measured)
{
  guint16 estimate, difference;

  g_mutex_lock (&goodix_health_lock);
  estimate = goodix_health_lookup (health->history, goodix_health_estimate);
  goodix_health_insert (health->history, measured);
  goodix_health_estimate = estimate;
  difference = ABS ((gint32) measured - estimate);
  if (operation == 0)
    {
      guint16 mean;
      guint length = MIN (goodix_health_enroll_checks, 4);
      gint16 statistic = goodix_health_statistic (health->history, length, &mean);

      health->enroll_allowed = estimate < GOODIX_HEALTH_ENROLL_THRESHOLD &&
                               (measured < GOODIX_HEALTH_ENROLL_THRESHOLD || statistic > 10);
      fp_dbg ("Health enrollment checks=%u length=%u statistic=%d",
              goodix_health_enroll_checks, length, statistic);
    }
  else
    {
      health->study_allowed = measured < GOODIX_HEALTH_STUDY_THRESHOLD &&
                              estimate < GOODIX_HEALTH_STUDY_THRESHOLD && difference < 20;
      health->enroll_allowed = measured < GOODIX_HEALTH_ENROLL_THRESHOLD;
    }
  g_mutex_unlock (&goodix_health_lock);
  fp_dbg ("Health operation=%u measured=%u estimate=%u difference=%u enroll=%d study=%d",
          operation, measured, estimate, difference,
          health->enroll_allowed, health->study_allowed);
}

void
goodix_health_reset (GoodixSensorHealth *health)
{
  g_return_if_fail (health != NULL && !health->pair_active);
  memset (health->history, 0, sizeof (health->history));
  health->initialized = TRUE;
  health->boot_seeded = FALSE;
  health->enroll_allowed = TRUE;
  health->study_allowed = FALSE;
  health->complete = TRUE;
}

void
goodix_health_note_capture (GoodixSensorHealth *health, gboolean enroll)
{
  g_return_if_fail (health != NULL && health->initialized);
  health->operation = enroll ? 0 : 1;
}

void
goodix_health_note_down (GoodixSensorHealth *health)
{
  g_return_if_fail (health != NULL && health->initialized);
  health->study_allowed = FALSE;
  health->complete = FALSE;
}

void
goodix_health_seed_base (GoodixSensorHealth            *health,
                         const GoodixHealthMeasurement *measurement)
{
  g_return_if_fail (health != NULL && health->initialized);
  g_return_if_fail (measurement != NULL);
  if (health->boot_seeded || !measurement->available)
    return;
  g_mutex_lock (&goodix_health_lock);
  for (guint i = 0; i < G_N_ELEMENTS (health->history); i++)
    health->history[i] = measurement->broken_pixels;
  goodix_health_estimate = measurement->broken_pixels;
  health->boot_seeded = TRUE;
  g_mutex_unlock (&goodix_health_lock);
}

gboolean
goodix_health_enroll_allowed (const GoodixSensorHealth *health)
{
  g_return_val_if_fail (health != NULL && health->initialized, FALSE);
  return health->enroll_allowed;
}

gboolean
goodix_health_is_complete (const GoodixSensorHealth *health)
{
  g_return_val_if_fail (health != NULL && health->initialized, FALSE);
  return health->complete;
}

gboolean
goodix_health_finish_deactivation (GoodixSensorHealth *health)
{
  g_return_val_if_fail (health != NULL && health->initialized, FALSE);
  health->complete = TRUE;
  g_mutex_lock (&goodix_health_lock);
  goodix_health_enroll_checks = 0;
  g_mutex_unlock (&goodix_health_lock);
  return health->study_allowed;
}

typedef enum {
  GOODIX_HEALTH_FIRST,
  GOODIX_HEALTH_SECOND,
  GOODIX_HEALTH_MEASURE,
  GOODIX_HEALTH_NUM_STATES,
} GoodixHealthState;

typedef struct
{
  GoodixHealthPairPurpose purpose;
  GoodixHealthDone        done;
  gpointer                user_data;
  guint32                 operation;
  guint16                *frames[2];
  GoodixHealthMeasurement measurement;
} GoodixHealthPair;

static void
goodix_health_pair_free (GoodixHealthPair *pair)
{
  g_free (pair->frames[0]);
  g_free (pair->frames[1]);
  g_free (pair);
}

static void
goodix_health_image_done (FpDevice *dev, const GoodixTransportResult *result,
                          GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  GoodixHealthPair *pair = fpi_ssm_get_data (ssm);
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (error)
    {
      if (result->write_cancelled)
        self->needs_reinit = TRUE;
      if (result->ordinary_exhaustion)
        {
          fp_dbg ("Health image acquisition exhausted: %s", error->message);
          g_clear_error (&error);
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      return;
    }
  pair->frames[fpi_ssm_get_cur_state (ssm)] = goodix_cmd_dup_image_reply (dev, &error);
  if (error)
    {
      /* Native raw-read status -1 is ordinary even when the command ACK and
       * image event completed. It does not replace the caller's old state. */
      fp_dbg ("Health raw image unavailable: %s", error->message);
      g_clear_error (&error);
      fpi_ssm_mark_completed (ssm);
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
goodix_health_pair_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixHealthPair *pair = fpi_ssm_get_data (ssm);
  guint state = fpi_ssm_get_cur_state (ssm);

  if (state == GOODIX_HEALTH_MEASURE)
    {
      pair->measurement.broken_pixels = goodix_health_measure (pair->frames[0], pair->frames[1]);
      pair->measurement.available = TRUE;
      if (pair->purpose == GOODIX_HEALTH_PAIR_UP)
        goodix_health_evaluate (&self->health, pair->operation, pair->measurement.broken_pixels);
      fpi_ssm_mark_completed (ssm);
      return;
    }
  else
    {
      guint16 dac = self->calib.dac_l;
      guint8 payload[4];
      GoodixTransportRequest request = {
        .cmd = { 2, 0, payload, sizeof (payload), TRUE },
        .expect_data = TRUE,
      };

      if (state == GOODIX_HEALTH_SECOND)
        dac -= self->calib.dac_delta;
      /* usbinterface!012d38 -> 0055d0 -> 0074bc: TX on, configured HV six,
       * no finger flag. Mode 2/3 is not encoded. Use the existing command
       * transport directly to retain its ordinary-exhaustion classification. */
      payload[0] = 0x01;
      payload[1] = 6;
      payload[2] = dac & 0xff;
      payload[3] = dac >> 8;
      goodix_transport_command (dev, &request, goodix_health_image_done, ssm);
    }
}

static void
goodix_health_pair_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixHealthPair *pair = fpi_ssm_get_data (ssm);

  self->health.pair_active = FALSE;
  if (!error && pair->purpose == GOODIX_HEALTH_PAIR_UP)
    self->health.complete = TRUE;
  pair->done (dev, &pair->measurement, error, pair->user_data);
}

void
goodix_health_start_pair (FpDevice *dev, GoodixHealthPairPurpose purpose,
                          GoodixHealthDone done, gpointer user_data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixHealthPair *pair;
  FpiSsm *ssm;

  g_return_if_fail (done != NULL);
  if (!self->health.initialized || self->health.pair_active || self->transport ||
      (purpose != GOODIX_HEALTH_PAIR_BASE && purpose != GOODIX_HEALTH_PAIR_UP))
    {
      GoodixHealthMeasurement unavailable = { 0 };

      done (dev, &unavailable,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY, "Sensor health owner is unavailable"),
            user_data);
      return;
    }
  pair = g_new0 (GoodixHealthPair, 1);
  pair->purpose = purpose;
  pair->done = done;
  pair->user_data = user_data;
  pair->operation = self->health.operation;
  self->health.pair_active = TRUE;
  if (purpose == GOODIX_HEALTH_PAIR_UP && pair->operation == 0)
    {
      g_mutex_lock (&goodix_health_lock);
      goodix_health_enroll_checks++;
      g_mutex_unlock (&goodix_health_lock);
    }
  ssm = fpi_ssm_new (dev, goodix_health_pair_handler, GOODIX_HEALTH_NUM_STATES);
  fpi_ssm_set_data (ssm, pair, (GDestroyNotify) goodix_health_pair_free);
  fpi_ssm_start (ssm, goodix_health_pair_done);
}
