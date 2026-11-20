/*
 * Goodix 53x5 driver for libfprint - current Milan runtime contracts
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "test-goodix53x5-milan-runtime-support.h"

void
generate_frames (guint16 setup[PIXELS],
                 guint16 live[PIXELS],
                 guint   pattern)
{
  gint ramp_column = 54 + (10 - 2 * (gint) (pattern % 5)) % 10;
  gint ramp_radius = pattern >= 9 ? 5 : 4;

  for (guint row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
    for (guint column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
      {
        gsize index = (gsize) row * GOODIX_MILAN_SENSOR_COLUMNS + column;
        guint16 baseline = (guint16) (
          0x0700 + row * 3 + column * 2 +
          (((row * 7) ^ (column * 13) ^ (pattern * 11)) & 0x3f));
        gint wrapped = (column * 8 + row * 8 + pattern * 17) % 80;
        gint first = ((gint) column - 32 - (gint) pattern) *
                     ((gint) column - 32 - (gint) pattern) +
                     ((gint) row - 28) * ((gint) row - 28);
        gint second = ((gint) column - 72) * ((gint) column - 72) +
                      ((gint) row - 55 + (gint) pattern) *
                      ((gint) row - 55 + (gint) pattern);
        guint16 delta = wrapped < 40 ? 300 : 1200;

        if (first < 36 || second < 49)
          delta = 1200;
        /* Avoid an all-sharp synthetic score distribution. */
        if (ABS ((gint) row - 44) <= ramp_radius &&
            ABS ((gint) column - ramp_column) <= ramp_radius)
          {
            setup[index] = (guint16) (
              baseline - delta + 800 +
              (ramp_radius - MAX (ABS ((gint) row - 44),
                                  ABS ((gint) column - ramp_column))) * 80);
          }
        else
          {
            setup[index] = baseline;
          }
        live[index] = (guint16) (baseline - delta);
      }
}

GBytes *
generate_template (guint pattern)
{
  g_autofree GoodixMilanPreprocessState *state = g_new0 (
    GoodixMilanPreprocessState, 1);
  GoodixMilanProfileState profile = { 0 };
  g_autofree guint16 *setup = g_new (guint16, PIXELS);
  g_autofree guint16 *live = g_new (guint16, PIXELS);
  g_autofree guint8 *processed = g_new (guint8, PIXELS);

  g_autoptr(GPtrArray) features = g_ptr_array_new_with_free_func (
    (GDestroyNotify) g_bytes_unref);
  GoodixMatchInfo *info = NULL;
  g_autoptr(GBytes) feature = NULL;
  GBytes *combined;
  gint quality = -1;
  gint coverage = -1;

  generate_frames (setup, live, pattern);
  goodix_milan_preprocess_reset (state);
  g_assert_cmpint (goodix_milan_preprocess (
                     state, &profile, setup, live, GOODIX_MILAN_PURPOSE_ENROLL,
                     processed, &quality, &coverage), ==, 0);
  g_assert_cmpint (goodix_milan_match_extract_native_result (
                     processed, state, live, (guint16) pattern,
                     (guint16) pattern, 0, GOODIX_MILAN_PRINT_SENSOR_TYPE,
                     &info), ==, GOODIX_MILAN_EXTRACTION_OK);
  feature = goodix_milan_match_serialize_template (info);
  g_assert_nonnull (feature);
  g_ptr_array_add (features, g_bytes_ref (feature));
  combined = goodix_milan_match_combine_templates (features);
  g_assert_nonnull (combined);
  g_assert_true (goodix_milan_print_validate_template (combined, NULL, NULL));
  goodix_milan_match_free_info (info);
  return combined;
}

static void
harness_open (FpDevice *device)
{
  fpi_device_open_complete (device, NULL);
}

static void
harness_close (FpDevice *device)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);

  g_clear_object (&self->milan_task);
  g_clear_object (&self->cancel);
  milan_runtime_test_clear_pending_result_report (self);
#ifdef GOODIX53X5_DEBUG
  g_clear_pointer (&self->captured_image, g_free);
#endif
  g_clear_pointer (&self->captured_raw_image, g_free);
  goodix_milan_generation_invalidate (&self->milan_generation);
  g_clear_pointer (&self->enroll_transaction,
                   goodix_milan_enrollment_transaction_free);
  fpi_device_close_complete (device, NULL);
}

static void
harness_cancel (FpDevice *device)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (device);

  self->action_epoch++;
  if (self->cancel)
    g_cancellable_cancel (self->cancel);
  g_mutex_lock (&plan.mutex);
  plan.cancel_called = TRUE;
  g_cond_broadcast (&plan.condition);
  g_mutex_unlock (&plan.mutex);
}

static const FpIdEntry harness_ids[] = {
  { .virtual_envvar = "GOODIX53X5_MILAN_RUNTIME_TEST" },
  { .virtual_envvar = NULL },
};

FpDevice *
new_device (void)
{
  FpDeviceClass *klass = g_type_class_ref (FPI_TYPE_DEVICE_GOODIX53X5);
  FpDevice *device;
  FpiDeviceGoodix53x5 *self;
  g_autofree guint16 *live = g_new (guint16, PIXELS);

  klass->type = FP_DEVICE_TYPE_VIRTUAL;
  klass->id_table = harness_ids;
  klass->open = harness_open;
  klass->close = harness_close;
  klass->verify = milan_runtime_test_auth_start;
  klass->identify = milan_runtime_test_auth_start;
  klass->enroll = milan_runtime_test_enroll_start;
  klass->cancel = harness_cancel;
  device = g_object_new (FPI_TYPE_DEVICE_GOODIX53X5, NULL);
  g_type_class_unref (klass);
  g_assert_true (fp_device_open_sync (device, NULL, NULL));

  self = FPI_DEVICE_GOODIX53X5 (device);
  self->milan_sensor_subtype = GOODIX_MILAN_PRINT_SENSOR_TYPE;
  self->milan_generation = g_new0 (GoodixMilanGeneration, 1);
  self->milan_generation->generation_id = 1;
  self->last_milan_generation_id = 1;
  self->milan_generation->admitted = TRUE;
  self->milan_generation->setup_tx_on = g_new (guint16, PIXELS);
  generate_frames (self->milan_generation->setup_tx_on, live, 0);
  goodix_milan_preprocess_reset (&self->milan_generation->state);
  return device;
}

FpPrint *
make_print (FpDevice *device,
            GBytes   *template_bytes)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) data = goodix_milan_print_build_data (template_bytes,
                                                            &error);
  FpPrint *print = fp_print_new (device);

  g_assert_no_error (error);
  g_assert_nonnull (data);
  g_assert_true (g_variant_is_of_type (data, G_VARIANT_TYPE ("(uuuusay)")));
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  return g_object_ref_sink (print);
}

GBytes *
get_print_template (FpPrint *print)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GError) error = NULL;
  GBytes *template_bytes = NULL;

  g_object_get (print, "fpi-data", &data, NULL);
  g_assert_true (goodix_milan_print_parse_data (data, &template_bytes, &error));
  g_assert_no_error (error);
  return template_bytes;
}

void
match_report (FpDevice *device,
              FpPrint  *match,
              FpPrint  *print,
              gpointer  user_data,
              GError   *error)
{
  AsyncResult *result = user_data;

  (void) device;
  result->reports++;
  g_set_object (&result->reported_match, match);
  g_set_object (&result->reported_print, print);
  g_clear_error (&result->reported_error);
  if (error)
    result->reported_error = g_error_copy (error);
  if (result->cancel_on_report)
    g_cancellable_cancel (result->cancel_on_report);
}

void
verify_done (GObject      *source,
             GAsyncResult *async,
             gpointer      user_data)
{
  AsyncResult *result = user_data;

  result->success = fp_device_verify_finish_with_update (
    FP_DEVICE (source), async, &result->matched, NULL, &result->updated,
    &result->error);
  result->completions++;
  result->done = TRUE;
}

void
identify_done (GObject      *source,
               GAsyncResult *async,
               gpointer      user_data)
{
  AsyncResult *result = user_data;

  result->success = fp_device_identify_finish_with_update (
    FP_DEVICE (source), async, &result->match, NULL, &result->updated,
    &result->error);
  result->completions++;
  result->done = TRUE;
}

void
wait_done (AsyncResult *result)
{
  while (!result->done)
    g_main_context_iteration (NULL, TRUE);
}

void
wait_paused (void)
{
  while (!paused_ssm)
    g_main_context_iteration (NULL, TRUE);
}

void
wait_study (void)
{
  g_mutex_lock (&plan.mutex);
  while (!plan.study_entered)
    g_cond_wait (&plan.condition, &plan.mutex);
  g_mutex_unlock (&plan.mutex);
}

void
wait_cancelled (void)
{
  g_mutex_lock (&plan.mutex);
  while (!plan.cancel_called)
    {
      g_mutex_unlock (&plan.mutex);
      g_assert_true (g_main_context_iteration (NULL, FALSE));
      g_mutex_lock (&plan.mutex);
    }
  g_mutex_unlock (&plan.mutex);
}

void
release_study (void)
{
  g_mutex_lock (&plan.mutex);
  plan.release_study = TRUE;
  g_cond_broadcast (&plan.condition);
  g_mutex_unlock (&plan.mutex);
}

void
clear_result (AsyncResult *result)
{
  g_clear_object (&result->match);
  g_clear_object (&result->reported_match);
  g_clear_object (&result->reported_print);
  g_clear_object (&result->enrolled);
  g_clear_error (&result->reported_error);
  g_clear_error (&result->error);
  memset (result, 0, sizeof (*result));
}

void
close_device (FpDevice *device)
{
  g_assert_true (fp_device_close_sync (device, NULL, NULL));
}
