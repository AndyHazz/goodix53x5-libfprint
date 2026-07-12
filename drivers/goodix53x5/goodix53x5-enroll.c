/*
 * Goodix 53x5 driver for libfprint — Enrollment flow
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
#include "goodix53x5-session.h"
#include "goodix53x5-scan.h"
#include "goodix53x5-match.h"
#include "goodix53x5-enroll.h"
#include "fpi-print.h"

#include <string.h>

#define GOODIX_ENROLL_RELEASE_SETTLE_MS 350

/* Enroll SSM */
typedef enum {
  GOODIX_ENROLL_REINIT = 0,
  GOODIX_ENROLL_REINIT_DONE,
  GOODIX_ENROLL_CAPTURE_REF,
  GOODIX_ENROLL_WAIT_FINGER,
  GOODIX_ENROLL_CAPTURE,
  GOODIX_ENROLL_PROCESS,
  GOODIX_ENROLL_WAIT_FINGER_UP,
  GOODIX_ENROLL_NEXT,
  GOODIX_ENROLL_NUM_STATES,
} GoodixEnrollState;

/* ========================================================================
 * Enroll SSM
 * ======================================================================== */

static void
goodix_enroll_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_ENROLL_REINIT:
      if (!goodix_maybe_start_reinit_subsm (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_ENROLL_REINIT_DONE:
      self->needs_reinit = FALSE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_ENROLL_CAPTURE_REF:
      if (self->cancel && g_cancellable_is_cancelled (self->cancel))
        {
          fpi_ssm_mark_failed (ssm,
                               g_error_new_literal (G_IO_ERROR,
                                                    G_IO_ERROR_CANCELLED,
                                                    "Enrollment cancelled"));
          return;
        }

      goodix_scan_start_ref_capture_subsm (ssm, dev);
      break;

    case GOODIX_ENROLL_WAIT_FINGER:
      goodix_scan_start_finger_wait_subsm (ssm, dev);
      break;

    case GOODIX_ENROLL_CAPTURE:
      goodix_scan_start_capture_subsm (ssm, dev);
      break;

    case GOODIX_ENROLL_PROCESS:
      {
        GoodixMatchInfo *info;
        GBytes *feature;
        int keypoints;

        /* Partial-contact captures make weak templates: the clipped
         * (non-contact) area holds no ridge data, and historical fluke
         * matches rode templates enrolled with poor coverage. Ask the user
         * to re-place the finger instead of storing such a stage. */
        if (self->captured_clipped_fraction > GOODIX_ENROLL_MAX_CLIPPED_FRACTION)
          {
            fp_dbg ("Enrollment stage rejected: %.1f%% of frame has no "
                    "finger contact (limit %.1f%%)",
                    self->captured_clipped_fraction * 100.0,
                    GOODIX_ENROLL_MAX_CLIPPED_FRACTION * 100.0);
            g_clear_pointer (&self->captured_image, g_free);
            fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                        fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
            fpi_ssm_next_state (ssm);
            return;
          }

        info = goodix_match_extract (self->captured_image);
        keypoints = goodix_match_keypoints_count (info);

        if (keypoints < GOODIX_MIN_CAPTURE_KEYPOINTS)
          {
            goodix_match_free_info (info);
            g_clear_pointer (&self->captured_image, g_free);
            fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                        fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
            fpi_ssm_next_state (ssm);
            return;
          }

        feature = goodix_match_serialize_template (info);
        goodix_match_free_info (info);
        if (feature == NULL)
          {
            g_clear_pointer (&self->captured_image, g_free);
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                           "Failed to serialize SIGFM features"));
            return;
          }

        g_ptr_array_add (self->enroll_features, feature);
        g_clear_pointer (&self->captured_image, g_free);
        self->enroll_stage++;

        fp_dbg ("Enrollment stage %d/%d complete",
                self->enroll_stage, GOODIX_ENROLL_SAMPLES);

        fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_ENROLL_WAIT_FINGER_UP:
      goodix_scan_start_finger_up_subsm (ssm, dev);
      break;

    case GOODIX_ENROLL_NEXT:
      if (self->enroll_stage < GOODIX_ENROLL_SAMPLES)
        {
          if (self->cancel && g_cancellable_is_cancelled (self->cancel))
            {
              fpi_ssm_mark_failed (ssm,
                                   g_error_new_literal (G_IO_ERROR,
                                                        G_IO_ERROR_CANCELLED,
                                                        "Enrollment cancelled"));
              return;
            }

          fp_dbg ("Waiting %dms for enrollment release to settle",
                  GOODIX_ENROLL_RELEASE_SETTLE_MS);
          fpi_ssm_jump_to_state_delayed (ssm, GOODIX_ENROLL_CAPTURE_REF,
                                         GOODIX_ENROLL_RELEASE_SETTLE_MS);
        }
      else
        fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
goodix_enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;
  self->blocking_ssm = NULL;

  if (error)
    {
      if (goodix_error_indicates_stale_device (error))
        self->needs_reinit = TRUE;

      g_clear_pointer (&self->enroll_features, g_ptr_array_unref);
      g_clear_pointer (&self->reference_image, g_free);
      g_clear_pointer (&self->captured_image, g_free);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  self->needs_reinit = FALSE;

  /* Build print from serialized enrollment features */
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);

  /* Build GVariant "aay" — array of byte arrays, one per enrollment sample.
   * There is no driver-private format magic/version here; templates enrolled
   * with the old TX-off p2 preprocessing must be re-enrolled for p3 scoring.
   */
  GVariantBuilder builder;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

  for (guint i = 0; i < self->enroll_features->len; i++)
    {
      GBytes *feature = g_ptr_array_index (self->enroll_features, i);
      gsize feature_len;
      const guint8 *feature_data = g_bytes_get_data (feature, &feature_len);

      g_variant_builder_add (&builder, "@ay",
                             g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                        feature_data,
                                                        feature_len,
                                                        1));
    }

  GVariant *data = g_variant_builder_end (&builder);

  g_object_set (G_OBJECT (print), "fpi-data", data, NULL);

  g_clear_pointer (&self->enroll_features, g_ptr_array_unref);

  fp_info ("Enrollment complete with %d samples", GOODIX_ENROLL_SAMPLES);

  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

/**
 * Reset enrollment action state and start the top-level enroll SSM.
 */
void
goodix_enroll_start (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  self->enroll_stage = 0;
  g_clear_pointer (&self->reference_image, g_free);
  g_clear_pointer (&self->captured_image, g_free);
  g_clear_pointer (&self->enroll_features, g_ptr_array_unref);
  self->enroll_features = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);

  ssm = fpi_ssm_new (dev, goodix_enroll_ssm_handler,
                      GOODIX_ENROLL_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_enroll_ssm_done);
}
