/*
 * Goodix 53x5 driver for libfprint — Verify/identify flow
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
#include "goodix53x5-auth.h"
#include "fpi-print.h"

#include <string.h>

static gboolean
goodix_match_scores_need_exhaustive_logging (void)
{
  return !g_log_writer_default_would_drop (G_LOG_LEVEL_DEBUG, G_LOG_DOMAIN);
}

static gboolean
goodix_gallery_has_single_username (GPtrArray *gallery)
{
  const gchar *username;

  if (gallery->len == 0)
    return FALSE;

  username = fp_print_get_username (g_ptr_array_index (gallery, 0));
  if (username == NULL || username[0] == '\0')
    return FALSE;

  for (guint i = 1; i < gallery->len; i++)
    {
      FpPrint *print = g_ptr_array_index (gallery, i);

      if (g_strcmp0 (username, fp_print_get_username (print)) != 0)
        return FALSE;
    }

  return TRUE;
}

/* Verify/Identify SSM */
typedef enum {
  GOODIX_VERIFY_REINIT = 0,
  GOODIX_VERIFY_REINIT_DONE,
  GOODIX_VERIFY_CAPTURE_REF,
  GOODIX_VERIFY_WAIT_FINGER,
  GOODIX_VERIFY_CAPTURE,
  GOODIX_VERIFY_MATCH,
  GOODIX_VERIFY_FINISH,
  GOODIX_VERIFY_NUM_STATES,
} GoodixVerifyState;

/* ========================================================================
 * Verify / Identify SSM (shared — checks current action for dispatch)
 * ======================================================================== */

void
goodix_clear_pending_result_report (FpiDeviceGoodix53x5 *self)
{
  self->pending_result_report = FALSE;
  self->pending_result_action = 0;
  self->pending_verify_result = 0;
  g_clear_object (&self->pending_identify_match);
  g_clear_error (&self->pending_result_error);
  g_clear_error (&self->pending_action_error);
}

static void
goodix_queue_action_error (FpiDeviceGoodix53x5 *self,
                           GError              *error)
{
  goodix_clear_pending_result_report (self);

  self->pending_action_error = error;
}

static void
goodix_queue_verify_report (FpiDeviceGoodix53x5 *self,
                            FpiMatchResult       result,
                            GError              *error)
{
  goodix_clear_pending_result_report (self);

  self->pending_result_report = TRUE;
  self->pending_result_action = FPI_DEVICE_ACTION_VERIFY;
  self->pending_verify_result = result;
  self->pending_result_error = error;
}

static void
goodix_queue_identify_report (FpiDeviceGoodix53x5 *self,
                              FpPrint             *match,
                              GError              *error)
{
  goodix_clear_pending_result_report (self);

  self->pending_result_report = TRUE;
  self->pending_result_action = FPI_DEVICE_ACTION_IDENTIFY;
  if (match != NULL)
    self->pending_identify_match = g_object_ref (match);
  self->pending_result_error = error;
}

static void
goodix_flush_pending_result_report (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (!self->pending_result_report)
    return;

  self->action_result_reported = TRUE;

  if (self->pending_result_action == FPI_DEVICE_ACTION_IDENTIFY)
    {
      g_autoptr(FpPrint) match = g_steal_pointer (&self->pending_identify_match);

      fpi_device_identify_report (dev, match, NULL,
                                  g_steal_pointer (&self->pending_result_error));
    }
  else
    {
      fpi_device_verify_report (dev, self->pending_verify_result, NULL,
                                g_steal_pointer (&self->pending_result_error));
    }

  self->pending_result_report = FALSE;
  self->pending_result_action = 0;
  self->pending_verify_result = 0;
}

static void
goodix_verify_ssm_handler (FpiSsm   *ssm,
                           FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_VERIFY_REINIT:
      if (!goodix_maybe_start_reinit_subsm (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;

    case GOODIX_VERIFY_REINIT_DONE:
      self->needs_reinit = FALSE;
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_VERIFY_CAPTURE_REF:
      goodix_scan_start_ref_capture_subsm (ssm, dev);
      break;

    case GOODIX_VERIFY_WAIT_FINGER:
      goodix_scan_start_finger_wait_subsm (ssm, dev);
      break;

    case GOODIX_VERIFY_CAPTURE:
      goodix_scan_start_capture_subsm (ssm, dev);
      break;

    case GOODIX_VERIFY_MATCH:
      {
        FpiDeviceAction action = fpi_device_get_current_action (dev);
        GoodixMatchInfo *probe_info;
        int keypoints;

        /* Extract SIFT features once for both identify and verify paths */
        probe_info = goodix_match_extract (self->captured_image);
        keypoints = goodix_match_keypoints_count (probe_info);

        if (keypoints < GOODIX_MIN_CAPTURE_KEYPOINTS)
          {
            if (action == FPI_DEVICE_ACTION_IDENTIFY)
              {
                goodix_queue_identify_report (self, NULL,
                                              fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
              }
            else
              {
                goodix_queue_verify_report (self, FPI_MATCH_ERROR,
                                            fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
              }

            self->verify_wait_finger_up = TRUE;
            goodix_match_free_info (probe_info);
            g_clear_pointer (&self->captured_image, g_free);
            fpi_ssm_next_state (ssm);
            return;
          }

        if (action == FPI_DEVICE_ACTION_IDENTIFY)
          {
            /* Identify: match against gallery of enrolled prints */
            GPtrArray *gallery = NULL;
            FpPrint *match = NULL;
            int best_score = 0;
            int best_match_score = 0;
            int valid_templates = 0;
            gboolean saw_unusable_template = FALSE;
            gboolean stop_after_match;

            fpi_device_get_identify_data (dev, &gallery);
            stop_after_match =
              !goodix_match_scores_need_exhaustive_logging () &&
              goodix_gallery_has_single_username (gallery);

            for (guint i = 0; i < gallery->len; i++)
              {
                FpPrint *tmpl = g_ptr_array_index (gallery, i);
                GVariant *tmpl_data = NULL;

                g_object_get (G_OBJECT (tmpl), "fpi-data", &tmpl_data, NULL);
                if (tmpl_data == NULL)
                  continue;

                GVariantIter iter;
                GVariant *child;
                int sample_idx = 0;
                int tmpl_best_score = 0;

                g_variant_iter_init (&iter, tmpl_data);
                while ((child = g_variant_iter_next_value (&iter)))
                  {
                    gsize len;
                    const guint8 *feature;

                    feature = g_variant_get_fixed_array (child, &len, 1);
                    if (len > 0)
                      {
                        int score;
                        GoodixSigfmTemplateStatus template_status;

                        template_status = goodix_match_serialized_feature (probe_info,
                                                                           feature,
                                                                           len,
                                                                           &score);
                        if (template_status != GOODIX_SIGFM_TEMPLATE_OK)
                          {
                            saw_unusable_template = TRUE;

                            fp_dbg ("identify: gallery[%u] sample %d invalid SIGFM template",
                                    i, sample_idx);
                            sample_idx++;
                            g_variant_unref (child);
                            continue;
                          }

                        valid_templates++;
                        fp_dbg ("identify: gallery[%u] sample %d sigfm_score %d",
                                i, sample_idx, score);

                        if (score > tmpl_best_score)
                          tmpl_best_score = score;

                        sample_idx++;

                        if (stop_after_match &&
                            tmpl_best_score >= GOODIX_SIGFM_BEST_MIN)
                          {
                            g_variant_unref (child);
                            break;
                          }
                      }
                    g_variant_unref (child);
                  }
                g_variant_unref (tmpl_data);

                if (tmpl_best_score > best_score)
                  best_score = tmpl_best_score;

                if (tmpl_best_score >= GOODIX_SIGFM_BEST_MIN &&
                    tmpl_best_score > best_match_score)
                  {
                    best_match_score = tmpl_best_score;
                    match = tmpl;
                  }

                if (stop_after_match && match != NULL)
                  break;
              }

            fp_dbg ("Identify best SIGFM score: %d (best_min: %d)",
                    best_score, GOODIX_SIGFM_BEST_MIN);

            if (valid_templates == 0 && saw_unusable_template)
              {
                goodix_queue_action_error (self,
                                           fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
                self->verify_wait_finger_up = FALSE;
              }
            else if (match != NULL)
              {
                goodix_queue_identify_report (self, match, NULL);
                self->verify_wait_finger_up = FALSE;
              }
            else
              {
                goodix_queue_identify_report (self, NULL, NULL);
                self->verify_wait_finger_up = TRUE;
              }
          }
        else
          {
            /* Verify: match against single enrolled print */
            FpPrint *print = NULL;
            GVariant *data = NULL;
            int best_score = 0;
            int sample_idx = 0;
            int valid_templates = 0;
            gboolean saw_unusable_template = FALSE;
            gboolean score_all_templates =
              goodix_match_scores_need_exhaustive_logging ();

            fpi_device_get_verify_data (dev, &print);
            g_object_get (G_OBJECT (print), "fpi-data", &data, NULL);

            if (data != NULL)
              {
                GVariantIter iter;
                GVariant *child;

                g_variant_iter_init (&iter, data);
                while ((child = g_variant_iter_next_value (&iter)))
                  {
                    gsize len;
                    const guint8 *feature;

                    feature = g_variant_get_fixed_array (child, &len, 1);
                    if (len > 0)
                      {
                        int score;
                        GoodixSigfmTemplateStatus template_status;

                        template_status = goodix_match_serialized_feature (probe_info,
                                                                           feature,
                                                                           len,
                                                                           &score);
                        if (template_status != GOODIX_SIGFM_TEMPLATE_OK)
                          {
                            saw_unusable_template = TRUE;

                            fp_dbg ("verify: sample %d invalid SIGFM template",
                                    sample_idx);
                            sample_idx++;
                            g_variant_unref (child);
                            continue;
                          }

                        valid_templates++;
                        fp_dbg ("verify: sample %d sigfm_score %d",
                                sample_idx, score);

                        if (score > best_score)
                          best_score = score;

                        sample_idx++;

                        /* Verify targets one known print, so later samples
                         * cannot change the result after the gate is met. */
                        if (!score_all_templates &&
                            best_score >= GOODIX_SIGFM_BEST_MIN)
                          {
                            g_variant_unref (child);
                            break;
                          }
                      }
                    g_variant_unref (child);
                  }
                g_variant_unref (data);
              }

            fp_dbg ("Verify best SIGFM score: %d (best_min: %d)",
                    best_score, GOODIX_SIGFM_BEST_MIN);

            if (valid_templates == 0 && saw_unusable_template)
              {
                goodix_queue_action_error (self,
                                           fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
                self->verify_wait_finger_up = FALSE;
              }
            else if (best_score >= GOODIX_SIGFM_BEST_MIN)
              {
                goodix_queue_verify_report (self, FPI_MATCH_SUCCESS, NULL);
                self->verify_wait_finger_up = FALSE;
              }
            else
              {
                goodix_queue_verify_report (self, FPI_MATCH_FAIL, NULL);
                self->verify_wait_finger_up = TRUE;
              }
          }

        goodix_match_free_info (probe_info);
        g_clear_pointer (&self->captured_image, g_free);

        if (self->verify_wait_finger_up)
          goodix_flush_pending_result_report (dev);

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_VERIFY_FINISH:
      if (self->verify_wait_finger_up)
        goodix_scan_start_finger_up_subsm (ssm, dev);
      else
        goodix_scan_start_deactivate_subsm (ssm, dev);
      break;
    }
}

static void
goodix_verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  self->task_ssm = NULL;
  self->blocking_ssm = NULL;
  g_clear_pointer (&self->reference_image, g_free);
  g_clear_pointer (&self->captured_image, g_free);

  if (error)
    {
      /* If cleanup fails after matching, the auth result still matters more
       * than post-result hardware cleanup. */
      gint failed_state = fpi_ssm_get_cur_state (ssm);

      if (failed_state >= GOODIX_VERIFY_FINISH &&
          !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fp_warn ("Post-match cleanup error (non-fatal): %s",
                   error->message);
          g_clear_error (&error);
        }
    }

  if (error == NULL)
    {
      if (self->pending_action_error != NULL)
        error = g_steal_pointer (&self->pending_action_error);
      else
        goodix_flush_pending_result_report (dev);
    }
  else
    goodix_clear_pending_result_report (self);

  self->action_result_reported = FALSE;
  self->verify_wait_finger_up = FALSE;

  /* Transport-level failures mean the USB claim/session is likely stale
   * (e.g. system slept while the device was claimed but idle, where the
   * driver suspend hook never runs). Reinitialize on the next attempt so
   * one failed auth self-heals instead of failing forever. A clean result
   * proves the device state is valid. */
  if (error == NULL)
    self->needs_reinit = FALSE;
  else if (goodix_error_indicates_stale_device (error))
    self->needs_reinit = TRUE;

  if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_complete (dev, error);
  else
    fpi_device_verify_complete (dev, error);
}

/**
 * Reset verify/identify action state and start the top-level auth SSM.
 * The SSM dispatches on the current libfprint action internally.
 */
void
goodix_auth_start (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  goodix_clear_pending_result_report (self);
  self->action_result_reported = FALSE;
  self->verify_wait_finger_up = FALSE;
  g_clear_pointer (&self->reference_image, g_free);
  g_clear_pointer (&self->captured_image, g_free);

  ssm = fpi_ssm_new (dev, goodix_verify_ssm_handler,
                      GOODIX_VERIFY_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_verify_ssm_done);
}
