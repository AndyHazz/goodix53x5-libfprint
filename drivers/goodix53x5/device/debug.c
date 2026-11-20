/*
 * Goodix 53x5 driver for libfprint - opt-in diagnostic instrumentation
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef GOODIX53X5_DEBUG
#error "device/debug.c is only valid in a goodix53x5_debug build"
#endif

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/debug.h"
#include "milan/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib/gstdio.h>

#define GOODIX53X5_BUILD_ID_MARKER "goodix53x5-build-id-v1:"
#define GOODIX53X5_SOURCE_ID_MARKER "goodix53x5-source-id-v1:"

static const gchar goodix_debug_build_id_marker[] __attribute__((used)) =
  GOODIX53X5_BUILD_ID_MARKER GOODIX53X5_DEBUG_BUILD_ID;
static const gchar goodix_debug_source_id_marker[] __attribute__((used)) =
  GOODIX53X5_SOURCE_ID_MARKER GOODIX53X5_DEBUG_SOURCE_ID;

typedef enum
{
  GOODIX_DUMP_PROBES_NONE,
  GOODIX_DUMP_PROBES_FAILED,
  GOODIX_DUMP_PROBES_ALL,
} GoodixDumpProbesMode;

static const gchar *
goodix_debug_dump_dir (void)
{
  const gchar *dump_dir = g_getenv ("GOODIX53X5_DUMP_DIR");

  return dump_dir != NULL && dump_dir[0] != '\0' ? dump_dir : NULL;
}

gboolean
goodix_debug_dump_enabled (void)
{
  return goodix_debug_dump_dir () != NULL;
}

static gboolean
goodix_debug_ensure_dump_dir (const gchar *dump_dir)
{
  if (g_mkdir_with_parents (dump_dir, 0700) != 0)
    {
      fp_warn ("Could not create dump dir %s: %s", dump_dir,
               g_strerror (errno));
      return FALSE;
    }

  (void) g_chmod (dump_dir, 0700);
  return TRUE;
}

static gboolean
goodix_debug_write_dump (const gchar      *prefix,
                          guint32           crc,
                          const GByteArray *buf,
                          const gchar      *extension)
{
  const gchar *dump_dir = goodix_debug_dump_dir ();
  g_autofree gchar *path = NULL;
  gint fd = -1;
  gint64 stamp = g_get_real_time ();
  gsize written = 0;
  gboolean created = FALSE;
  gboolean published = TRUE;

  for (guint attempt = 0; attempt < 1000 && fd < 0; attempt++)
    {
      g_free (path);
      path = g_strdup_printf ("%s/%s-%" G_GINT64_FORMAT "-%08x.%s",
                              dump_dir, prefix, stamp + attempt, crc, extension);
      fd = g_open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd >= 0)
        created = TRUE;
      else if (errno != EEXIST)
        break;
    }
  while (fd >= 0 && written < buf->len)
    {
      ssize_t count = write (fd, buf->data + written, buf->len - written);

      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        {
          if (count == 0)
            errno = EIO;
          break;
        }
      written += count;
    }
  if (fd < 0 || written != buf->len || fsync (fd) != 0)
    published = FALSE;
  if (fd >= 0 && close (fd) != 0)
    published = FALSE;
  if (!published)
    {
      gint saved_errno = errno;

      if (created && path)
        g_unlink (path);
      fp_warn ("Failed to publish %s: %s", path ? path : prefix,
               g_strerror (saved_errno));
      return FALSE;
    }

  fp_dbg ("Dumped %s (%u bytes)", path, (unsigned) buf->len);
  return TRUE;
}

typedef struct
{
  gchar   *basename;
  guint64  bytes;
  gchar   *encoding;
  gchar    sha256[65];
} GoodixDebugArtifact;

typedef struct
{
  GoodixDebugArtifact *after_match;
  GoodixDebugArtifact *input;
} GoodixDebugGalleryArtifacts;

static void
goodix_debug_artifact_free (GoodixDebugArtifact *artifact)
{
  if (!artifact)
    return;
  g_free (artifact->basename);
  g_free (artifact->encoding);
  g_free (artifact);
}

static void
goodix_debug_gallery_artifacts_free (GoodixDebugGalleryArtifacts *artifacts)
{
  if (!artifacts)
    return;
  goodix_debug_artifact_free (artifacts->after_match);
  goodix_debug_artifact_free (artifacts->input);
  g_free (artifacts);
}

static gboolean
goodix_debug_env_enabled (const gchar *name)
{
  const gchar *value = g_getenv (name);

  return value != NULL && value[0] != '\0' && g_strcmp0 (value, "0") != 0;
}

static gboolean
goodix_debug_valid_sha256 (const gchar *value)
{
  if (!value || strlen (value) != 64)
    return FALSE;
  for (guint i = 0; i < 64; i++)
    if (!g_ascii_isdigit (value[i]) &&
        !(value[i] >= 'a' && value[i] <= 'f'))
      return FALSE;
  return TRUE;
}

static GBytes *
goodix_debug_raw12_le_bytes (const guint16 *image)
{
  guint8 *data;

  if (!image)
    return NULL;
  data = g_malloc (GOODIX_SENSOR_PIXELS * 2);
  for (gsize i = 0; i < GOODIX_SENSOR_PIXELS; i++)
    {
      const guint16 value = image[i] & 0x0fff;

      data[i * 2] = value & 0xff;
      data[i * 2 + 1] = value >> 8;
    }
  return g_bytes_new_take (data, GOODIX_SENSOR_PIXELS * 2);
}

static GoodixDebugArtifact *
goodix_debug_publish_artifact (const gchar *prefix,
                               GBytes      *source,
                               const gchar *encoding)
{
  const gchar *dump_dir = goodix_debug_dump_dir ();
  g_autofree gchar *path = NULL;
  g_autofree gchar *basename = NULL;
  g_autofree gchar *sha256 = NULL;
  gconstpointer data;
  gsize size;
  gint fd = -1;
  gint64 stamp = g_get_real_time ();
  gsize written = 0;
  gboolean created = FALSE;
  gboolean published = TRUE;

  if (!source || !dump_dir)
    return NULL;
  data = g_bytes_get_data (source, &size);
  sha256 = g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, size);
  for (guint attempt = 0; attempt < 1000 && fd < 0; attempt++)
    {
      g_free (basename);
      g_free (path);
      basename = g_strdup_printf (
        "%s-%" G_GINT64_FORMAT "-%08x.bin", prefix, stamp + attempt,
        goodix_crypto_crc32_mpeg2 (data, size));
      path = g_build_filename (dump_dir, basename, NULL);
      fd = g_open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd >= 0)
        created = TRUE;
      else if (errno != EEXIST)
        break;
    }
  while (fd >= 0 && written < size)
    {
      ssize_t count = write (fd, (const guint8 *) data + written,
                             size - written);

      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        {
          if (count == 0)
            errno = EIO;
          break;
        }
      written += count;
    }
  if (fd < 0 || written != size || fsync (fd) != 0)
    published = FALSE;
  if (fd >= 0 && close (fd) != 0)
    published = FALSE;
  if (!published)
    {
      gint saved_errno = errno;

      if (created && path)
        g_unlink (path);
      fp_warn ("Failed to publish runtime artifact %s: %s",
               path ? path : prefix, g_strerror (saved_errno));
      return NULL;
    }

  GoodixDebugArtifact *artifact = g_new0 (GoodixDebugArtifact, 1);

  artifact->basename = g_steal_pointer (&basename);
  artifact->bytes = size;
  artifact->encoding = g_strdup (encoding);
  g_strlcpy (artifact->sha256, sha256, sizeof (artifact->sha256));
  return artifact;
}

static void
goodix_debug_json_string (GString     *json,
                          const gchar *value)
{
  const gchar *cursor = value ? value : "";

  g_string_append_c (json, '"');
  while (*cursor)
    {
      gunichar character = g_utf8_get_char_validated (cursor, -1);

      if (character == (gunichar) -1 || character == (gunichar) -2)
        {
          g_string_append (json, "\\ufffd");
          cursor++;
          continue;
        }
      switch (character)
        {
        case '"': g_string_append (json, "\\\""); break;
        case '\\': g_string_append (json, "\\\\"); break;
        case '\b': g_string_append (json, "\\b"); break;
        case '\f': g_string_append (json, "\\f"); break;
        case '\n': g_string_append (json, "\\n"); break;
        case '\r': g_string_append (json, "\\r"); break;
        case '\t': g_string_append (json, "\\t"); break;
        default:
          if (character < 0x20 || character > 0x7e)
            {
              if (character <= 0xffff)
                g_string_append_printf (json, "\\u%04x", character);
              else
                {
                  guint32 adjusted = character - 0x10000;

                  g_string_append_printf (json, "\\u%04x\\u%04x",
                                          0xd800 + (adjusted >> 10),
                                          0xdc00 + (adjusted & 0x3ff));
                }
            }
          else
            g_string_append_c (json, character);
          break;
        }
      cursor = g_utf8_next_char (cursor);
    }
  g_string_append_c (json, '"');
}

static void
goodix_debug_json_artifact (GString                   *json,
                            const GoodixDebugArtifact *artifact)
{
  if (!artifact)
    {
      g_string_append (json, "null");
      return;
    }
  g_string_append (json, "{\"basename\":");
  goodix_debug_json_string (json, artifact->basename);
  g_string_append_printf (json, ",\"bytes_u64\":%" G_GUINT64_FORMAT
                          ",\"encoding\":", artifact->bytes);
  goodix_debug_json_string (json, artifact->encoding);
  g_string_append (json, ",\"sha256\":");
  goodix_debug_json_string (json, artifact->sha256);
  g_string_append_c (json, '}');
}

static void
goodix_debug_json_error (GString      *json,
                         const GError *error)
{
  if (!error)
    {
      g_string_append (json, "null");
      return;
    }
  g_string_append_printf (json, "{\"code_i32\":%d,\"domain_u32\":%u,"
                          "\"message\":", error->code, error->domain);
  goodix_debug_json_string (json, error->message);
  g_string_append_c (json, '}');
}

void
goodix_debug_dump_image (const gchar  *prefix,
                         const guint8 *img,
                         gsize         len)
{
  const gchar *dump_dir = goodix_debug_dump_dir ();
  g_autofree gchar *header = NULL;
  g_autoptr(GByteArray) buf = NULL;

  if (dump_dir == NULL || img == NULL || len != GOODIX_SENSOR_PIXELS ||
      !goodix_debug_ensure_dump_dir (dump_dir))
    return;

  header = g_strdup_printf ("P5\n%d %d\n255\n", GOODIX_SENSOR_WIDTH,
                            GOODIX_SENSOR_HEIGHT);
  buf = g_byte_array_new ();
  g_byte_array_append (buf, (const guint8 *) header, strlen (header));
  g_byte_array_append (buf, img, len);
  goodix_debug_write_dump (
    prefix, goodix_crypto_crc32_mpeg2 (img, len), buf, "pgm");
}

void
goodix_debug_dump_raw12 (const gchar   *prefix,
                         const guint16 *img,
                         gsize          len)
{
  const gchar *dump_dir = goodix_debug_dump_dir ();
  g_autofree gchar *header = NULL;
  g_autoptr(GByteArray) buf = NULL;
  gsize header_len;

  if (dump_dir == NULL || img == NULL || len != GOODIX_SENSOR_PIXELS ||
      !goodix_debug_ensure_dump_dir (dump_dir))
    return;

  header = g_strdup_printf ("P5\n%d %d\n4095\n", GOODIX_SENSOR_WIDTH,
                            GOODIX_SENSOR_HEIGHT);
  header_len = strlen (header);
  buf = g_byte_array_new ();
  g_byte_array_append (buf, (const guint8 *) header, header_len);
  for (gsize i = 0; i < len; i++)
    {
      guint16 value = img[i] & 0x0fff;
      guint8 bytes[2] = { value >> 8, value & 0xff };

      g_byte_array_append (buf, bytes, sizeof (bytes));
    }
  goodix_debug_write_dump (
    prefix,
    goodix_crypto_crc32_mpeg2 (buf->data + header_len, len * 2), buf, "pgm");
}

void
goodix_debug_dump_pair (const gchar   *prefix,
                        const guint16 *raw_img,
                        const guint8  *img)
{
  g_autofree gchar *raw_prefix = NULL;

  if (!goodix_debug_dump_enabled ())
    return;
  raw_prefix = g_strdup_printf ("raw12-%s", prefix);
  goodix_debug_dump_raw12 (raw_prefix, raw_img, GOODIX_SENSOR_PIXELS);
  goodix_debug_dump_image (prefix, img, GOODIX_SENSOR_PIXELS);
}

static GoodixDumpProbesMode
goodix_debug_dump_probes_mode (void)
{
  const gchar *value = g_getenv ("GOODIX53X5_DUMP_PROBES");

  if (value == NULL || value[0] == '\0' ||
      g_ascii_strcasecmp (value, "failed") == 0)
    return GOODIX_DUMP_PROBES_FAILED;
  if (g_ascii_strcasecmp (value, "all") == 0)
    return GOODIX_DUMP_PROBES_ALL;
  if (g_ascii_strcasecmp (value, "none") == 0)
    return GOODIX_DUMP_PROBES_NONE;
  fp_warn ("Ignoring invalid GOODIX53X5_DUMP_PROBES=%s (using failed)", value);
  return GOODIX_DUMP_PROBES_FAILED;
}

void
goodix_debug_dump_probe (FpiDeviceAction action,
                         const gchar    *outcome,
                         const guint16  *raw_img,
                         const guint8   *img)
{
  GoodixDumpProbesMode mode;
  gboolean should_dump;
  g_autofree gchar *prefix = NULL;

  if (!goodix_debug_dump_enabled ())
    return;
  mode = goodix_debug_dump_probes_mode ();
  should_dump = mode == GOODIX_DUMP_PROBES_ALL ||
                (mode == GOODIX_DUMP_PROBES_FAILED &&
                 (g_strcmp0 (outcome, "fail") == 0 ||
                  g_strcmp0 (outcome, "miss") == 0 ||
                  g_strcmp0 (outcome, "weak") == 0));
  if (!should_dump)
    return;
  prefix = g_strdup_printf ("%s-%s",
                            action == FPI_DEVICE_ACTION_IDENTIFY
                              ? "identify" : "verify",
                            outcome);
  goodix_debug_dump_pair (prefix, raw_img, img);
}

gboolean
goodix_debug_timing_enabled (void)
{
  const gchar *value = g_getenv ("GOODIX53X5_LOG_TIMING");

  return value != NULL && value[0] != '\0' && g_strcmp0 (value, "0") != 0;
}

static const gchar *
goodix_debug_action_name (FpiDeviceAction action)
{
  switch (action)
    {
    case FPI_DEVICE_ACTION_OPEN: return "open";
    case FPI_DEVICE_ACTION_CLOSE: return "close";
    case FPI_DEVICE_ACTION_ENROLL: return "enroll";
    case FPI_DEVICE_ACTION_VERIFY: return "verify";
    case FPI_DEVICE_ACTION_IDENTIFY: return "identify";
    case FPI_DEVICE_ACTION_NONE: return "none";
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_CAPTURE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
      return "other";
    }
  g_assert_not_reached ();
}

static const gchar *
goodix_debug_purpose_name (GoodixMilanPreprocessPurpose purpose)
{
  static const gchar * const names[] = { "authentication", "enrollment" };

  return (guint) purpose < G_N_ELEMENTS (names) ? names[purpose] : "unknown";
}

const gchar *
goodix_debug_runtime_status_name (guint status)
{
  static const gchar * const names[] = {
    "match", "no-match", "retry", "invalid-data", "cancelled"
  };

  return status < G_N_ELEMENTS (names) ? names[status] : "unknown";
}

const gchar *
goodix_debug_study_action_name (guint action)
{
  static const gchar * const names[] = {
    "none", "append", "replace-no-relation", "geometric", "replace", "queued"
  };

  return action < G_N_ELEMENTS (names) ? names[action] : "unknown";
}

gchar *
goodix_debug_format_winner (guint index, gsize position)
{
  if (index == G_MAXUINT && position == G_MAXSIZE)
    return g_strdup ("none");
  if (index == G_MAXUINT || position == G_MAXSIZE)
    return g_strdup_printf ("invalid(index=%u,position=%" G_GSIZE_FORMAT ")",
                            index, position);
  return g_strdup_printf ("gallery(index=%u,position=%" G_GSIZE_FORMAT ")",
                          index, position);
}

gchar *
goodix_debug_format_template_features (const GoodixMilanRuntimeOutput *output)
{
  GoodixMilanRuntimeGalleryResult *winner;
  guint before;
  guint after;
  guint maximum;

  if (output->winner_position >= output->gallery_results->len)
    return g_strdup ("none");
  winner = g_ptr_array_index (output->gallery_results, output->winner_position);
  before = winner->template_info.feature_count;
  after = output->final_candidate
            ? output->final_candidate_info.feature_count
            : before;
  maximum = output->final_candidate
              ? output->final_candidate_info.maximum_features
              : winner->template_info.maximum_features;
  if (!output->final_candidate)
    return g_strdup_printf ("%u/%u", before, maximum);
  return g_strdup_printf ("%u->%u/%u", before, after, maximum);
}

static const gchar *
goodix_debug_checkpoint_name (GoodixMilanRuntimeCheckpoint checkpoint)
{
  static const gchar * const names[] = {
    "none", "before-preprocess", "after-preprocess", "after-extract",
    "before-gallery", "after-gallery", "before-study", "after-study"
  };

  return (guint) checkpoint < G_N_ELEMENTS (names) ? names[checkpoint] : "unknown";
}

static gchar *
goodix_debug_format_cancellation (const GoodixMilanRuntimeOutput *output)
{
  const gchar *checkpoint = goodix_debug_checkpoint_name (
    output->cancellation.cancelled_at);

  if (output->cancellation.cancelled_at == GOODIX_MILAN_RUNTIME_CHECKPOINT_NONE)
    return g_strdup ("none");
  if (output->cancellation.cancelled_gallery_position == G_MAXSIZE)
    return g_strdup (checkpoint);
  return g_strdup_printf ("%s(gallery-position=%" G_GSIZE_FORMAT ")",
                          checkpoint,
                          output->cancellation.cancelled_gallery_position);
}

static gchar *
goodix_debug_format_error (const GError *error)
{
  const gchar *domain;

  if (!error)
    return g_strdup ("none");
  domain = g_quark_to_string (error->domain);
  return g_strdup_printf ("%s(%d):%s", domain ? domain : "unknown-domain",
                          error->code, error->message);
}

void
goodix_debug_timing_log (FpDevice    *dev,
                         const gchar *scope,
                         const gchar *event,
                         gint64       duration_us,
                         const gchar *detail)
{
  if (!goodix_debug_timing_enabled ())
    return;
  fp_info ("timing[%s] %s %s: %.2f ms%s%s",
           goodix_debug_action_name (fpi_device_get_current_action (dev)),
           scope, event, duration_us / 1000.0,
           detail != NULL ? " " : "", detail != NULL ? detail : "");
}

static void
goodix_debug_timing_reset_phases (GoodixDebugTiming *timing)
{
  timing->open_started_us = 0;
  timing->open_phase_started_us = 0;
  timing->open_last_state_name = NULL;
  timing->finger_wait_started_us = 0;
  timing->finger_wait_phase_started_us = 0;
  timing->finger_wait_false_event_retries = 0;
  timing->finger_up_started_us = 0;
  timing->finger_up_phase_started_us = 0;
  timing->ref_capture_started_us = 0;
  timing->ref_capture_phase_started_us = 0;
  timing->capture_started_us = 0;
  timing->capture_phase_started_us = 0;
  timing->deactivate_started_us = 0;
  timing->deactivate_phase_started_us = 0;
}

void
goodix_debug_timing_action_start (FpiDeviceGoodix53x5 *self,
                                  FpDevice            *dev,
                                  const gchar         *detail)
{
  if (!goodix_debug_timing_enabled ())
    return;
  self->debug_timing.action_started_us = g_get_monotonic_time ();
  goodix_debug_timing_reset_phases (&self->debug_timing);
  goodix_debug_timing_log (dev, "action", "start", 0, detail);
}

void
goodix_debug_timing_action_done (FpiDeviceGoodix53x5 *self,
                                 FpDevice            *dev,
                                 const gchar         *detail)
{
  if (!goodix_debug_timing_enabled ())
    return;
  if (self->debug_timing.action_started_us != 0)
    goodix_debug_timing_log (
      dev, "action", "done",
      g_get_monotonic_time () - self->debug_timing.action_started_us, detail);
  self->debug_timing.action_started_us = 0;
  goodix_debug_timing_reset_phases (&self->debug_timing);
}

void
goodix_debug_timing_open_state (FpiDeviceGoodix53x5 *self,
                                FpDevice            *dev,
                                const gchar         *state_name,
                                gint64               now_us)
{
  GoodixDebugTiming *timing = &self->debug_timing;

  if (!goodix_debug_timing_enabled ())
    return;
  if (timing->open_started_us == 0)
    {
      timing->open_started_us = now_us;
      timing->open_phase_started_us = now_us;
      goodix_debug_timing_log (dev, "open", "start", 0, NULL);
    }
  else
    {
      goodix_debug_timing_log (
        dev, "open",
        timing->open_last_state_name != NULL ? timing->open_last_state_name
                                             : "unknown",
        now_us - timing->open_phase_started_us, NULL);
      timing->open_phase_started_us = now_us;
    }
  timing->open_last_state_name = state_name;
}

void
goodix_debug_timing_open_done (FpiDeviceGoodix53x5 *self,
                               FpDevice            *dev,
                               const gchar         *detail)
{
  GoodixDebugTiming *timing = &self->debug_timing;
  gint64 now_us;

  if (!goodix_debug_timing_enabled () || timing->open_started_us == 0)
    return;
  now_us = g_get_monotonic_time ();
  goodix_debug_timing_log (
    dev, "open",
    timing->open_last_state_name != NULL ? timing->open_last_state_name
                                         : "unknown",
    now_us - timing->open_phase_started_us, NULL);
  goodix_debug_timing_log (dev, "open", "done",
                           now_us - timing->open_started_us, detail);
  timing->open_started_us = 0;
  timing->open_phase_started_us = 0;
  timing->open_last_state_name = NULL;
}

void
goodix_debug_capture_runtime_metadata (GoodixDebugRuntimeMetadata *metadata,
                                        FpiDeviceAction             action,
                                        const guint16              *setup_tx_on,
                                        const guint16              *live_raw,
                                        guint64 generation_use_index,
                                        gboolean setup_initialized,
                                        gboolean setup_refresh_pending,
                                        gboolean setup_not_ready)
{
  g_return_if_fail (metadata != NULL);
  g_return_if_fail (setup_tx_on != NULL);
  g_return_if_fail (live_raw != NULL);

  goodix_debug_clear_runtime_metadata (metadata);
  metadata->action = action;
  metadata->generation_use_index = generation_use_index;
  metadata->setup_initialized = setup_initialized;
  metadata->setup_refresh_pending = setup_refresh_pending;
  metadata->setup_not_ready = setup_not_ready;
  if (!goodix_debug_env_enabled ("GOODIX53X5_DUMP_TEMPLATES") ||
      !goodix_debug_dump_enabled ())
    return;
  metadata->setup_tx_on = goodix_debug_raw12_le_bytes (setup_tx_on);
  metadata->live_raw = goodix_debug_raw12_le_bytes (live_raw);
}

void
goodix_debug_clear_runtime_metadata (GoodixDebugRuntimeMetadata *metadata)
{
  if (!metadata)
    return;
  g_clear_pointer (&metadata->setup_tx_on, g_bytes_unref);
  g_clear_pointer (&metadata->live_raw, g_bytes_unref);
}

void
goodix_debug_log_runtime_result (FpDevice                         *dev,
                                  guint                             stage,
                                  const GoodixDebugRuntimeMetadata *metadata,
                                  const GoodixMilanRuntimeOutput   *output,
                                  gboolean driver_cancellation_observed)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  const gchar *dump_dir = goodix_debug_dump_dir ();
  g_autofree gchar *cancellation = NULL;
  g_autofree gchar *common_prefix = NULL;
  g_autofree gchar *learning_error = NULL;
  g_autofree gchar *operation_id = NULL;
  g_autofree gchar *prefix = NULL;
  g_autofree gchar *runtime_error = NULL;
  g_autofree gchar *template_features = NULL;
  g_autofree gchar *winner = NULL;
  g_autoptr(GPtrArray) gallery_artifacts = NULL;
  g_autoptr(GString) record = NULL;
  g_autoptr(GByteArray) bytes = NULL;
  g_autoptr(GBytes) final_candidate = NULL;
  GoodixDebugArtifact *final_candidate_artifact = NULL;
  GoodixDebugArtifact *live_raw_artifact = NULL;
  GoodixDebugArtifact *native_probe_artifact = NULL;
  GoodixDebugArtifact *processed_image_artifact = NULL;
  GoodixDebugArtifact *setup_tx_on_artifact = NULL;
  const gchar *action_name;
  gchar *record_data;
  gsize record_len;
  guint64 chronology;
  gboolean runtime_cancelled;

  if (metadata == NULL || output == NULL)
    return;
  action_name = goodix_debug_action_name (metadata->action);
  winner = goodix_debug_format_winner (output->winner_index,
                                       output->winner_position);
  template_features = goodix_debug_format_template_features (output);
  cancellation = goodix_debug_format_cancellation (output);
  runtime_error = goodix_debug_format_error (output->error);
  learning_error = goodix_debug_format_error (output->learning_error);
  if (goodix_debug_env_enabled ("GOODIX53X5_LOG_DIAGNOSTICS"))
    fp_info ("diagnostic[%s] epoch=%" G_GUINT64_FORMAT
             " generation=%" G_GUINT64_FORMAT
             " stage=%u processing=%s(%u) status=%s(%u) quality=%d coverage=%d "
             "probe_records=%u partitions=%u/%u score=%d winner=%s"
             " study=%s(%u) attempted=%s completed=%s "
             "study_gates=finalize:%s/action:%s/queue:%s "
             "template_features=%s "
             "gallery=%u-valid/%u-invalid/%u-evaluated "
             "capture_health=present:%s/enroll:%s admission=0x%08x/detail:%u "
             "cancel=%s error=%s learning_error=%s",
             action_name,
             output->action_epoch, output->generation_id, stage,
             goodix_debug_purpose_name (output->purpose),
             (guint) output->purpose,
             goodix_debug_runtime_status_name (output->status),
             (guint) output->status,
             output->quality, output->coverage,
             output->probe_record_count, output->probe_partition0_count,
             output->probe_partition1_count, output->score, winner,
             goodix_debug_study_action_name (output->study_action),
             (guint) output->study_action,
             output->study_attempted ? "yes" : "no",
             output->study_completed ? "yes" : "no",
             output->match_result.study_control.study_finalization_gate
               ? "yes" : "no",
             output->match_result.study_control.study_action_gate
               ? "yes" : "no",
             output->match_result.study_control.queue_candidate_eligible
               ? "yes" : "no",
             template_features,
             output->valid_gallery_count,
             output->invalid_gallery_count, output->evaluated_gallery_count,
             output->capture_health_present ? "yes" : "no",
             output->capture_enroll_allowed ? "yes" : "no",
             output->admission_status, output->admission_detail,
             cancellation, runtime_error, learning_error);

  if (!goodix_debug_env_enabled ("GOODIX53X5_DUMP_TEMPLATES") || !dump_dir)
    return;
  if (!goodix_debug_valid_sha256 (
        goodix_debug_build_id_marker + sizeof (GOODIX53X5_BUILD_ID_MARKER) - 1) ||
      !goodix_debug_valid_sha256 (
        goodix_debug_source_id_marker + sizeof (GOODIX53X5_SOURCE_ID_MARKER) - 1))
    {
      fp_warn ("Refusing runtime v3 emission with invalid build provenance");
      return;
    }
  if (!metadata->setup_tx_on || !metadata->live_raw ||
      !goodix_debug_ensure_dump_dir (dump_dir))
    return;
  if (self->debug_chronology == G_MAXUINT64)
    {
      fp_warn ("Runtime debug chronology exhausted");
      return;
    }
  chronology = self->debug_chronology + 1;
  common_prefix = g_strdup_printf (
    "runtime-artifact-%s-%s-%" G_GUINT64_FORMAT "-%" G_GUINT64_FORMAT
    "-%u-%" G_GUINT64_FORMAT "-setup-i%u-r%u-n%u",
    self->debug_capture_session_id, action_name, output->action_epoch,
    output->generation_id, stage, chronology,
    metadata->setup_initialized, metadata->setup_refresh_pending,
    metadata->setup_not_ready);
  operation_id = g_strdup_printf ("%s/%s/%" G_GUINT64_FORMAT,
                                  self->debug_capture_session_id, action_name,
                                  output->action_epoch);

#define PUBLISH_ARTIFACT(role, source, encoding) G_STMT_START { \
  g_clear_pointer (&prefix, g_free); \
  prefix = g_strdup_printf ("%s-%s", common_prefix, #role); \
  role##_artifact = goodix_debug_publish_artifact (prefix, source, encoding); \
} G_STMT_END
  PUBLISH_ARTIFACT (setup_tx_on, metadata->setup_tx_on,
                    "raw-u16le-12-108x88");
  PUBLISH_ARTIFACT (live_raw, metadata->live_raw, "raw-u16le-12-108x88");
  PUBLISH_ARTIFACT (processed_image, output->processed_image,
                    "raw-u8-108x88");
  PUBLISH_ARTIFACT (native_probe, output->probe_template,
                    "goodix-milan-native-template");
  if (output->final_candidate)
    final_candidate = g_bytes_ref (output->final_candidate);
  PUBLISH_ARTIFACT (final_candidate, final_candidate,
                    "goodix-milan-native-template");
#undef PUBLISH_ARTIFACT

  g_clear_pointer (&prefix, g_free);
  gallery_artifacts = g_ptr_array_new_with_free_func (
    (GDestroyNotify) goodix_debug_gallery_artifacts_free);
  for (guint i = 0; i < output->gallery_results->len; i++)
    {
      GoodixMilanRuntimeGalleryResult *result =
        g_ptr_array_index (output->gallery_results, i);
      GoodixDebugGalleryArtifacts *artifacts = g_new0 (
        GoodixDebugGalleryArtifacts, 1);

      prefix = g_strdup_printf ("%s-gallery-%" G_GSIZE_FORMAT "-input",
                                common_prefix, result->gallery_position);
      artifacts->input = goodix_debug_publish_artifact (
        prefix, result->input_template, "goodix-milan-native-template");
      g_clear_pointer (&prefix, g_free);
      prefix = g_strdup_printf ("%s-gallery-%" G_GSIZE_FORMAT "-after-match",
                                common_prefix, result->gallery_position);
      artifacts->after_match = goodix_debug_publish_artifact (
        prefix, result->after_match_template, "goodix-milan-native-template");
      g_ptr_array_add (gallery_artifacts, artifacts);
      g_clear_pointer (&prefix, g_free);
    }

  runtime_cancelled = output->status == GOODIX_MILAN_RUNTIME_CANCELLED ||
                      output->cancellation.cancelled_at !=
                        GOODIX_MILAN_RUNTIME_CHECKPOINT_NONE;
  record = g_string_new (NULL);
  g_string_append (record, "{\"action\":");
  goodix_debug_json_string (record, action_name);
  g_string_append_printf (record,
                          ",\"action_epoch_u64\":%" G_GUINT64_FORMAT
                          ",\"anti_fake_mode\":1,\"artifacts\":{"
                          "\"final_candidate\":", output->action_epoch);
  goodix_debug_json_artifact (record, final_candidate_artifact);
  g_string_append (record, ",\"gallery\":[");
  for (guint i = 0; i < gallery_artifacts->len; i++)
    {
      GoodixDebugGalleryArtifacts *artifacts =
        g_ptr_array_index (gallery_artifacts, i);
      GoodixMilanRuntimeGalleryResult *result =
        g_ptr_array_index (output->gallery_results, i);

      if (i)
        g_string_append_c (record, ',');
      g_string_append (record, "{\"after_match\":");
      goodix_debug_json_artifact (record, artifacts->after_match);
      g_string_append_printf (record,
                              ",\"gallery_position_u64\":%"
                              G_GSIZE_FORMAT ",\"input\":",
                              result->gallery_position);
      goodix_debug_json_artifact (record, artifacts->input);
      g_string_append_c (record, '}');
    }
  g_string_append (record, "],\"live_raw\":");
  goodix_debug_json_artifact (record, live_raw_artifact);
  g_string_append (record, ",\"native_probe\":");
  goodix_debug_json_artifact (record, native_probe_artifact);
  g_string_append (record, ",\"processed_image\":");
  goodix_debug_json_artifact (record, processed_image_artifact);
  g_string_append (record, ",\"setup_tx_on\":");
  goodix_debug_json_artifact (record, setup_tx_on_artifact);
  g_string_append (record, "},\"boundary_policy\":\"canonical-zero-v1\","
                           "\"build_id\":\"");
  g_string_append (record,
                   goodix_debug_build_id_marker +
                     sizeof (GOODIX53X5_BUILD_ID_MARKER) - 1);
  g_string_append (record, "\",\"cancellation\":{\"driver_observed\":");
  g_string_append (record, driver_cancellation_observed ? "true" : "false");
  g_string_append (record, ",\"runtime_checkpoint_u32\":");
  if (runtime_cancelled)
    g_string_append_printf (record, "%u",
                            (guint) output->cancellation.cancelled_at);
  else
    g_string_append (record, "null");
  g_string_append (record, ",\"runtime_gallery_position_u64\":");
  if (runtime_cancelled &&
      output->cancellation.cancelled_gallery_position != G_MAXSIZE)
    g_string_append_printf (
      record, "%" G_GSIZE_FORMAT,
      output->cancellation.cancelled_gallery_position);
  else
    g_string_append (record, "null");
  g_string_append (record, ",\"runtime_observed\":");
  g_string_append (record, runtime_cancelled ? "true" : "false");
  g_string_append_printf (
    record,
    "},\"capture_session_id\":\"%s\",\"chronology_u64\":%"
    G_GUINT64_FORMAT ",\"coverage_i32\":",
    self->debug_capture_session_id, chronology);
  if (output->preprocess_attempted)
    g_string_append_printf (record, "%d", output->coverage);
  else
    g_string_append (record, "null");
  g_string_append_printf (
    record,
    ",\"dac_high_u16\":%u,\"dac_low_u16\":%u,\"errors\":{"
    "\"learning\":", output->dac_high, output->dac_low);
  goodix_debug_json_error (record, output->learning_error);
  g_string_append (record, ",\"runtime\":");
  goodix_debug_json_error (record, output->error);
  g_string_append_printf (
    record,
    "},\"evaluated_gallery_u32\":%u,\"gallery\":[",
    output->evaluated_gallery_count);
  for (guint i = 0; i < output->gallery_results->len; i++)
    {
      GoodixMilanRuntimeGalleryResult *result =
        g_ptr_array_index (output->gallery_results, i);

      if (i != 0)
        g_string_append_c (record, ',');
      g_string_append (record, "{\"accepted\":");
      g_string_append (record, result->evaluated
                                 ? (result->accepted ? "true" : "false")
                                 : "null");
      g_string_append (record, ",\"after_match_sha256\":");
      if (result->after_match_sha256[0])
        goodix_debug_json_string (record, result->after_match_sha256);
      else
        g_string_append (record, "null");
      g_string_append_printf (
        record,
        ",\"evaluated\":%s,\"gallery_index_u32\":%u,"
        "\"gallery_position_u64\":%" G_GSIZE_FORMAT
        ",\"input_template_sha256\":",
        result->evaluated ? "true" : "false", result->gallery_index,
        result->gallery_position);
      if (result->input_template_sha256[0])
        goodix_debug_json_string (record, result->input_template_sha256);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"lifecycle_update_feature_mask_u64\":");
      if (result->evaluated)
        g_string_append_printf (
          record, "%" G_GUINT64_FORMAT,
          result->match_result.lifecycle_update_feature_mask);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"matched_feature_u64\":");
      if (result->evaluated)
        g_string_append_printf (record, "%" G_GSIZE_FORMAT,
                                result->match_result.matched_feature_index);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_counter_after_study_u32\":");
      if (result->queue_after_study_observed)
        g_string_append_printf (record, "%u",
                                result->queue_counter_after_study);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_counter_before_match_u32\":");
      if (result->queue_before_match_observed)
        g_string_append_printf (record, "%u",
                                result->queue_counter_before_match);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_eligible_i32\":");
      if (result->evaluated)
        g_string_append_printf (
          record, "%d",
          result->match_result.study_control.queue_candidate_eligible);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_occupied_after_match_u64\":");
      if (result->queue_after_match_observed)
        g_string_append_printf (record, "%" G_GSIZE_FORMAT,
                                result->queue_occupied_after_match);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_occupied_after_study_u64\":");
      if (result->queue_after_study_observed)
        g_string_append_printf (record, "%" G_GSIZE_FORMAT,
                                result->queue_occupied_after_study);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_occupied_before_match_u64\":");
      if (result->queue_before_match_observed)
        g_string_append_printf (record, "%" G_GSIZE_FORMAT,
                                result->queue_occupied_before_match);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_state_after_study_u32\":");
      if (result->queue_after_study_observed)
        g_string_append_printf (record, "%u", result->queue_state_after_study);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"queue_state_before_match_u32\":");
      if (result->queue_before_match_observed)
        g_string_append_printf (record, "%u", result->queue_state_before_match);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"score_i32\":");
      if (result->evaluated)
        g_string_append_printf (record, "%d", result->score);
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"valid\":");
      if (result->validation_observed)
        g_string_append (record, result->valid ? "true" : "false");
      else
        g_string_append (record, "null");
      g_string_append (record, ",\"validation_error\":");
      goodix_debug_json_error (record, result->validation_error);
      g_string_append_c (record, '}');
    }
  g_string_append_printf (
    record,
    "],\"generation_id_u64\":%" G_GUINT64_FORMAT
    ",\"generation_use_index_u64\":%" G_GUINT64_FORMAT
    ",\"invalid_gallery_u32\":%u,\"lifecycle\":{"
    "\"extraction\":{\"attempted\":%s,\"completed\":%s},"
    "\"preprocess\":{\"attempted\":%s,\"completed\":%s},"
    "\"study\":{\"attempted\":%s,\"completed\":%s}},"
    "\"operation_id\":",
    output->generation_id, metadata->generation_use_index,
    output->invalid_gallery_count,
    output->extraction_attempted ? "true" : "false",
    output->extraction_completed ? "true" : "false",
    output->preprocess_attempted ? "true" : "false",
    output->preprocess_completed ? "true" : "false",
    output->study_attempted ? "true" : "false",
    output->study_completed ? "true" : "false");
  goodix_debug_json_string (record, operation_id);
  g_string_append_printf (
    record,
    ",\"partition0_count_u32\":%u,\"partition1_count_u32\":%u,"
    "\"preprocess_status_i32\":",
    output->probe_partition0_count, output->probe_partition1_count);
  if (output->preprocess_status_available)
    g_string_append_printf (record, "%d", output->preprocess_status);
  else
    g_string_append (record, "null");
  g_string_append_printf (
    record,
    ",\"print_schema\":4,\"probe_record_count_u32\":%u,\"profile_u16\":9,"
    "\"purpose_u32\":%u,"
    "\"quality_i32\":",
    output->probe_record_count, (guint) output->purpose);
  if (output->preprocess_attempted)
    g_string_append_printf (record, "%d", output->quality);
  else
    g_string_append (record, "null");
  g_string_append_printf (
    record,
    ",\"schema\":\"goodix53x5-runtime-debug/v3\",\"score_i32\":");
  if (output->evaluated_gallery_count > 0)
    g_string_append_printf (record, "%d", output->score);
  else
    g_string_append (record, "null");
  g_string_append_printf (
    record,
    ",\"sensor_subtype_u16\":12,\"stage_u32\":%u,\"status_u32\":%u,"
    "\"study_action_u32\":",
    stage, (guint) output->status);
  if (output->study_attempted)
    g_string_append_printf (record, "%u", (guint) output->study_action);
  else
    g_string_append (record, "null");
  g_string_append_printf (
    record,
    ",\"tcode_u16\":%u,\"valid_gallery_u32\":%u,"
    "\"winner_index_u32\":",
    output->tcode, output->valid_gallery_count);
  if (output->winner_position != G_MAXSIZE)
    g_string_append_printf (record, "%u", output->winner_index);
  else
    g_string_append (record, "null");
  g_string_append (record, ",\"winner_position_u64\":");
  if (output->winner_position != G_MAXSIZE)
    g_string_append_printf (record, "%" G_GSIZE_FORMAT,
                            output->winner_position);
  else
    g_string_append (record, "null");
  g_string_append (record, "}\n");
  prefix = g_strdup_printf (
    "runtime-%s-%" G_GUINT64_FORMAT "-%" G_GUINT64_FORMAT "-%u-%"
    G_GUINT64_FORMAT,
    action_name, output->action_epoch, output->generation_id, stage,
    chronology);
  record_len = record->len;
  record_data = g_string_free (g_steal_pointer (&record), FALSE);
  bytes = g_byte_array_new_take ((guint8 *) record_data, record_len);
  if (goodix_debug_write_dump (
        prefix, goodix_crypto_crc32_mpeg2 (bytes->data, bytes->len), bytes,
        "json"))
    self->debug_chronology = chronology;
  goodix_debug_artifact_free (final_candidate_artifact);
  goodix_debug_artifact_free (live_raw_artifact);
  goodix_debug_artifact_free (native_probe_artifact);
  goodix_debug_artifact_free (processed_image_artifact);
  goodix_debug_artifact_free (setup_tx_on_artifact);
}
