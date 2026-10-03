/*
 * Goodix 53x5 driver for libfprint - Milan preprocessing persistence
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/persistence.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib/gstdio.h>

#define GOODIX_MILAN_STATE_DIR "/var/lib/fprint"
#define GOODIX_MILAN_STATE_PREFIX "goodix53x5-preprocess-"
#define GOODIX_MILAN_STATE_VERSION 2u
#define GOODIX_MILAN_STATE_HEADER_SIZE 64u
#define GOODIX_MILAN_STATE_SAMPLE_FORMAT 2u
#define GOODIX_MILAN_STATE_CALIBRATION_SIZE \
  (GOODIX_MILAN_SENSOR_PIXELS * sizeof (guint16))
#define GOODIX_MILAN_STATE_RING_PLANES_SIZE \
  (3u * GOODIX_MILAN_EXTRACTION_CLASSIFICATION_PIXELS)
#define GOODIX_MILAN_STATE_AGE_PLANE_SIZE GOODIX_MILAN_SENSOR_PIXELS
#define GOODIX_MILAN_STATE_REFERENCE_ROWS (GOODIX_MILAN_SENSOR_ROWS / 2u)
#define GOODIX_MILAN_STATE_REFERENCE_COLUMNS (GOODIX_MILAN_SENSOR_COLUMNS / 2u)
#define GOODIX_MILAN_STATE_REFERENCE_VALUES \
  (GOODIX_MILAN_STATE_REFERENCE_ROWS * GOODIX_MILAN_STATE_REFERENCE_COLUMNS)
#define GOODIX_MILAN_STATE_REFERENCE_SIZE \
  (GOODIX_MILAN_STATE_REFERENCE_VALUES * sizeof (guint16))
#define GOODIX_MILAN_STATE_DIGEST_SIZE 32u
#define GOODIX_MILAN_STATE_PAYLOAD_OFFSET GOODIX_MILAN_STATE_HEADER_SIZE
#define GOODIX_MILAN_STATE_CALIBRATION_OFFSET GOODIX_MILAN_STATE_PAYLOAD_OFFSET
#define GOODIX_MILAN_STATE_RING_COUNT_OFFSET \
  (GOODIX_MILAN_STATE_CALIBRATION_OFFSET + GOODIX_MILAN_STATE_CALIBRATION_SIZE)
#define GOODIX_MILAN_STATE_COMPONENT_COUNT_OFFSET \
  (GOODIX_MILAN_STATE_RING_COUNT_OFFSET + 1u)
#define GOODIX_MILAN_STATE_REFERENCE_COUNT_OFFSET \
  (GOODIX_MILAN_STATE_COMPONENT_COUNT_OFFSET + 1u)
#define GOODIX_MILAN_STATE_RING_PLANES_OFFSET \
  (GOODIX_MILAN_STATE_REFERENCE_COUNT_OFFSET + 1u)
#define GOODIX_MILAN_STATE_COMPONENT_AGES_OFFSET \
  (GOODIX_MILAN_STATE_RING_PLANES_OFFSET + GOODIX_MILAN_STATE_RING_PLANES_SIZE)
#define GOODIX_MILAN_STATE_SUPPORT_AGES_OFFSET \
  (GOODIX_MILAN_STATE_COMPONENT_AGES_OFFSET + GOODIX_MILAN_STATE_AGE_PLANE_SIZE)
#define GOODIX_MILAN_STATE_REFERENCE_OFFSET \
  (GOODIX_MILAN_STATE_SUPPORT_AGES_OFFSET + GOODIX_MILAN_STATE_AGE_PLANE_SIZE)
#define GOODIX_MILAN_STATE_PAYLOAD_SIZE \
  (GOODIX_MILAN_STATE_REFERENCE_OFFSET + GOODIX_MILAN_STATE_REFERENCE_SIZE - \
   GOODIX_MILAN_STATE_PAYLOAD_OFFSET)
#define GOODIX_MILAN_STATE_DIGEST_OFFSET \
  (GOODIX_MILAN_STATE_PAYLOAD_OFFSET + GOODIX_MILAN_STATE_PAYLOAD_SIZE)
#define GOODIX_MILAN_STATE_FILE_SIZE \
  (GOODIX_MILAN_STATE_DIGEST_OFFSET + GOODIX_MILAN_STATE_DIGEST_SIZE)
#define GOODIX_MILAN_STATE_MAX_SAMPLE_COUNT 400u

enum {
  GOODIX_MILAN_STATE_MAGIC_OFFSET = 0,
  GOODIX_MILAN_STATE_VERSION_OFFSET = 8,
  GOODIX_MILAN_STATE_HEADER_SIZE_OFFSET = 12,
  GOODIX_MILAN_STATE_SUBTYPE_OFFSET = 16,
  GOODIX_MILAN_STATE_ROWS_OFFSET = 18,
  GOODIX_MILAN_STATE_COLUMNS_OFFSET = 20,
  GOODIX_MILAN_STATE_SAMPLE_FORMAT_OFFSET = 22,
  GOODIX_MILAN_STATE_SAMPLE_COUNT_OFFSET = 24,
  GOODIX_MILAN_STATE_PAYLOAD_SIZE_OFFSET = 28,
  GOODIX_MILAN_STATE_IDENTITY_OFFSET = 32,
};

static const guint8 goodix_milan_state_magic[8] = {
  'G', '5', '3', 'P', '9', 'P', 'S', '\0'
};
static const gchar goodix_milan_identity_domain[] =
  "goodix53x5-preprocess-v2";

/* Selected at sample delivery, immutable until the setup worker publishes it.
 * Neither the destination nor the bytes borrow the device or live generation. */
struct _GoodixMilanSetupSave
{
  gchar  *path;
  guint8 *contents;
};

static void
goodix_milan_write_u16 (guint8 *output,
                        guint16 value)
{
  value = GUINT16_TO_LE (value);
  memcpy (output, &value, sizeof (value));
}

static void
goodix_milan_write_u32 (guint8 *output,
                        guint32 value)
{
  value = GUINT32_TO_LE (value);
  memcpy (output, &value, sizeof (value));
}

static guint16
goodix_milan_read_u16 (const guint8 *input)
{
  guint16 value;

  memcpy (&value, input, sizeof (value));
  return GUINT16_FROM_LE (value);
}

static guint32
goodix_milan_read_u32 (const guint8 *input)
{
  guint32 value;

  memcpy (&value, input, sizeof (value));
  return GUINT32_FROM_LE (value);
}

static gint32
goodix_milan_shift_right (gint32 value,
                          guint  shift)
{
  guint32 bits = (guint32) value;

  if (value >= 0)
    return (gint32) (bits >> shift);
  return (gint32) ((bits >> shift) |
                   (~UINT32_C (0) << (32u - shift)));
}

static void
goodix_milan_restore_reference (const guint8 *packed,
                                guint16      *output)
{
  gint16 source[GOODIX_MILAN_STATE_REFERENCE_VALUES];

  for (gsize i = 0; i < G_N_ELEMENTS (source); i++)
    source[i] = (gint16) goodix_milan_read_u16 (packed + i * sizeof (guint16));

  for (gsize row = 0; row < GOODIX_MILAN_SENSOR_ROWS; row++)
    for (gsize column = 0; column < GOODIX_MILAN_SENSOR_COLUMNS; column++)
      {
        gsize source_row = row / 2u;
        gsize source_column = column / 2u;
        gint32 values[4];
        guint value_count = 0;
        gint32 value;

        for (gsize y = source_row;
             y < source_row + 2u && y < GOODIX_MILAN_STATE_REFERENCE_ROWS;
             y++)
          for (gsize x = source_column;
               x < source_column + 2u &&
               x < GOODIX_MILAN_STATE_REFERENCE_COLUMNS;
               x++)
            values[value_count++] =
              source[y * GOODIX_MILAN_STATE_REFERENCE_COLUMNS + x];

        if (value_count == 4)
          {
            gint32 fx = (column & 1u) ? 128 : 0;
            gint32 fy = (row & 1u) ? 128 : 0;
            guint32 weighted =
              (guint32) values[0] * (guint32) (256 - fx) *
                (guint32) (256 - fy) +
              (guint32) values[1] * (guint32) fx *
                (guint32) (256 - fy) +
              (guint32) values[2] * (guint32) (256 - fx) * (guint32) fy +
              (guint32) values[3] * (guint32) fx * (guint32) fy + 0x8000u;

            value = goodix_milan_shift_right ((gint32) weighted, 16);
          }
        else
          {
            gint32 sum = 0;

            for (guint i = 0; i < value_count; i++)
              sum += values[i];
            value = sum / (gint32) value_count;
          }
        output[row * GOODIX_MILAN_SENSOR_COLUMNS + column] =
          (guint16) (gint16) value;
      }
}

static void
goodix_milan_store_reference (const guint16 *input,
                              guint8        *packed)
{
  for (gsize row = 0; row < GOODIX_MILAN_STATE_REFERENCE_ROWS; row++)
    for (gsize column = 0; column < GOODIX_MILAN_STATE_REFERENCE_COLUMNS;
         column++)
      {
        gsize source = row * 2u * GOODIX_MILAN_SENSOR_COLUMNS + column * 2u;
        gint32 sum = (gint16) input[source] +
                     (gint16) input[source + 1] +
                     (gint16) input[source + GOODIX_MILAN_SENSOR_COLUMNS] +
                     (gint16) input[source + GOODIX_MILAN_SENSOR_COLUMNS + 1];

        goodix_milan_write_u16 (
          packed + (row * GOODIX_MILAN_STATE_REFERENCE_COLUMNS + column) *
                     sizeof (guint16),
          (guint16) (gint16) goodix_milan_shift_right (sum, 2));
      }
}

static void
goodix_milan_sha256 (const guint8 *data,
                     gsize         size,
                     guint8        digest[GOODIX_MILAN_STATE_DIGEST_SIZE])
{
  g_autoptr(GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  gsize digest_size = GOODIX_MILAN_STATE_DIGEST_SIZE;

  g_checksum_update (checksum, data, size);
  g_checksum_get_digest (checksum, digest, &digest_size);
}

static gchar *
goodix_milan_state_path (const gchar *prefix,
                         const guint8 identity[GOODIX_MILAN_STATE_DIGEST_SIZE])
{
  static const gchar hex[] = "0123456789abcdef";
  gchar encoded[GOODIX_MILAN_STATE_DIGEST_SIZE * 2 + 1];

  for (gsize i = 0; i < GOODIX_MILAN_STATE_DIGEST_SIZE; i++)
    {
      encoded[i * 2] = hex[identity[i] >> 4];
      encoded[i * 2 + 1] = hex[identity[i] & 0x0f];
    }
  encoded[sizeof (encoded) - 1] = '\0';
  return g_strdup_printf (GOODIX_MILAN_STATE_DIR "/%s%s.bin", prefix, encoded);
}

static void
goodix_milan_state_header (guint8              *contents,
                           FpiDeviceGoodix53x5 *self,
                           guint32              sample_count)
{
  memcpy (contents + GOODIX_MILAN_STATE_MAGIC_OFFSET,
          goodix_milan_state_magic, sizeof (goodix_milan_state_magic));
  goodix_milan_write_u32 (contents + GOODIX_MILAN_STATE_VERSION_OFFSET,
                          GOODIX_MILAN_STATE_VERSION);
  goodix_milan_write_u32 (contents + GOODIX_MILAN_STATE_HEADER_SIZE_OFFSET,
                          GOODIX_MILAN_STATE_HEADER_SIZE);
  goodix_milan_write_u16 (contents + GOODIX_MILAN_STATE_SUBTYPE_OFFSET,
                          self->milan_sensor_subtype);
  goodix_milan_write_u16 (contents + GOODIX_MILAN_STATE_ROWS_OFFSET,
                          GOODIX_MILAN_SENSOR_ROWS);
  goodix_milan_write_u16 (contents + GOODIX_MILAN_STATE_COLUMNS_OFFSET,
                          GOODIX_MILAN_SENSOR_COLUMNS);
  goodix_milan_write_u16 (contents + GOODIX_MILAN_STATE_SAMPLE_FORMAT_OFFSET,
                          GOODIX_MILAN_STATE_SAMPLE_FORMAT);
  goodix_milan_write_u32 (contents + GOODIX_MILAN_STATE_SAMPLE_COUNT_OFFSET,
                          sample_count);
  goodix_milan_write_u32 (contents + GOODIX_MILAN_STATE_PAYLOAD_SIZE_OFFSET,
                          GOODIX_MILAN_STATE_PAYLOAD_SIZE);
  memcpy (contents + GOODIX_MILAN_STATE_IDENTITY_OFFSET,
          self->milan_persistence_identity,
          sizeof (self->milan_persistence_identity));
}

static gboolean
goodix_milan_state_directory_secure (GError **error)
{
  GStatBuf stat_buffer;

  if (g_lstat (GOODIX_MILAN_STATE_DIR, &stat_buffer) != 0)
    {
      int saved_errno = errno;

      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
                   "Failed to inspect %s: %s", GOODIX_MILAN_STATE_DIR,
                   g_strerror (saved_errno));
      return FALSE;
    }
  if (!S_ISDIR (stat_buffer.st_mode) || stat_buffer.st_uid != geteuid () ||
      (stat_buffer.st_mode & 0777) != 0700)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_ACCES,
                   "Milan state directory %s has unsafe ownership or permissions",
                   GOODIX_MILAN_STATE_DIR);
      return FALSE;
    }
  return TRUE;
}

static gboolean
goodix_milan_state_read (const gchar *path,
                         gsize        size,
                         guint8     **contents,
                         GError     **error)
{
  GStatBuf stat_buffer;
  g_autofree guint8 *buffer = NULL;
  gsize offset = 0;
  int descriptor;

  descriptor = g_open (path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0);
  if (descriptor < 0)
    {
      int saved_errno = errno;

      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
                   "Failed to open %s: %s", path, g_strerror (saved_errno));
      return FALSE;
    }
  if (fstat (descriptor, &stat_buffer) != 0 ||
      !S_ISREG (stat_buffer.st_mode) || stat_buffer.st_uid != geteuid () ||
      (stat_buffer.st_mode & 0777) != 0600 ||
      stat_buffer.st_size != (goffset) size)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL,
                   "Milan state %s has invalid size, ownership, or permissions",
                   path);
      close (descriptor);
      return FALSE;
    }

  buffer = g_malloc (size);
  while (offset < size)
    {
      ssize_t bytes_read = read (descriptor, buffer + offset,
                                 size - offset);

      if (bytes_read < 0 && errno == EINTR)
        continue;
      if (bytes_read <= 0)
        {
          int saved_errno = bytes_read < 0 ? errno : EIO;

          g_set_error (error, G_FILE_ERROR,
                       g_file_error_from_errno (saved_errno),
                       "Failed to read %s: %s", path,
                       g_strerror (saved_errno));
          close (descriptor);
          return FALSE;
        }
      offset += (gsize) bytes_read;
    }
  close (descriptor);
  *contents = g_steal_pointer (&buffer);
  return TRUE;
}

static int
goodix_milan_state_open_directory (GError **error)
{
  GStatBuf stat_buffer;
  int descriptor = -1;
  int parent = -1;
  int saved_errno;
  int result;
  gboolean created = FALSE;

  descriptor = g_open (GOODIX_MILAN_STATE_DIR,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, 0);
  if (descriptor < 0 && errno == ENOENT)
    {
      /* /var/lib must already be provisioned durably. Own only the leaf's
       * creation, including its link in that parent, not an ancestor tree. */
      parent = g_open ("/var/lib",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, 0);
      if (parent < 0 || mkdirat (parent, "fprint", 0700) != 0)
        goto fail;
      created = TRUE;
      descriptor = openat (parent, "fprint",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
  if (descriptor < 0 || fstat (descriptor, &stat_buffer) != 0)
    goto fail;
  if (!S_ISDIR (stat_buffer.st_mode) || stat_buffer.st_uid != geteuid () ||
      (stat_buffer.st_mode & 0777) != 0700)
    {
      errno = EACCES;
      goto fail;
    }
  if (created)
    {
      if (fsync (parent) != 0)
        goto fail;
      created = FALSE;
      /* Linux releases the descriptor even when close reports an error. */
      result = close (parent);
      parent = -1;
      if (result != 0)
        goto fail;
    }
  return descriptor;

fail:
  saved_errno = errno;
  if (descriptor >= 0)
    close (descriptor);
  /* Remove an uncommitted, still-empty leaf so a retry repeats parent sync.
   * As with temp cleanup, removal can itself fail under a filesystem fault. */
  if (created)
    unlinkat (parent, "fprint", AT_REMOVEDIR);
  if (parent >= 0)
    close (parent);
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
               "Failed to prepare %s: %s", GOODIX_MILAN_STATE_DIR,
               g_strerror (saved_errno));
  return -1;
}

static gboolean
goodix_milan_state_write (const gchar  *path,
                          const guint8 *contents,
                          gsize         size,
                          GError      **error)
{
  g_autofree gchar *uuid = NULL;
  g_autofree gchar *temporary = NULL;
  GStatBuf stat_buffer;
  gsize offset = 0;
  int directory;
  int descriptor = -1;
  int saved_errno;
  int result;
  gboolean temporary_exists = FALSE;

  directory = goodix_milan_state_open_directory (error);
  if (directory < 0)
    return FALSE;
  uuid = g_uuid_string_random ();
  temporary = g_strdup_printf (".goodix53x5-%s.tmp", uuid);
  descriptor = openat (directory, temporary,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0)
    goto fail;
  temporary_exists = TRUE;
  /* Never copy permissions from the previous destination. A restrictive umask
   * may remove owner bits; fix those on our own inode before syncing it. */
  if (fstat (descriptor, &stat_buffer) != 0 ||
      ((stat_buffer.st_mode & 0777) != 0600 && fchmod (descriptor, 0600) != 0))
    goto fail;
  while (offset < size)
    {
      ssize_t written = write (descriptor, contents + offset, size - offset);

      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        {
          if (written == 0)
            errno = EIO;
          goto fail;
        }
      offset += (gsize) written;
    }
  if (fsync (descriptor) != 0)
    goto fail;
  result = close (descriptor);
  descriptor = -1;
  if (result != 0)
    goto fail;
  if (renameat (directory, temporary, directory, strrchr (path, '/') + 1) != 0)
    goto fail;
  temporary_exists = FALSE;
  /* After rename the complete new file is visible. A directory sync failure
   * means uncertain durability, not rollback. */
  if (fsync (directory) != 0)
    goto fail;
  result = close (directory);
  directory = -1;
  if (result == 0)
    return TRUE;

fail:
  saved_errno = errno;
  if (descriptor >= 0)
    close (descriptor);
  if (temporary_exists)
    unlinkat (directory, temporary, 0);
  if (directory >= 0)
    close (directory);
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
               "Failed to save %s: %s", path, g_strerror (saved_errno));
  return FALSE;
}

static gboolean
goodix_milan_state_valid (
  const guint8 *contents,
  gsize         size,
  const guint8  identity[GOODIX_MILAN_STATE_DIGEST_SIZE],
  guint16       subtype)
{
  guint8 digest[GOODIX_MILAN_STATE_DIGEST_SIZE];

  if (size != GOODIX_MILAN_STATE_FILE_SIZE ||
      memcmp (contents + GOODIX_MILAN_STATE_MAGIC_OFFSET,
              goodix_milan_state_magic,
              sizeof (goodix_milan_state_magic)) != 0 ||
      goodix_milan_read_u32 (
        contents + GOODIX_MILAN_STATE_VERSION_OFFSET) !=
      GOODIX_MILAN_STATE_VERSION ||
      goodix_milan_read_u32 (
        contents + GOODIX_MILAN_STATE_HEADER_SIZE_OFFSET) !=
      GOODIX_MILAN_STATE_HEADER_SIZE ||
      goodix_milan_read_u16 (
        contents + GOODIX_MILAN_STATE_SUBTYPE_OFFSET) != subtype ||
      goodix_milan_read_u16 (contents + GOODIX_MILAN_STATE_ROWS_OFFSET) !=
      GOODIX_MILAN_SENSOR_ROWS ||
      goodix_milan_read_u16 (contents + GOODIX_MILAN_STATE_COLUMNS_OFFSET) !=
      GOODIX_MILAN_SENSOR_COLUMNS ||
      goodix_milan_read_u16 (
        contents + GOODIX_MILAN_STATE_SAMPLE_FORMAT_OFFSET) !=
      GOODIX_MILAN_STATE_SAMPLE_FORMAT ||
      goodix_milan_read_u32 (
        contents + GOODIX_MILAN_STATE_SAMPLE_COUNT_OFFSET) >
      GOODIX_MILAN_STATE_MAX_SAMPLE_COUNT ||
      goodix_milan_read_u32 (
        contents + GOODIX_MILAN_STATE_PAYLOAD_SIZE_OFFSET) !=
      GOODIX_MILAN_STATE_PAYLOAD_SIZE ||
      memcmp (contents + GOODIX_MILAN_STATE_IDENTITY_OFFSET, identity,
              GOODIX_MILAN_STATE_DIGEST_SIZE) != 0 ||
      contents[GOODIX_MILAN_STATE_RING_COUNT_OFFSET] > 3u ||
      contents[GOODIX_MILAN_STATE_COMPONENT_COUNT_OFFSET] > 5u ||
      contents[GOODIX_MILAN_STATE_REFERENCE_COUNT_OFFSET] > 50u)
    return FALSE;

  for (gsize i = 0; i < GOODIX_MILAN_STATE_RING_PLANES_SIZE; i++)
    if (contents[GOODIX_MILAN_STATE_RING_PLANES_OFFSET + i] > 2u)
      return FALSE;
  for (gsize i = 0; i < GOODIX_MILAN_STATE_AGE_PLANE_SIZE; i++)
    if (contents[GOODIX_MILAN_STATE_COMPONENT_AGES_OFFSET + i] > 5u ||
        contents[GOODIX_MILAN_STATE_SUPPORT_AGES_OFFSET + i] > 50u)
      return FALSE;

  goodix_milan_sha256 (contents, GOODIX_MILAN_STATE_DIGEST_OFFSET, digest);
  return memcmp (contents + GOODIX_MILAN_STATE_DIGEST_OFFSET, digest,
                 sizeof (digest)) == 0;
}

void
goodix_milan_persistence_prepare (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  g_autoptr(GChecksum) checksum = NULL;
  guint8 encoded[10];
  gsize digest_size = sizeof (self->milan_persistence_identity);

  goodix_milan_persistence_clear (dev);
  if (!self->otp_data || self->otp_len == 0 || self->otp_len > G_MAXUINT32)
    {
      fp_warn ("Cannot key Milan preprocessing state without verified OTP");
      return;
    }

  goodix_milan_write_u32 (encoded, self->chip_id);
  goodix_milan_write_u16 (encoded + 4, self->milan_sensor_subtype);
  goodix_milan_write_u32 (encoded + 6, (guint32) self->otp_len);
  checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, (const guint8 *) goodix_milan_identity_domain,
                     sizeof (goodix_milan_identity_domain) - 1);
  g_checksum_update (checksum, encoded, sizeof (encoded));
  g_checksum_update (checksum, self->otp_data, self->otp_len);
  g_checksum_get_digest (checksum, self->milan_persistence_identity,
                         &digest_size);
  self->milan_persistence_identity_valid = TRUE;
}

void
goodix_milan_persistence_clear (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  memset (self->milan_persistence_identity, 0,
          sizeof (self->milan_persistence_identity));
  self->milan_persistence_identity_valid = FALSE;
}

GoodixMilanSetupSave *
goodix_milan_persistence_restore (FpDevice              *dev,
                                  GoodixMilanGeneration *generation)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autofree guint8 *contents = NULL;
  GoodixMilanPreprocessState *restored;
  GoodixMilanSetupSave *save;

  g_autoptr(GError) error = NULL;

  g_return_val_if_fail (generation != NULL, NULL);
  save = g_try_new0 (GoodixMilanSetupSave, 1);
  if (!save)
    return NULL;
  if (!self->milan_persistence_identity_valid)
    return save;
  save->path = goodix_milan_state_path (GOODIX_MILAN_STATE_PREFIX,
                                        self->milan_persistence_identity);

  if (!goodix_milan_state_directory_secure (&error))
    {
      if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        fp_warn ("Cannot use Milan preprocessing state directory: %s",
                 error->message);
      goto defaults;
    }
  if (!goodix_milan_state_read (save->path, GOODIX_MILAN_STATE_FILE_SIZE, &contents, &error))
    {
      if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        fp_warn ("Failed to read Milan preprocessing state %s: %s",
                 save->path, error->message);
      goto defaults;
    }
  if (!goodix_milan_state_valid (contents, GOODIX_MILAN_STATE_FILE_SIZE,
                                 self->milan_persistence_identity,
                                 self->milan_sensor_subtype))
    {
      fp_warn ("Ignoring invalid Milan preprocessing state %s", save->path);
      goto defaults;
    }

  /* The setup caller already reset this temporary generation. All validation
   * precedes these writes; decoding the validated fixed-size fields cannot fail. */
  restored = &generation->state;
  /* Native import retains these fresh-DLL defaults, not persisted values. */
  restored->profile9_history_mask_threshold = 60;
  restored->profile9_history_mask_average = 60;
  restored->sample_count = goodix_milan_read_u32 (
    contents + GOODIX_MILAN_STATE_SAMPLE_COUNT_OFFSET);
  for (gsize i = 0; i < GOODIX_MILAN_SENSOR_PIXELS; i++)
    restored->calibration_map[i] = goodix_milan_read_u16 (
      contents + GOODIX_MILAN_STATE_CALIBRATION_OFFSET +
      i * sizeof (guint16));
  restored->extraction_classification.retained_count =
    contents[GOODIX_MILAN_STATE_RING_COUNT_OFFSET];
  restored->extraction_persistence.retained_count =
    contents[GOODIX_MILAN_STATE_RING_COUNT_OFFSET];
  memcpy (restored->extraction_classification.retained_class_planes,
          contents + GOODIX_MILAN_STATE_RING_PLANES_OFFSET,
          GOODIX_MILAN_STATE_RING_PLANES_SIZE);
  memcpy (restored->extraction_persistence.retained_class_planes,
          contents + GOODIX_MILAN_STATE_RING_PLANES_OFFSET,
          GOODIX_MILAN_STATE_RING_PLANES_SIZE);
  restored->profile9_history_update_count =
    contents[GOODIX_MILAN_STATE_COMPONENT_COUNT_OFFSET];
  restored->profile9_history_count =
    contents[GOODIX_MILAN_STATE_REFERENCE_COUNT_OFFSET];
  memcpy (restored->profile9_component_age,
          contents + GOODIX_MILAN_STATE_COMPONENT_AGES_OFFSET,
          GOODIX_MILAN_STATE_AGE_PLANE_SIZE);
  memcpy (restored->profile9_reference_age,
          contents + GOODIX_MILAN_STATE_SUPPORT_AGES_OFFSET,
          GOODIX_MILAN_STATE_AGE_PLANE_SIZE);
  goodix_milan_restore_reference (
    contents + GOODIX_MILAN_STATE_REFERENCE_OFFSET,
    restored->profile9_history_reference);
  fp_info ("Restored Milan preprocessing state with %u samples",
           generation->state.sample_count);
  /* Setup changes no compact-format field. Keep the original packed reference
   * and packet instead of encoding the reconstructed or transferred globals. */
  save->contents = g_steal_pointer (&contents);
  return save;

defaults:
  save->contents = g_try_malloc0 (GOODIX_MILAN_STATE_FILE_SIZE);
  if (save->contents)
    {
      /* Native default calibration is unity before the first live initializer
       * clears it. The immediate setup-save must retain that pre-live value. */
      goodix_milan_state_header (save->contents, self, 0);
      for (gsize i = 0; i < GOODIX_MILAN_SENSOR_PIXELS; i++)
        goodix_milan_write_u16 (
          save->contents + GOODIX_MILAN_STATE_CALIBRATION_OFFSET +
          i * sizeof (guint16), 0x2000);
      goodix_milan_sha256 (save->contents, GOODIX_MILAN_STATE_DIGEST_OFFSET,
                           save->contents + GOODIX_MILAN_STATE_DIGEST_OFFSET);
    }
  return save;
}

void
goodix_milan_setup_save_free (GoodixMilanSetupSave *save)
{
  if (!save)
    return;
  g_free (save->path);
  g_free (save->contents);
  g_free (save);
}

static gint32
goodix_milan_setup_save_publish (gpointer user_data)
{
  GoodixMilanSetupSave *save = user_data;

  g_autoptr(GError) error = NULL;

  if (!save || (save->path && !save->contents))
    return 0x8001;
  if (!save->path)
    return 0x8002;
  if (!goodix_milan_state_write (save->path, save->contents,
                                 GOODIX_MILAN_STATE_FILE_SIZE, &error))
    fp_warn ("Failed to save Milan setup state %s: %s",
             save->path, error->message);
  return 0;
}

void
goodix_milan_persistence_bind_setup (GoodixMilanRuntimeInput *input,
                                     GoodixMilanGeneration   *generation)
{
  g_return_if_fail (input != NULL);
  g_return_if_fail (generation != NULL);
  goodix_milan_runtime_input_set_setup_hook (
    input, goodix_milan_setup_save_publish,
    g_steal_pointer (&generation->setup_save),
    (GDestroyNotify) goodix_milan_setup_save_free);
}

void
goodix_milan_persistence_save (FpDevice                         *dev,
                               const GoodixMilanPreprocessState *state)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autofree guint8 *contents = NULL;
  g_autofree gchar *path = NULL;
  const guint8 *retained_planes;

  g_autoptr(GError) error = NULL;

  if (!state || !self->milan_persistence_identity_valid)
    return;
  retained_planes = (const guint8 *)
    state->extraction_persistence.retained_class_planes;
  if (state->sample_count > GOODIX_MILAN_STATE_MAX_SAMPLE_COUNT)
    {
      fp_warn ("Refusing to save invalid Milan sample count %u",
               state->sample_count);
      return;
    }
  if (state->extraction_persistence.retained_count > 3u ||
      state->profile9_history_update_count > 5u ||
      state->profile9_history_count > 50u)
    {
      fp_warn ("Refusing to save invalid Milan retained-state counters");
      return;
    }
  for (gsize i = 0; i < GOODIX_MILAN_STATE_RING_PLANES_SIZE; i++)
    if (retained_planes[i] > 2u)
      {
        fp_warn ("Refusing to save invalid Milan retained class plane");
        return;
      }
  for (gsize i = 0; i < GOODIX_MILAN_STATE_AGE_PLANE_SIZE; i++)
    if (state->profile9_component_age[i] > 5u ||
        state->profile9_reference_age[i] > 50u)
      {
        fp_warn ("Refusing to save invalid Milan retained age plane");
        return;
      }

  contents = g_malloc0 (GOODIX_MILAN_STATE_FILE_SIZE);
  goodix_milan_state_header (contents, self, state->sample_count);
  for (gsize i = 0; i < GOODIX_MILAN_SENSOR_PIXELS; i++)
    goodix_milan_write_u16 (
      contents + GOODIX_MILAN_STATE_CALIBRATION_OFFSET +
        i * sizeof (guint16),
      state->calibration_map[i]);
  contents[GOODIX_MILAN_STATE_RING_COUNT_OFFSET] =
    (guint8) state->extraction_persistence.retained_count;
  contents[GOODIX_MILAN_STATE_COMPONENT_COUNT_OFFSET] =
    (guint8) state->profile9_history_update_count;
  contents[GOODIX_MILAN_STATE_REFERENCE_COUNT_OFFSET] =
    (guint8) state->profile9_history_count;
  memcpy (contents + GOODIX_MILAN_STATE_RING_PLANES_OFFSET,
          retained_planes,
          GOODIX_MILAN_STATE_RING_PLANES_SIZE);
  memcpy (contents + GOODIX_MILAN_STATE_COMPONENT_AGES_OFFSET,
          state->profile9_component_age,
          GOODIX_MILAN_STATE_AGE_PLANE_SIZE);
  memcpy (contents + GOODIX_MILAN_STATE_SUPPORT_AGES_OFFSET,
          state->profile9_reference_age,
          GOODIX_MILAN_STATE_AGE_PLANE_SIZE);
  goodix_milan_store_reference (
    state->profile9_history_reference,
    contents + GOODIX_MILAN_STATE_REFERENCE_OFFSET);
  goodix_milan_sha256 (contents, GOODIX_MILAN_STATE_DIGEST_OFFSET,
                       contents + GOODIX_MILAN_STATE_DIGEST_OFFSET);

  path = goodix_milan_state_path (GOODIX_MILAN_STATE_PREFIX,
                                  self->milan_persistence_identity);
  if (!goodix_milan_state_write (path, contents, GOODIX_MILAN_STATE_FILE_SIZE, &error))
    {
      fp_warn ("Failed to save Milan preprocessing state %s: %s",
               path, error->message);
      return;
    }
  fp_info ("Saved Milan preprocessing state with %u samples",
           state->sample_count);
}
