/*
 * Goodix 53x5 driver for libfprint
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
#include "driver-private.h"
#include "device/session.h"
#include "device/enroll.h"
#include "device/auth.h"
#include "device/persistence.h"
#include "device/transport.h"
#include "device/scan.h"

#include <string.h>

G_DEFINE_TYPE (FpiDeviceGoodix53x5, fpi_device_goodix53x5,
               FP_TYPE_DEVICE)

/* ========================================================================
 * FpDevice virtual methods
 * ======================================================================== */

static void
goodix_open (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->open_recovery_attempted = FALSE;
  self->open_usb_reset_required = FALSE;
  g_clear_object (&self->session_cancel);
  self->session_cancel = g_cancellable_new ();
  self->session_suspended = FALSE;
  self->suspend_pending = FALSE;
  goodix_start_open_ssm (dev);
}

static void
goodix_close (FpDevice *dev)
{
  goodix_session_close (dev);
}

static void
goodix_enroll (FpDevice *dev)
{
  goodix_session_start_action (dev);
}

static void
goodix_verify (FpDevice *dev)
{
  goodix_session_start_action (dev);
}

static void
goodix_identify (FpDevice *dev)
{
  goodix_session_start_action (dev);
}

static void
goodix_suspend (FpDevice *dev)
{
  goodix_session_suspend (dev);
}

static void
goodix_resume (FpDevice *dev)
{
  goodix_session_resume (dev);
}

static void
goodix_cancel (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (goodix_session_cancel_pending_action (dev))
    return;

  if (self->cancel)
    {
      self->action_epoch++;
      g_cancellable_cancel (self->cancel);
    }
}

static void
goodix_removed (FpDevice *dev, GParamSpec *pspec, gpointer data)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gboolean removed = FALSE;

  g_object_get (dev, "removed", &removed, NULL);
  if (!removed || (!self->session_open && !self->task_ssm))
    return;
  self->needs_reinit = TRUE;
  if (self->session_cancel)
    g_cancellable_cancel (self->session_cancel);
  goodix_scan_stop_coordinator (
    dev, fpi_device_error_new (FP_DEVICE_ERROR_REMOVED));
}

/* ========================================================================
 * GObject boilerplate
 * ======================================================================== */

static void
fpi_device_goodix53x5_init (FpiDeviceGoodix53x5 *self)
{
#ifdef GOODIX53X5_DEBUG
  g_autofree gchar *capture_session_id = g_uuid_string_random ();

  g_strlcpy (self->debug_capture_session_id, capture_session_id,
             sizeof (self->debug_capture_session_id));
#endif
  memset (self->psk, 0, sizeof (self->psk));
  self->profile9_fdt.drift_anchor_empty = TRUE;
  self->session_cancel = g_cancellable_new ();
  g_signal_connect (self, "notify::removed", G_CALLBACK (goodix_removed), NULL);
}

static const FpIdEntry goodix53x5_id_table[] = {
  { .vid = 0x27c6, .pid = 0x5335, },
  { .vid = 0x27c6, .pid = 0x5385, },
  { .vid = 0x27c6, .pid = 0x5395, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
goodix_finalize (GObject *object)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (object);

  goodix_milan_generation_invalidate (&self->milan_retained_generation);
  g_clear_pointer (&self->hardware_reference, g_free);
  g_clear_object (&self->session_cancel);
  G_OBJECT_CLASS (fpi_device_goodix53x5_parent_class)->finalize (object);
}

static void
fpi_device_goodix53x5_class_init (FpiDeviceGoodix53x5Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = goodix_finalize;
  dev_class->id = "goodix53x5";
  dev_class->full_name = "Goodix HTK32 Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = goodix53x5_id_table;
  dev_class->nr_enroll_stages = GOODIX_ENROLL_SAMPLES;
  /* Native Milan has no equivalent time-based thermal cutoff. */
  dev_class->temp_hot_seconds = -1;
  dev_class->features = FP_DEVICE_FEATURE_VERIFY | FP_DEVICE_FEATURE_IDENTIFY;

  dev_class->open = goodix_open;
  dev_class->close = goodix_close;
  dev_class->enroll = goodix_enroll;
  dev_class->verify = goodix_verify;
  dev_class->identify = goodix_identify;
  dev_class->cancel = goodix_cancel;
  dev_class->suspend = goodix_suspend;
  dev_class->resume  = goodix_resume;
}
