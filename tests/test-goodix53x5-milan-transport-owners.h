/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Included once by the suite entry point; only external platform seams change. */
#include "test-goodix53x5-milan-transport-fixture.h"

static void capture_setup (FpDevice *, GoodixMilanGeneration *);
/* Compile the actual owners, replacing USB submission, the monotonic clock,
 * and setup preparation preceding our completed-capture boundary. FpiSsm is not mocked.
 * The executable supplies these owners instead of their archive objects. */
#define fpi_usb_transfer_submit mock_submit
#define fpi_device_get_cancellable test_action_cancellable
#define goodix_milan_generation_prepare_setup capture_setup
#define g_get_monotonic_time test_monotonic_time
#include "drivers/goodix53x5/device/transport.c"
#include "drivers/goodix53x5/device/commands.c"
#include "drivers/goodix53x5/device/scan.c"
static gboolean idle_test_release (void);
static gboolean idle_test_reset (void);
static gboolean idle_test_claim (GError **error);
static gboolean idle_test_usb_close (void);
static void idle_test_open_complete (FpDevice *dev, GError *error);
static void idle_test_close_complete (FpDevice *dev, GError *error);
static FpiSsm *idle_test_reinit_ssm (FpDevice *dev, FpiSsmHandlerCallback handler,
                                    int states, int cleanup, const char *name);
static void startup_delay (FpiSsm *ssm, int state, int delay);
static GString *startup_trace;
static guint startup_delays;
/* Exercise the real driver close, replacing only USB release and the outer
 * action completion (this transport fixture has no libfprint current GTask). */
#define g_usb_device_release_interface(device, interface, flags, error) idle_test_release ()
#define fpi_device_close_complete idle_test_close_complete
#include "drivers/goodix53x5/goodix53x5.c"
#define g_usb_device_reset(device, error) idle_test_reset ()
#define g_usb_device_claim_interface(device, interface, flags, error) idle_test_claim (error)
#define fpi_ssm_new_full idle_test_reinit_ssm
/* The virtual fixture has no USB handle or outer open GTask. Keep the real
 * session SSM and completion owner, replacing only those platform seams. */
#define g_usb_device_close(device, error) ((void) (device), idle_test_usb_close ())
#define fpi_device_open_complete idle_test_open_complete
#define fpi_device_action_is_cancelled(device) g_cancellable_is_cancelled (action_cancel_token)
#define fpi_device_get_usb_device(device) ((GUsbDevice *) NULL)
#define fpi_ssm_jump_to_state_delayed startup_delay
#include "drivers/goodix53x5/device/session.c"
#undef fpi_ssm_jump_to_state_delayed
#undef fpi_device_get_usb_device
#undef fpi_device_action_is_cancelled
#undef fpi_device_open_complete
#undef g_usb_device_close
#undef fpi_ssm_new_full
#undef g_usb_device_claim_interface
#undef g_usb_device_reset
#undef g_usb_device_release_interface
#undef fpi_device_close_complete
#undef goodix_milan_generation_prepare_setup
#undef fpi_usb_transfer_submit
#undef fpi_device_get_cancellable
#undef g_get_monotonic_time
