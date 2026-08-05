/*
 * Host-test stand-in for libfprint's internal drivers_api.h.
 *
 * goodix53x5-crypto.c's only dependency on libfprint is the two logging macros
 * below (upstream fpi-log.h defines them as plain g_debug/g_warning). Confirm
 * that is still true with:
 *
 *   grep -o 'fp_[a-z_]*\|fpi_[a-z_]*' drivers/goodix53x5/goodix53x5-crypto.c \
 *     | sort -u
 *
 * Providing them here lets the real crypto translation unit be compiled and
 * unit-tested on the host with nothing but glib and OpenSSL - no cloned and
 * configured libfprint tree needed. Put this directory first on the include
 * path so it shadows the real header.
 */
#pragma once

#include <glib.h>

#define fp_dbg  g_debug
#define fp_warn g_warning
