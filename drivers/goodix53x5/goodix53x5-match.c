/*
 * Goodix 53x5 driver for libfprint — SIGFM template format and matching
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
#include "goodix53x5-match.h"
#include "sigfm/sigfm.hpp"

#include <string.h>

/* Driver-owned wrapper for serialized SIGFM features. Bump the version when
 * preprocessing, extraction, or matching semantics make old templates unsafe
 * to compare against newly enrolled templates. */
#define GOODIX_SIGFM_TEMPLATE_MAGIC      "G53S"
#define GOODIX_SIGFM_TEMPLATE_MAGIC_LEN  4
#define GOODIX_SIGFM_TEMPLATE_VERSION    1
#define GOODIX_SIGFM_TEMPLATE_HEADER_LEN \
  (GOODIX_SIGFM_TEMPLATE_MAGIC_LEN + sizeof (guint16))
#define GOODIX_SIGFM_TEMPLATE_MAX_LEN    (1024 * 1024)

GoodixMatchInfo *
goodix_match_extract (const guint8 *image)
{
  return sigfm_extract (image, GOODIX_SENSOR_WIDTH, GOODIX_SENSOR_HEIGHT);
}

int
goodix_match_keypoints_count (GoodixMatchInfo *info)
{
  return sigfm_keypoints_count (info);
}

void
goodix_match_free_info (GoodixMatchInfo *info)
{
  sigfm_free_info (info);
}

GBytes *
goodix_match_serialize_template (GoodixMatchInfo *info)
{
  guint8 *feature;
  guint8 *template;
  guint16 version;
  int feature_len;

  feature = sigfm_serialize_binary (info, &feature_len);
  if (feature == NULL || feature_len <= 0 ||
      feature_len > GOODIX_SIGFM_TEMPLATE_MAX_LEN - GOODIX_SIGFM_TEMPLATE_HEADER_LEN)
    {
      g_free (feature);
      return NULL;
    }

  template = g_malloc (GOODIX_SIGFM_TEMPLATE_HEADER_LEN + feature_len);
  memcpy (template, GOODIX_SIGFM_TEMPLATE_MAGIC,
          GOODIX_SIGFM_TEMPLATE_MAGIC_LEN);
  version = GUINT16_TO_LE (GOODIX_SIGFM_TEMPLATE_VERSION);
  memcpy (template + GOODIX_SIGFM_TEMPLATE_MAGIC_LEN, &version,
          sizeof (version));
  memcpy (template + GOODIX_SIGFM_TEMPLATE_HEADER_LEN, feature, feature_len);
  g_free (feature);

  return g_bytes_new_take (template,
                           GOODIX_SIGFM_TEMPLATE_HEADER_LEN + feature_len);
}

static SigfmImgInfo *
goodix_match_deserialize_template (const guint8 *template,
                                   gsize         template_len,
                                   GoodixSigfmTemplateStatus *status)
{
  SigfmImgInfo *info;
  guint16 version;
  gsize feature_len;

  *status = GOODIX_SIGFM_TEMPLATE_INVALID;

  if (template_len <= GOODIX_SIGFM_TEMPLATE_HEADER_LEN ||
      template_len > GOODIX_SIGFM_TEMPLATE_MAX_LEN ||
      memcmp (template, GOODIX_SIGFM_TEMPLATE_MAGIC,
              GOODIX_SIGFM_TEMPLATE_MAGIC_LEN) != 0)
    {
      *status = GOODIX_SIGFM_TEMPLATE_INCOMPATIBLE;
      return NULL;
    }

  memcpy (&version, template + GOODIX_SIGFM_TEMPLATE_MAGIC_LEN,
          sizeof (version));
  if (GUINT16_FROM_LE (version) != GOODIX_SIGFM_TEMPLATE_VERSION)
    {
      *status = GOODIX_SIGFM_TEMPLATE_INCOMPATIBLE;
      return NULL;
    }

  feature_len = template_len - GOODIX_SIGFM_TEMPLATE_HEADER_LEN;
  if (feature_len > G_MAXINT)
    return NULL;

  info = sigfm_deserialize_binary (template + GOODIX_SIGFM_TEMPLATE_HEADER_LEN,
                                   (int) feature_len);
  if (info != NULL)
    *status = GOODIX_SIGFM_TEMPLATE_OK;

  return info;
}

GoodixSigfmTemplateStatus
goodix_match_serialized_feature (GoodixMatchInfo *probe_info,
                                 const guint8    *feature,
                                 gsize            feature_len,
                                 int             *score)
{
  SigfmImgInfo *tmpl_info;
  GoodixSigfmTemplateStatus status;

  tmpl_info = goodix_match_deserialize_template (feature, feature_len,
                                                 &status);
  if (tmpl_info == NULL)
    return status;

  *score = sigfm_match_score (probe_info, tmpl_info);
  sigfm_free_info (tmpl_info);
  if (*score < 0)
    return GOODIX_SIGFM_TEMPLATE_INVALID;

  return GOODIX_SIGFM_TEMPLATE_OK;
}
