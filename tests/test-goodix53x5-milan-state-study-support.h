/*
 * Goodix 53x5 driver for libfprint - synthetic Milan state invariants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef TEST_GOODIX53X5_MILAN_STATE_STUDY_SUPPORT_H
#define TEST_GOODIX53X5_MILAN_STATE_STUDY_SUPPORT_H

#include "drivers/goodix53x5/milan/match/info-private.h"
#include "drivers/goodix53x5/milan/match/match.h"
#include "drivers/goodix53x5/milan/print.h"
#include "drivers/goodix53x5/milan/study/queue.h"
#include "drivers/goodix53x5/milan/template/codec-private.h"

#include <glib.h>
#include <stdint.h>
#include <string.h>

GBytes *
study_feature_element (guint    seed,
                       gboolean matchable,
                       gint32   active,
                       gint32   state,
                       gint32   residual,
                       gint32   ordinal,
                       gint32   marker);

GoodixMatchInfo *
study_match_info_from_feature (GBytes  *feature,
                               gboolean matchable);

GoodixMatchInfo *
study_match_info (guint    seed,
                  gboolean matchable,
                  gint32   marker);

GBytes *
study_gallery (GoodixMilanStudyAction action,
               gboolean               matchable_enrolled);

GoodixMilanMatchResult
study_primary_result (gint32 retained_flag);

GBytes *
ordered_match_feature (gint32 ordinal,
                       gint32 translation);

GBytes *
study_candidate_feature (gint32 ordinal,
                         gint32 coverage);

void
assert_study_template (GBytes                       *bytes,
                       guint32                       expected_relations,
                       GoodixMilanPrintTemplateInfo *info,
                       GoodixMilanUnpackedTemplate  *unpacked);

void
unpack_study_template (GBytes                      *bytes,
                       GoodixMilanUnpackedTemplate *unpacked);

void
assert_feature_material_equal (const GoodixMilanFeatureView *actual,
                               const GoodixMilanFeatureView *expected);

void
assert_replacement_semantics (
  const GoodixMilanUnpackedTemplate *before,
  const GoodixMilanUnpackedTemplate *after,
  const GoodixMilanUnpackedTemplate *probe,
  GoodixMilanStudyAction              action,
  gsize                               selected_index,
  gint32                              generation_count,
  gint32                              lifecycle_count,
  gboolean                            finalize_transaction);

#endif /* TEST_GOODIX53X5_MILAN_STATE_STUDY_SUPPORT_H */
