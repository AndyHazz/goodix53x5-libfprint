/*
 * Goodix 53x5 driver for libfprint - generated Milan parity tests
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "drivers/goodix53x5/milan/match/match.h"

GoodixMatchInfo *make_distinct_append_fixture (const GoodixMatchInfo *probe);
void assert_generic_append_material (GBytes *probe, GBytes *before, GBytes *after);
