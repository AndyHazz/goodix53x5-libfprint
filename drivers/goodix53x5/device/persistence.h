/*
 * Goodix 53x5 driver for libfprint - Milan preprocessing persistence
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "device/base.h"
#include "milan/runtime.h"

void goodix_milan_persistence_prepare (FpDevice *dev);
void goodix_milan_persistence_clear (FpDevice *dev);
GoodixMilanSetupSave *goodix_milan_persistence_restore (FpDevice              *dev,
                                                        GoodixMilanGeneration *generation);
void goodix_milan_setup_save_free (GoodixMilanSetupSave *save);
void goodix_milan_persistence_bind_setup (GoodixMilanRuntimeInput *input,
                                          GoodixMilanGeneration   *generation);
void goodix_milan_persistence_save (FpDevice                         *dev,
                                    const GoodixMilanPreprocessState *state);
