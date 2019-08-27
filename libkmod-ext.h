/*
 * libkmod - interface to kernel module operations
 *
 * Copyright (c) 2013, Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */
#pragma once

int kmod_ext_probe(struct kmod_ctx *ctx, const char *alias,
		   unsigned int flags, const char *options);

int kmod_ext_remove(struct kmod_ctx *ctx, const char *alias);

int kmod_ext_info(struct kmod_ctx *ctx, const char *alias,
		  void (*info_cb)(struct kmod_ctx *ctx, const char *param,
				  const char *value));
