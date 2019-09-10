/*
 * Copyright (c) 2019, Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libkmod/libkmod-internal.h>

static int kmod_ext_insert_module(struct kmod_module *module,
				  unsigned int flags, const char *options)
{
	return kmod_module_probe_insert_module(module, flags, options, NULL,
					       NULL, NULL);
}

static int kmod_ext_is_module_file(const char *filename)
{
	struct stat st;
	size_t len;

	if (stat(filename, &st) || !S_ISREG(st.st_mode))
		return 0;

	/* Check for valid module extensions: .ko .ko.gz .ko.xz */
	len = strlen(filename);
	if ((len > 3 && !strncmp(filename + len - 3, ".ko", 3))    ||
	    (len > 6 && !strncmp(filename + len - 6, ".ko.gz", 6)) ||
	    (len > 6 && !strncmp(filename + len - 6, ".ko.xz", 6)))
		return 1;

	return 0;
}

static int kmod_ext_get_modules(struct kmod_ctx *ctx, const char *alias,
				struct kmod_list **list)
{
	struct kmod_module *module;
	int rc;

	/* ctx and alias parameters have been checked by callers */
	if (!list || *list != NULL)
		return -EINVAL;

	if (kmod_ext_is_module_file(alias)) {
		rc = kmod_module_new_from_path(ctx, alias, &module);
		if (rc) {
			ERR(ctx, "Failed to load module file %s\n", alias);
			return rc;
		}

		*list = kmod_list_append(*list, module);

		return 0;
	}

	rc = kmod_module_new_from_lookup(ctx, alias, list);
	if (!rc && !*list)
		rc = -ENOENT;

	return rc;
}

KMOD_EXPORT int kmod_ext_probe(struct kmod_ctx *ctx, const char *alias,
			       unsigned int flags, const char *options)
{
	struct kmod_list *entry, *mod_list = NULL;
	struct kmod_module *module;
	int rc;

	if (!ctx || !alias) {
		rc = -ENOSYS;
		goto exit;
	}

	rc = kmod_ext_get_modules(ctx, alias, &mod_list);
	if (rc < 0)
		goto exit;

	kmod_list_foreach(entry, mod_list) {
		module = kmod_module_get_module(entry);

		INFO(ctx, "Probing %s (%s):\n", kmod_module_get_name(module),
		     kmod_module_get_path(module));

		rc = kmod_ext_insert_module(module, flags, options);

		kmod_module_unref(module);

		if (rc)
			break;
	}

	kmod_module_unref_list(mod_list);

exit:
	if (rc)
		ERR(ctx, "Failed to load module '%s' (%s)\n", alias,
		    strerror(-rc));

	return rc;
}

static int kmod_ext_remove_list(struct kmod_ctx *ctx, struct kmod_list *list,
				bool fail_in_use)
{
	struct kmod_list *entry, *dep_list;
	struct kmod_module *module;
	const char *mod_name;
	int rc, ref;

	kmod_list_foreach(entry, list) {
		module = kmod_module_get_module(entry);
		mod_name = kmod_module_get_name(module);

		ref = kmod_module_get_refcnt(module);
		if (ref > 0) {
			if (fail_in_use) {
				rc = -EBUSY;
				ERR(ctx, "Module %s in use.\n", mod_name);
			} else {
				rc = 0;
				INFO(ctx, "Module %s in use.\n", mod_name);
			}

			goto unref_mod;
		}

		if (ref == 0) {
			INFO(ctx, "Removing module %s\n", mod_name);

			rc = kmod_module_remove_module(module, 0);
			if (rc) {
				if (rc != -EEXIST)
					goto unref_mod;

				rc = 0;
				INFO(ctx, "Module %s not in kernel.\n",
				     mod_name);
			}
		}

		dep_list = kmod_module_get_dependencies(module);

		if (dep_list) {
			INFO(ctx, "Removing %s dependencies.\n", mod_name);

			kmod_ext_remove_list(ctx, dep_list, false);
			kmod_module_unref_list(dep_list);
		}

		rc = 0;

unref_mod:
		kmod_module_unref(module);

		if (rc)
			return rc;
	}

	return 0;
}

KMOD_EXPORT int kmod_ext_remove(struct kmod_ctx *ctx, const char *alias)
{
	struct kmod_list *mod_list = NULL;
	int rc;

	if (!ctx || !alias) {
		rc = -ENOSYS;
		goto exit;
	}

	rc = kmod_ext_get_modules(ctx, alias, &mod_list);
	if (rc < 0)
		goto exit;

	rc = kmod_ext_remove_list(ctx, mod_list, true);

	kmod_module_unref_list(mod_list);

exit:
	if (rc)
		ERR(ctx, "Failed to unload module '%s' (%s)\n", alias,
		    strerror(-rc));

	return rc;
}

static int kmod_ext_info_module(struct kmod_ctx *ctx,
				struct kmod_module *module,
				void (*info_cb)(struct kmod_ctx *ctx,
						const char *param,
						const char *value))
{
	struct kmod_list *info_list = NULL, *info;
	const char *key, *value;
	int rc;

	rc = kmod_module_get_info(module, &info_list);
	if (rc < 0) {
		ERR(ctx, "Failed to get module info for '%s' (%s)\n",
		    kmod_module_get_name(module), strerror(-rc));
		return rc;
	}

	info_cb(ctx, "filename", kmod_module_get_path(module));
	info_cb(ctx, "name", kmod_module_get_name(module));

	kmod_list_foreach(info, info_list) {
		key = kmod_module_info_get_key(info);
		value = kmod_module_info_get_value(info);

		info_cb(ctx, key, value);
	}

	kmod_module_info_free_list(info_list);

	return 0;
}

KMOD_EXPORT int kmod_ext_info(struct kmod_ctx *ctx, const char *alias,
			      void (*info_cb)(struct kmod_ctx *ctx,
					      const char *param,
					      const char *value))
{
	struct kmod_list *mod_list = NULL, *mod;

	struct kmod_module *module;
	int rc;

	if (!ctx || !alias || !info_cb)
		return -ENOSYS;

	rc = kmod_ext_get_modules(ctx, alias, &mod_list);
	if (rc < 0) {
		ERR(ctx, "Failed to get module '%s' (%s)\n", alias,
		    strerror(-rc));
		return rc;
	}

	kmod_list_foreach(mod, mod_list) {
		module = kmod_module_get_module(mod);

		kmod_ext_info_module(ctx, module, info_cb);

		kmod_module_unref(module);
	}

	kmod_module_unref_list(mod_list);

	return 0;
}
