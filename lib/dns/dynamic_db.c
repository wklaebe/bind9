/*
 * Copyright (C) 2008-2011  Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND Red Hat DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL Red Hat BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */


#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/region.h>
#include <isc/task.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/dynamic_db.h>
#include <dns/log.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <string.h>

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifndef DYNDB_LIBDIR
#define DYNDB_LIBDIR ""
#endif

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)


typedef isc_result_t (*register_func_t)(isc_mem_t *mctx, const char *name,
		const char * const *argv,
		const dns_dyndb_arguments_t *dyndb_args);
typedef void (*destroy_func_t)(void);

typedef struct dyndb_implementation dyndb_implementation_t;

struct dyndb_implementation {
	isc_mem_t			*mctx;
	void				*handle;
	register_func_t			register_function;
	destroy_func_t			destroy_function;
	LINK(dyndb_implementation_t)	link;
};

struct dns_dyndb_arguments {
	dns_view_t	*view;
	dns_zonemgr_t	*zmgr;
	isc_task_t	*task;
	isc_timermgr_t	*timermgr;
};

/* List of implementations. Locked by dyndb_lock. */
static LIST(dyndb_implementation_t) dyndb_implementations;
/* Locks dyndb_implementations. */
static isc_mutex_t dyndb_lock;
static isc_once_t once = ISC_ONCE_INIT;

static void
dyndb_initialize(void) {
	RUNTIME_CHECK(isc_mutex_init(&dyndb_lock) == ISC_R_SUCCESS);
	INIT_LIST(dyndb_implementations);
}


#if HAVE_DLFCN_H
static isc_result_t
load_symbol(void *handle, const char *symbol_name, void **symbolp)
{
	const char *errmsg;
	void *symbol;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	symbol = dlsym(handle, symbol_name);
	if (symbol == NULL) {
		errmsg = dlerror();
		if (errmsg == NULL)
			errmsg = "returned function pointer is NULL";
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DYNDB, ISC_LOG_ERROR,
			      "failed to lookup symbol %s: %s",
			      symbol_name, errmsg);
		return ISC_R_FAILURE;
	}
	dlerror();

	*symbolp = symbol;

	return ISC_R_SUCCESS;
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *filename, dyndb_implementation_t **impp)
{
	isc_result_t result;
	size_t module_size;
	isc_buffer_t *module_buf = NULL;
	isc_region_t module_region;
	void *handle = NULL;
	dyndb_implementation_t *imp;
	register_func_t register_function = NULL;
	destroy_func_t destroy_function = NULL;

	REQUIRE(impp != NULL && *impp == NULL);

	/* Build up the full path. */
	module_size = strlen(DYNDB_LIBDIR) + strlen(filename) + 1;
	CHECK(isc_buffer_allocate(mctx, &module_buf, module_size));
	isc_buffer_putstr(module_buf, DYNDB_LIBDIR);
	isc_buffer_putstr(module_buf, filename);
	isc_buffer_putuint8(module_buf, 0);
	isc_buffer_region(module_buf, &module_region);

	handle = dlopen((char *)module_region.base, RTLD_LAZY);
	if (handle == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DYNDB, ISC_LOG_ERROR,
			      "failed to dynamically load driver '%s': %s",
			      filename, dlerror());
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	dlerror();

	CHECK(load_symbol(handle, "dynamic_driver_init",
			  (void **)&register_function));
	CHECK(load_symbol(handle, "dynamic_driver_destroy",
			  (void **)&destroy_function));

	imp = isc_mem_get(mctx, sizeof(dyndb_implementation_t));
	if (imp == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	imp->handle = handle;
	imp->register_function = register_function;
	imp->destroy_function = destroy_function;
	INIT_LINK(imp, link);

	*impp = imp;

cleanup:
	if (result != ISC_R_SUCCESS && handle != NULL)
		dlclose(handle);
	if (module_buf != NULL)
		isc_buffer_free(&module_buf);

	return result;
}

static void
unload_library(dyndb_implementation_t **impp)
{
	dyndb_implementation_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dyndb_implementation_t));

	*impp = NULL;
}

#else	/* HAVE_DLFCN_H */
static isc_result_t
load_library(isc_mem_t *mctx, const char *filename, dyndb_implementation_t **impp)
{
	UNUSED(mctx);
	UNUSED(filename);
	UNUSED(impp);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		      ISC_LOG_ERROR,
		      "dynamic database support is not implemented")

	return ISC_R_NOTIMPLEMENTED;
}

static void
unload_library(dyndb_implementation_t **impp)
{
	dyndb_implementation_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dyndb_implementation_t));

	*impp = NULL;
}
#endif	/* HAVE_DLFCN_H */

isc_result_t
dns_dynamic_db_load(const char *libname, const char *name, isc_mem_t *mctx,
		    const char * const *argv,
		    const dns_dyndb_arguments_t *dyndb_args)
{
	isc_result_t result;
	dyndb_implementation_t *implementation = NULL;

	RUNTIME_CHECK(isc_once_do(&once, dyndb_initialize) == ISC_R_SUCCESS);

	CHECK(load_library(mctx, libname, &implementation));
	CHECK(implementation->register_function(mctx, name, argv, dyndb_args));

	LOCK(&dyndb_lock);
	APPEND(dyndb_implementations, implementation, link);
	UNLOCK(&dyndb_lock);

	return ISC_R_SUCCESS;

cleanup:
	if (implementation != NULL)
		unload_library(&implementation);

	return result;
}

void
dns_dynamic_db_cleanup(isc_boolean_t exiting)
{
	dyndb_implementation_t *elem;
	dyndb_implementation_t *prev;

	RUNTIME_CHECK(isc_once_do(&once, dyndb_initialize) == ISC_R_SUCCESS);

	LOCK(&dyndb_lock);
	elem = TAIL(dyndb_implementations);
	while (elem != NULL) {
		prev = PREV(elem, link);
		UNLINK(dyndb_implementations, elem, link);
		elem->destroy_function();
		unload_library(&elem);
		elem = prev;
	}
	UNLOCK(&dyndb_lock);

	if (exiting == ISC_TRUE)
		isc_mutex_destroy(&dyndb_lock);
}

dns_dyndb_arguments_t *
dns_dyndb_arguments_create(isc_mem_t *mctx)
{
	dns_dyndb_arguments_t *args;

	args = isc_mem_get(mctx, sizeof(*args));
	if (args != NULL)
		memset(args, 0, sizeof(*args));

	return args;
}

void
dns_dyndb_arguments_destroy(isc_mem_t *mctx, dns_dyndb_arguments_t *args)
{
	REQUIRE(args != NULL);

	dns_dyndb_set_view(args, NULL);
	dns_dyndb_set_zonemgr(args, NULL);
	dns_dyndb_set_task(args, NULL);
	dns_dyndb_set_timermgr(args, NULL);

	isc_mem_put(mctx, args, sizeof(*args));
}

void
dns_dyndb_set_view(dns_dyndb_arguments_t *args, dns_view_t *view)
{
	REQUIRE(args != NULL);

	if (args->view != NULL)
		dns_view_detach(&args->view);
	if (view != NULL)
		dns_view_attach(view, &args->view);
}

dns_view_t *
dns_dyndb_get_view(dns_dyndb_arguments_t *args)
{
	REQUIRE(args != NULL);

	return args->view;
}

void
dns_dyndb_set_zonemgr(dns_dyndb_arguments_t *args, dns_zonemgr_t *zmgr)
{
	REQUIRE(args != NULL);

	if (args->zmgr != NULL)
		dns_zonemgr_detach(&args->zmgr);
	if (zmgr != NULL)
		dns_zonemgr_attach(zmgr, &args->zmgr);
}

dns_zonemgr_t *
dns_dyndb_get_zonemgr(dns_dyndb_arguments_t *args)
{
	REQUIRE(args != NULL);

	return args->zmgr;
}

void
dns_dyndb_set_task(dns_dyndb_arguments_t *args, isc_task_t *task)
{
	REQUIRE(args != NULL);

	if (args->task != NULL)
		isc_task_detach(&args->task);
	if (task != NULL)
		isc_task_attach(task, &args->task);
}

isc_task_t *
dns_dyndb_get_task(dns_dyndb_arguments_t *args)
{
	REQUIRE(args != NULL);

	return args->task;
}

void
dns_dyndb_set_timermgr(dns_dyndb_arguments_t *args, isc_timermgr_t *timermgr)
{
	REQUIRE(args != NULL);

	args->timermgr = timermgr;
}

isc_timermgr_t *
dns_dyndb_get_timermgr(dns_dyndb_arguments_t *args)
{
	REQUIRE(args != NULL);

	return args->timermgr;
}
