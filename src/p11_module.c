/*
 * Copyright 2020 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "p11_module.h"

#define P11MODULE_ENV "PKCS11MODULE"
#define P11SLOTID_ENV "PKCS11SLOTID"

int p11_module_init(struct p11ctx *ctx)
{
    char *so_handle_str, *slotid_str, *ptr;
    CK_C_GetFunctionList get_fn;
    CK_FUNCTION_LIST *fn;
    CK_SLOT_ID slotid;
    void *so_handle;
    CK_RV rv;

    so_handle_str = getenv(P11MODULE_ENV);
    if (so_handle_str == NULL || *so_handle_str == '\0')
        goto err;

    so_handle = dlopen(so_handle_str, RTLD_NOW);
    if (so_handle == NULL)
        goto err;

    *(void **)(&get_fn) = dlsym(so_handle, "C_GetFunctionList");
    if (get_fn == NULL)
        goto err;

    rv = get_fn(&fn);
    if (rv != CKR_OK)
        goto err;

    slotid_str = getenv(P11SLOTID_ENV);
    if (slotid_str == NULL || *slotid_str == '\0')
        goto err;

    slotid = strtoul(slotid_str, &ptr, 0);
    if (*ptr != '\0')
        goto err;

    ctx->so_handle = so_handle;
    ctx->fn = fn;
    ctx->slotid = slotid;
    return 1;
err:
    if (so_handle != NULL) {
        dlclose(so_handle);
        so_handle = NULL;
    }
    return 0;
}

void p11_module_fini(struct p11ctx *ctx)
{
    dlclose(ctx->so_handle);
    ctx->so_handle = NULL;
}
