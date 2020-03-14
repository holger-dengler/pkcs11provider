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

#include "rsa.h"

static OSSL_OP_keymgmt_gen_init_fn rsa_keymgmt_gen_init;
static OSSL_OP_keymgmt_gen_fn rsa_keymgmt_gen;
static OSSL_OP_keymgmt_gen_cleanup_fn rsa_keymgmt_gen_cleanup;
static OSSL_OP_keymgmt_free_fn rsa_keymgmt_free;
static OSSL_OP_keymgmt_has_fn rsa_keymgmt_has;

int rsa_available(const struct provctx *ctx)
{
    UNUSED(ctx);
    return 1;
}

const OSSL_DISPATCH *rsa_keymgmt(void)
{
    static const OSSL_DISPATCH rsa_keymgmt_tbl[] = {
        /*
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_keymgmt_new},
        */
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))rsa_keymgmt_gen_init},
        /*
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, 
            (void (*)(void))rsa_keymgmt_gen_set_template},
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))rsa_keymgmt_gen_set_params},
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))rsa_keymgmt_gen_settable_params},
        */
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_keymgmt_gen},
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
            (void (*)(void))rsa_keymgmt_gen_cleanup},
        /*
        */
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_keymgmt_free},
        /*
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))rsa_keymgmt_get_params},
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*)(void))rsa_keymgmt_gettable_params},
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))rsa_keymgmt_set_params},
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
            (void (*)(void))rsa_keymgmt_settable_params},
        {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
            (void (*)(void))rsa_keymgmt_query_operation_name},
        */
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))rsa_keymgmt_has},
        /*
        {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))rsa_keymgmt_validate},
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))rsa_keymgmt_match},
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))rsa_keymgmt_import},
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))TYPES, rsa_keymgmt_import_types},
        {OSSL_FUNC_KEYMGMT_EXPORT,
            (void (*)(void))rsa_keymgmt_export},
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))rsa_keymgmt_export_types},
        {OSSL_FUNC_KEYMGMT_COPY, (void (*)(void))rsa_keymgmt_copy},
	*/
        {0, NULL}
    };

    return rsa_keymgmt_tbl;
}

static void *rsa_keymgmt_gen_init(void *provctx, int selection)
{
    UNUSED(provctx);
    UNUSED(selection);
    return NULL;
}

static void *rsa_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    UNUSED(genctx);
    UNUSED(cb);
    UNUSED(cbarg);
    return NULL;
}

static void rsa_keymgmt_gen_cleanup(void *genctx)
{
    UNUSED(genctx);
}

static void rsa_keymgmt_free(void *keydata)
{
    UNUSED(keydata);
}

static int rsa_keymgmt_has(void *keydata, int selection)
{
    UNUSED(keydata);
    UNUSED(selection);
    return 1;
}
