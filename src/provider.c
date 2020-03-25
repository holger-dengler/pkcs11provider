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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "provctx.h"
#include "tables.h"

/* provider entry point (fixed name, exported) */
OSSL_provider_init_fn OSSL_provider_init;

/* functions offered by the provider to libcrypto */
#define PROVIDER_FN(name) static OSSL_##name##_fn name
PROVIDER_FN(provider_teardown);
PROVIDER_FN(provider_gettable_params);
PROVIDER_FN(provider_get_params);
PROVIDER_FN(provider_query_operation);
PROVIDER_FN(provider_get_reason_strings);
#undef PROVIDER_FN

/*
 * Provider global initialization mutex and refcount.
 * Used to serialize C_Initialize and C_Finalize calls: The pkcs11 module is
 * initialized when the first provider context is allocated and finalized when
 * the last provider context is freed. For details on pkcs11 multi-threading,
 * see [pkcs11 ug].
 */
struct {
    pthread_mutex_t mutex;
    unsigned int refcount;
} provider_init = {
    PTHREAD_MUTEX_INITIALIZER,
    0
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    struct provctx *ctx = NULL;
    int rc;

    assert(provider != NULL);
    assert(in != NULL);
    assert(out != NULL);
    assert(provctx != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        goto err;

    /* Save provider handle. */
    ctx->provider = provider;

    /* Get all core functions. */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
#define CASE(uname, lname)                     \
        case OSSL_FUNC_##uname:                \
            ctx->lname = OSSL_get_##lname(in); \
            break
	CASE(CORE_GETTABLE_PARAMS, core_gettable_params);
	CASE(CORE_GET_PARAMS, core_get_params);
	CASE(CORE_THREAD_START, core_thread_start);
	CASE(CORE_GET_LIBRARY_CONTEXT, core_get_library_context);
	CASE(CORE_NEW_ERROR, core_new_error);
	CASE(CORE_SET_ERROR_DEBUG, core_set_error_debug);
	CASE(CORE_VSET_ERROR, core_vset_error);
	CASE(CORE_SET_ERROR_MARK, core_set_error_mark);
	CASE(CORE_CLEAR_LAST_ERROR_MARK, core_clear_last_error_mark);
	CASE(CORE_POP_ERROR_TO_MARK, core_pop_error_to_mark);
	CASE(CRYPTO_MALLOC, CRYPTO_malloc);
	CASE(CRYPTO_ZALLOC, CRYPTO_zalloc);
	CASE(CRYPTO_FREE, CRYPTO_free);
	CASE(CRYPTO_CLEAR_FREE, CRYPTO_clear_free);
	CASE(CRYPTO_REALLOC, CRYPTO_realloc);
	CASE(CRYPTO_CLEAR_REALLOC, CRYPTO_clear_realloc);
	CASE(CRYPTO_SECURE_MALLOC, CRYPTO_secure_malloc);
	CASE(CRYPTO_SECURE_ZALLOC, CRYPTO_secure_zalloc);
	CASE(CRYPTO_SECURE_FREE, CRYPTO_secure_free);
	CASE(CRYPTO_SECURE_CLEAR_FREE, CRYPTO_secure_clear_free);
	CASE(CRYPTO_SECURE_ALLOCATED, CRYPTO_secure_allocated);
	CASE(OPENSSL_CLEANSE, OPENSSL_cleanse);
	CASE(BIO_NEW_FILE, BIO_new_file);
	CASE(BIO_NEW_MEMBUF, BIO_new_membuf);
	CASE(BIO_READ_EX, BIO_read_ex);
	CASE(BIO_FREE, BIO_free);
	CASE(BIO_VPRINTF, BIO_vprintf);
	CASE(SELF_TEST_CB, self_test_cb);
#undef CASE
        default:
            break;
        }
    }

    /* Check required core functions. */
    if (ctx->core_get_params == NULL
        || ctx->core_get_library_context == NULL)
        goto err;

    /* Save libctx handle. */
    ctx->libctx = ctx->core_get_library_context(provider);

    /* Get all core parameters. */
    {
        OSSL_PARAM core_params[] = {
            /* default params */
            {"openssl-version",
             OSSL_PARAM_UTF8_PTR, &ctx->openssl_version, 0, 0},
            {"provider-name", OSSL_PARAM_UTF8_PTR, &ctx->provider_name, 0, 0},
            {"module-filename",
             OSSL_PARAM_UTF8_PTR, &ctx->module_filename, 0, 0},
            {"module", OSSL_PARAM_UTF8_PTR, &ctx->module, 0, 0},
            /* custom params */
            {NULL, 0, NULL, 0, 0}
        };

        rc = ctx->core_get_params(provider, core_params);
	if (rc != 1)
            goto err;
    }

    /* Create operation dispatch tables. */
    rc = tables_create(ctx);
    if (rc != 1)
        goto err;

    /* Init successful. */
    {
        static const OSSL_DISPATCH provider_functions[] = {
            {OSSL_FUNC_PROVIDER_TEARDOWN,
                (void (*)(void))provider_teardown},
            {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
                (void (*)(void))provider_gettable_params},
            {OSSL_FUNC_PROVIDER_GET_PARAMS,
                (void (*)(void))provider_get_params},
            {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
                (void (*)(void))provider_query_operation},
            {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
                (void (*)(void))provider_get_reason_strings},
            {0, NULL}
        };
        *out = provider_functions;
    }
    *provctx = ctx;
    return 1;

err:/* Init failed. */
    provider_teardown(ctx);
    return 0;
}

/*
 * provider_teardown() is called when a provider is shut down and removed from
 * the core's provider store. It must free the passed provctx.
 */
static void provider_teardown(void *provctx)
{
    struct provctx *ctx = provctx;

    assert(provctx != NULL);

    tables_destroy(ctx);
    free(ctx);
}

/*
 * provider_gettable_params() should return a constant array of descriptor
 * OSSL_PARAM, for parameters that provider_get_params() can handle.
 */
static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable_params[] = {
        {OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
        {OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
        {NULL, 0, NULL, 0, 0}
    };

    assert(provctx != NULL);

    return gettable_params;
}

/*
 * provider_get_params() should process the OSSL_PARAM array params, setting
 * the values of the parameters it understands.
 */
static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    struct provctx *ctx = provctx;

    assert(provctx != NULL);
    assert(params != NULL);

    for (; params->key != NULL; params++) {
        if (strcmp(params->key, OSSL_PROV_PARAM_NAME) == 0) {
            if (params->data_type != OSSL_PARAM_UTF8_PTR)
                return 0;

	    params->data = ctx->provider_name;
            params->return_size = strlen(ctx->provider_name) + 1;
	    continue;
        }
        if (strcmp(params->key, OSSL_PROV_PARAM_VERSION) == 0) {
            if (params->data_type != OSSL_PARAM_UTF8_PTR)
                return 0;

	    params->data = VERSION;
            params->return_size = strlen(VERSION) + 1;
	    continue;
        }
    }

    return 1;
}

/*
 * provider_query_operation() should return a constant OSSL_ALGORITHM that
 * corresponds to the given operation_id. It should indicate if the core may
 * store a reference to this array by setting *no_store to 0 (core may store
 * a reference) or 1 (core may not store a reference).
 */
static const OSSL_ALGORITHM *provider_query_operation(void *provctx,
                                                      int operation_id,
                                                      const int *no_store)
{
    struct provctx *ctx = provctx;

    assert(provctx != NULL);
    assert(no_store != NULL);

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return ctx->digest;
    case OSSL_OP_CIPHER:
        return ctx->cipher;
    case OSSL_OP_MAC:
        return ctx->mac;
    case OSSL_OP_KDF:
        return ctx->kdf;
    case OSSL_OP_KEYMGMT:
        return ctx->keymgmt;
    case OSSL_OP_KEYEXCH:
        return ctx->keyexch;
    case OSSL_OP_SIGNATURE:
        return ctx->signature;
    case OSSL_OP_ASYM_CIPHER:
        return ctx->asym_cipher;
    case OSSL_OP_SERIALIZER:
        return ctx->serializer;
    default:
        break;
    }

    return NULL;
}

/*
 * provider_get_reason_strings() should return a constant OSSL_ITEM array that
 * provides reason strings for reason codes the provider may use when
 * reporting errors using core_put_error().
 */
static const OSSL_ITEM *provider_get_reason_strings(void *provctx)
{
    static const OSSL_ITEM reason_strings[] = {
#define REASON(X) {X, #X}
        REASON(1),
        REASON(2),
        REASON(3),
        REASON(4),
        REASON(5),
        REASON(6),
        REASON(7),
        REASON(8),
        REASON(9),
        REASON(10),
        REASON(11),
        REASON(12),
        REASON(13),
        REASON(14),
        REASON(15),
        REASON(16),
        REASON(17),
        REASON(18),
        REASON(19),
        REASON(20),
        REASON(21),
        REASON(22),
        REASON(23),
        REASON(24),
        REASON(25),
        REASON(26),
        REASON(27),
        REASON(28),
        REASON(29),
        REASON(30),
        REASON(31),
        REASON(32),
        REASON(33),
        REASON(34),
        REASON(35),
        REASON(36),
        REASON(37),
        REASON(38),
        REASON(39),
#undef REASON
        {0, NULL}
    };

    assert(provctx != NULL);

    return reason_strings;
}
