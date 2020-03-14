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
    CK_C_GetFunctionList get_functionlist;
    struct provctx *ctx = NULL;
    char *str;
    CK_RV rv;
    int rc;

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
    if (ctx->core_get_params == NULL)
        goto err;

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
            {"pkcs11module", OSSL_PARAM_UTF8_PTR, &ctx->pkcs11module, 0, 0},
            {"pkcs11slotid", OSSL_PARAM_UTF8_PTR, &ctx->pkcs11slotid, 0, 0},
            {NULL, 0, NULL, 0, 0}
        };

        rc = ctx->core_get_params(provider, core_params);
	if (rc != 1)
            goto err;
    }

    /*
     * If environment variables are set, they take precedence
     * over the corresponding config file parameters.
     */
    str = getenv("PKCS11MODULE");
    if (str != NULL && str[0] != '\0')
        ctx->pkcs11module = str;
    str = getenv("PKCS11SLOTID");
    if (str != NULL && str[0] != '\0')
        ctx->pkcs11slotid = str;

    ctx->so_handle = dlopen(ctx->pkcs11module, RTLD_NOW);
    if (ctx->so_handle == NULL)
        goto err;
    ctx->slotid = strtoul(ctx->pkcs11slotid, &str, 0);
    if (str[0] != '\0')
        goto err;

    /* Get pkcs11 module. entry point. */
    *(void **)(&get_functionlist) = dlsym(ctx->so_handle,
                                          "C_GetFunctionList");
    if (get_functionlist == NULL)
        goto err;
    rv = get_functionlist(&ctx->fn);
    if (rv != CKR_OK)
        goto err;

    /* Initialize pkcs11 module. */
    pthread_mutex_lock(&provider_init.mutex);
    if (provider_init.refcount == 0) {
        CK_C_INITIALIZE_ARGS initargs = {0};
        initargs.flags = CKF_OS_LOCKING_OK;

        rv = ctx->fn->C_Initialize(&initargs);
        if (rv == CKR_OK)
            provider_init.refcount = 1;
    } else {
        provider_init.refcount++;
    }
    pthread_mutex_unlock(&provider_init.mutex);
    if (rv != CKR_OK)
        goto err;

    /* Get the slot's mechanism list. */
    rv = ctx->fn->C_GetMechanismList(ctx->slotid, NULL, &ctx->mechcount);
    if (rv != CKR_OK)
        goto err;
    ctx->mechlist = calloc(ctx->mechcount, sizeof(*ctx->mechlist));
    if (ctx->mechlist == NULL)
        goto err;
    rv = ctx->fn->C_GetMechanismList(ctx->slotid,
                                     ctx->mechlist, &ctx->mechcount);
    if (rv != CKR_OK)
        goto err;

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
            /* XXX
            {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
                (void (*)(void))provider_get_reason_strings},
            */
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

    if (ctx == NULL)
        return;

    tables_destroy(ctx);

    if (ctx->mechlist != NULL) {
        free(ctx->mechlist);
        ctx->mechlist = NULL;
    }

    /* Finalize pkcs11 module. */
    pthread_mutex_lock(&provider_init.mutex);
    if (provider_init.refcount > 0) {
        provider_init.refcount--;

        if (provider_init.refcount == 0)
            ctx->fn->C_Finalize(NULL);
    }
    pthread_mutex_unlock(&provider_init.mutex);

    if (ctx->so_handle != NULL) {
        dlclose(ctx->so_handle);
        ctx->so_handle = NULL;
    }

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

    UNUSED(provctx);

    return gettable_params;
}

/*
 * provider_get_params() should process the OSSL_PARAM array params, setting
 * the values of the parameters it understands.
 */
static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    struct provctx *ctx = provctx;

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

    UNUSED(no_store);

    if (provctx == NULL)
        return NULL;

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
#define REASON_STRING(ckr) {ckr, #ckr}
        REASON_STRING(CKR_CANCEL),
        REASON_STRING(CKR_HOST_MEMORY),
        REASON_STRING(CKR_SLOT_ID_INVALID),
        REASON_STRING(CKR_GENERAL_ERROR),
        REASON_STRING(CKR_FUNCTION_FAILED),
        REASON_STRING(CKR_ARGUMENTS_BAD),
        REASON_STRING(CKR_NO_EVENT),
        REASON_STRING(CKR_NEED_TO_CREATE_THREADS),
        REASON_STRING(CKR_CANT_LOCK),
        REASON_STRING(CKR_ATTRIBUTE_READ_ONLY),
        REASON_STRING(CKR_ATTRIBUTE_SENSITIVE),
        REASON_STRING(CKR_ATTRIBUTE_TYPE_INVALID),
        REASON_STRING(CKR_ATTRIBUTE_VALUE_INVALID),
        REASON_STRING(CKR_ACTION_PROHIBITED),
        REASON_STRING(CKR_DATA_INVALID),
        REASON_STRING(CKR_DATA_LEN_RANGE),
        REASON_STRING(CKR_DEVICE_ERROR),
        REASON_STRING(CKR_DEVICE_MEMORY),
        REASON_STRING(CKR_DEVICE_REMOVED),
        REASON_STRING(CKR_ENCRYPTED_DATA_INVALID),
        REASON_STRING(CKR_ENCRYPTED_DATA_LEN_RANGE),
        REASON_STRING(CKR_AEAD_DECRYPT_FAILED),
        REASON_STRING(CKR_FUNCTION_CANCELED),
        REASON_STRING(CKR_FUNCTION_NOT_PARALLEL),
        REASON_STRING(CKR_FUNCTION_NOT_SUPPORTED),
        REASON_STRING(CKR_KEY_HANDLE_INVALID),
        REASON_STRING(CKR_KEY_SIZE_RANGE),
        REASON_STRING(CKR_KEY_TYPE_INCONSISTENT),
        REASON_STRING(CKR_KEY_NOT_NEEDED),
        REASON_STRING(CKR_KEY_CHANGED),
        REASON_STRING(CKR_KEY_NEEDED),
        REASON_STRING(CKR_KEY_INDIGESTIBLE),
        REASON_STRING(CKR_KEY_FUNCTION_NOT_PERMITTED),
        REASON_STRING(CKR_KEY_NOT_WRAPPABLE),
        REASON_STRING(CKR_KEY_UNEXTRACTABLE),
        REASON_STRING(CKR_MECHANISM_INVALID),
        REASON_STRING(CKR_MECHANISM_PARAM_INVALID),
        REASON_STRING(CKR_OBJECT_HANDLE_INVALID),
        REASON_STRING(CKR_OPERATION_ACTIVE),
        REASON_STRING(CKR_OPERATION_NOT_INITIALIZED),
        REASON_STRING(CKR_PIN_INCORRECT),
        REASON_STRING(CKR_PIN_INVALID),
        REASON_STRING(CKR_PIN_LEN_RANGE),
        REASON_STRING(CKR_PIN_EXPIRED),
        REASON_STRING(CKR_PIN_LOCKED),
        REASON_STRING(CKR_SESSION_CLOSED),
        REASON_STRING(CKR_SESSION_COUNT),
        REASON_STRING(CKR_SESSION_HANDLE_INVALID),
        REASON_STRING(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
        REASON_STRING(CKR_SESSION_READ_ONLY),
        REASON_STRING(CKR_SESSION_EXISTS),
        REASON_STRING(CKR_SESSION_READ_ONLY_EXISTS),
        REASON_STRING(CKR_SESSION_READ_WRITE_SO_EXISTS),
        REASON_STRING(CKR_SIGNATURE_INVALID),
        REASON_STRING(CKR_SIGNATURE_LEN_RANGE),
        REASON_STRING(CKR_TEMPLATE_INCOMPLETE),
        REASON_STRING(CKR_TEMPLATE_INCONSISTENT),
        REASON_STRING(CKR_TOKEN_NOT_PRESENT),
        REASON_STRING(CKR_TOKEN_NOT_RECOGNIZED),
        REASON_STRING(CKR_TOKEN_WRITE_PROTECTED),
        REASON_STRING(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
        REASON_STRING(CKR_UNWRAPPING_KEY_SIZE_RANGE),
        REASON_STRING(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
        REASON_STRING(CKR_USER_ALREADY_LOGGED_IN),
        REASON_STRING(CKR_USER_NOT_LOGGED_IN),
        REASON_STRING(CKR_USER_PIN_NOT_INITIALIZED),
        REASON_STRING(CKR_USER_TYPE_INVALID),
        REASON_STRING(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
        REASON_STRING(CKR_USER_TOO_MANY_TYPES),
        REASON_STRING(CKR_WRAPPED_KEY_INVALID),
        REASON_STRING(CKR_WRAPPED_KEY_LEN_RANGE),
        REASON_STRING(CKR_WRAPPING_KEY_HANDLE_INVALID),
        REASON_STRING(CKR_WRAPPING_KEY_SIZE_RANGE),
        REASON_STRING(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
        REASON_STRING(CKR_RANDOM_SEED_NOT_SUPPORTED),
        REASON_STRING(CKR_RANDOM_NO_RNG),
        REASON_STRING(CKR_DOMAIN_PARAMS_INVALID),
        REASON_STRING(CKR_CURVE_NOT_SUPPORTED),
        REASON_STRING(CKR_BUFFER_TOO_SMALL),
        REASON_STRING(CKR_SAVED_STATE_INVALID),
        REASON_STRING(CKR_INFORMATION_SENSITIVE),
        REASON_STRING(CKR_STATE_UNSAVEABLE),
        REASON_STRING(CKR_CRYPTOKI_NOT_INITIALIZED),
        REASON_STRING(CKR_CRYPTOKI_ALREADY_INITIALIZED),
        REASON_STRING(CKR_MUTEX_BAD),
        REASON_STRING(CKR_MUTEX_NOT_LOCKED),
        REASON_STRING(CKR_NEW_PIN_MODE),
        REASON_STRING(CKR_NEXT_OTP),
        REASON_STRING(CKR_EXCEEDED_MAX_ITERATIONS),
        REASON_STRING(CKR_FIPS_SELF_TEST_FAILED),
        REASON_STRING(CKR_LIBRARY_LOAD_FAILED),
        REASON_STRING(CKR_PIN_TOO_WEAK),
        REASON_STRING(CKR_PUBLIC_KEY_INVALID),
        REASON_STRING(CKR_FUNCTION_REJECTED),
        REASON_STRING(CKR_TOKEN_RESOURCE_EXCEEDED),
#undef REASON_STRING
        {0, NULL}
    };

    UNUSED(provctx);

    return reason_strings;
}
