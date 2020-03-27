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
#include <stdlib.h>
#include <string.h>

#include <openssl/params.h> /*XXX will eventually be provided by the core*/

#include "rsa.h"

/* required functions */
static OSSL_OP_keymgmt_gen_init_fn rsa_keymgmt_gen_init;
static OSSL_OP_keymgmt_gen_fn rsa_keymgmt_gen;
static OSSL_OP_keymgmt_gen_cleanup_fn rsa_keymgmt_gen_cleanup;
static OSSL_OP_keymgmt_free_fn rsa_keymgmt_free;
static OSSL_OP_keymgmt_has_fn rsa_keymgmt_has;
/* additional functions */
static OSSL_OP_keymgmt_get_params_fn rsa_keymgmt_get_params;
static OSSL_OP_keymgmt_gettable_params_fn rsa_keymgmt_gettable_params;
static OSSL_OP_keymgmt_gen_settable_params_fn rsa_keymgmt_gen_settable_params;
static OSSL_OP_keymgmt_gen_set_params_fn rsa_keymgmt_gen_set_params;

struct rsa_genctx {
    struct provctx *provctx;
    CK_ULONG modulus_bits;
    CK_BYTE *public_exponent;
    CK_ULONG public_exponentlen;
    CK_MECHANISM_TYPE mech;
};

struct rsa_keydata {
    struct rsa_genctx genctx;
    CK_OBJECT_HANDLE priv;
    CK_OBJECT_HANDLE pub;
};

const OSSL_DISPATCH *rsa_keymgmt(const struct provctx *ctx)
{
    static const OSSL_DISPATCH rsa_keymgmt_tbl[] = {
        /*
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_keymgmt_new},
        */
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))rsa_keymgmt_gen_init},
        /*
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, 
            (void (*)(void))rsa_keymgmt_gen_set_template},
        */
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))rsa_keymgmt_gen_set_params},
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))rsa_keymgmt_gen_settable_params},
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_keymgmt_gen},
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
            (void (*)(void))rsa_keymgmt_gen_cleanup},
        /*
        */
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_keymgmt_free},
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))rsa_keymgmt_get_params},
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*)(void))rsa_keymgmt_gettable_params},
        /*
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

    assert(ctx != NULL);

    if (ctx->rsakeygen[0].avail == 1)
        return rsa_keymgmt_tbl;

    return NULL;
}

static void *rsa_keymgmt_gen_init(void *provctx, int selection)
{
    static const CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};
    struct provctx *ctx = provctx;
    struct rsa_genctx *genctx;
    CK_ULONG idx;

    assert(provctx != NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    genctx = calloc(1, sizeof(*genctx));
    if (genctx == NULL)
        return NULL;

    genctx->public_exponentlen = sizeof(public_exponent);

    genctx->public_exponent = calloc(1, genctx->public_exponentlen);
    if (genctx->public_exponent == NULL)
        return NULL;

    idx = ctx->rsakeygen[0].idx;
    memcpy(genctx->public_exponent,
           public_exponent, genctx->public_exponentlen);
    genctx->modulus_bits = 2048;
    genctx->provctx = provctx;
    genctx->mech = ctx->mechlist[idx];
    return genctx;
}

static void *rsa_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    struct rsa_genctx *ctx = genctx;
    struct rsa_keydata *key = NULL;

    UNUSED(cb);
    UNUSED(cbarg);
    assert(genctx != NULL);

    CK_MECHANISM_TYPE mechtype = ctx->mech;
    CK_MECHANISM mech = {mechtype, NULL, 0};
    CK_BBOOL flag_token = ctx->provctx->tokobjs;
    CK_BBOOL flag_true = CK_TRUE;
    CK_RV rv;

    CK_ATTRIBUTE pub_templ[] = {
        /* Common storage object attributes */
        {CKA_TOKEN, &flag_token, sizeof(flag_token)},
        /* Common public key attributes */
        {CKA_ENCRYPT, &flag_true, sizeof(flag_true)},
        {CKA_VERIFY, &flag_true, sizeof(flag_true)},
        {CKA_WRAP, &flag_true, sizeof(flag_true)},
        /* RSA public key object attributes  */
        {CKA_MODULUS_BITS,
         &ctx->modulus_bits, sizeof(ctx->modulus_bits)}, /* required */
        {CKA_PUBLIC_EXPONENT,
         ctx->public_exponent, ctx->public_exponentlen}
    };
    CK_ATTRIBUTE priv_templ[] = {
        /* Common storage object attributes */
        {CKA_TOKEN, &flag_token, sizeof(flag_token)},
        {CKA_PRIVATE, &flag_true, sizeof(flag_true)},
        /* Common private key attributes */
        {CKA_SENSITIVE, &flag_true, sizeof(flag_true)},
        {CKA_DECRYPT, &flag_true, sizeof(flag_true)},
        {CKA_SIGN, &flag_true, sizeof(flag_true)},
        {CKA_UNWRAP, &flag_true, sizeof(flag_true)},
    };

    key = calloc(1, sizeof(*key));
    if (key == NULL)
        goto err;

    key->genctx.public_exponent = calloc(1, ctx->public_exponentlen);
    if (key->genctx.public_exponent == NULL)
        goto err;
    memcpy(key->genctx.public_exponent,
           ctx->public_exponent, ctx->public_exponentlen);
    key->genctx.provctx = ctx->provctx;
    key->genctx.modulus_bits = ctx->modulus_bits;
    key->genctx.public_exponentlen = ctx->public_exponentlen;
    key->genctx.mech = ctx->mech;

    rv = ctx->provctx->fn->C_GenerateKeyPair(ctx->provctx->session, &mech,
                                             pub_templ, NMEMB(pub_templ),
                                             priv_templ, NMEMB(priv_templ),
                                             &key->pub, &key->priv);
    if (rv != CKR_OK)
        goto err;

    return key;
err:
    free(key);
    return NULL;
}

static void rsa_keymgmt_gen_cleanup(void *genctx)
{
    struct rsa_genctx *ctx = genctx;

    assert(genctx != NULL);

    free(ctx->public_exponent);
    free(ctx);
}

static void rsa_keymgmt_free(void *keydata)
{
    struct rsa_keydata *key = keydata;
    struct provctx *ctx;

    if (key == NULL)
        return;

    ctx = key->genctx.provctx;

    (void)ctx->fn->C_DestroyObject(ctx->session, key->priv);
    (void)ctx->fn->C_DestroyObject(ctx->session, key->pub);
    free(key);
}

static int rsa_keymgmt_has(void *keydata, int selection)
{
    struct rsa_keydata *key = keydata;
    int ok = 0;

    assert(keydata != NULL);

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                      | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && 0;     /* XXX will change with PSS and OAEP */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE)
                && (key->priv != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key->priv != CK_INVALID_HANDLE);

    return ok;
}

static int rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    struct rsa_keydata *key = keydata;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, key->genctx.modulus_bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, (key->genctx.modulus_bits + 7) / 8))
        return 0;
# if 0  /* XXX PSS */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
       ) {
    }
#endif
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
            ) {
        if (!OSSL_PARAM_set_utf8_string(p, "SHA256")) /* XXX PSS */
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *rsa_keymgmt_gettable_params(void)
{
    static const OSSL_PARAM rsa_keymgmt_gettable_params_tbl[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return rsa_keymgmt_gettable_params_tbl;
}

static const OSSL_PARAM *rsa_keymgmt_gen_settable_params(void *provctx)
{
    static const OSSL_PARAM rsa_keymgmt_gen_settable_params_tbl[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    UNUSED(provctx);
    return rsa_keymgmt_gen_settable_params_tbl;
}

static int rsa_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct rsa_genctx *ctx = genctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        CK_ULONG bits, i, idx;
	int avail, rc;

        rc = OSSL_PARAM_get_size_t(p, &bits);
	if (rc != 1)
           return 0;

        for (i = 0; i < NMEMB(ctx->provctx->rsakeygen); i++) {
            avail = ctx->provctx->rsakeygen[i].avail;
            idx = ctx->provctx->rsakeygen[i].idx;

	    if (avail == 1
                && bits >= ctx->provctx->mechinfo[idx].ulMinKeySize
                && bits <= ctx->provctx->mechinfo[idx].ulMaxKeySize)
                break;
        }
	if (i == NMEMB(ctx->provctx->rsakeygen))
            return 0;

	ctx->mech = ctx->provctx->mechlist[idx];
	ctx->modulus_bits = bits;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
        const union {
            long one;
            char little;
        } is_endian = { 1 };
        unsigned char *buf = p->data;
        size_t buflen = p->data_size;

	if (is_endian.little == 1) {
            /* skip trainling zeros */
            for (buf += p->data_size - 1;
                 *buf == 0 && buflen > 0; buf--, buflen--)
                ;
            buf = p->data;
	} else {
            /* skip leading zeros */
            for (buf = p->data; *buf == 0 && buflen > 0; buf++, buflen--)
                ;
	}

	ctx->public_exponentlen = buflen;
	ctx->public_exponent = realloc(ctx->public_exponent, buflen);
	if (ctx->public_exponent == NULL)
            return 0;

	if (is_endian.little == 1) {
            size_t i;

            for (i = 0; i < buflen; i++) {
                ctx->public_exponent[i] = buf[buflen - 1 - i];
            }
	} else {
            memcpy(ctx->public_exponent, buf, buflen);
	}
    }
    return 1;
}
