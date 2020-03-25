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

#include "rsa.h"
#include "tables.h"

#define DECLARE_TBL(name)                             \
static int __tbl_##name##_create(struct provctx *);   \
static void __tbl_##name##_destroy(struct provctx *);
DECLARE_TBL(digest)
DECLARE_TBL(cipher)
DECLARE_TBL(mac)
DECLARE_TBL(kdf)
DECLARE_TBL(keymgmt)
DECLARE_TBL(keyexch)
DECLARE_TBL(signature)
DECLARE_TBL(asym_cipher)
DECLARE_TBL(serializer)
#undef DECLARE_TBL

int tables_create(struct provctx *ctx)
{
    assert(ctx != NULL);

    if (__tbl_digest_create(ctx) != 1
        || __tbl_cipher_create(ctx) != 1
        || __tbl_mac_create(ctx) != 1
        || __tbl_kdf_create(ctx) != 1
        || __tbl_keymgmt_create(ctx) != 1
        || __tbl_keyexch_create(ctx) != 1
        || __tbl_signature_create(ctx) != 1
        || __tbl_asym_cipher_create(ctx) != 1
        || __tbl_serializer_create(ctx) != 1)
        return 0;

    return 1;
}

void tables_destroy(struct provctx *ctx)
{
    assert(ctx != NULL);

    __tbl_digest_destroy(ctx);
    __tbl_cipher_destroy(ctx);
    __tbl_mac_destroy(ctx);
    __tbl_kdf_destroy(ctx);
    __tbl_keymgmt_destroy(ctx);
    __tbl_keyexch_destroy(ctx);
    __tbl_signature_destroy(ctx);
    __tbl_asym_cipher_destroy(ctx);
    __tbl_serializer_destroy(ctx);
}

#define DEFINE_TBL_UNIMPLEMENTED(name)                  \
static int __tbl_##name##_create(struct provctx *ctx)   \
{                                                       \
    assert(ctx != NULL);                                \
    ctx->name = NULL;                                   \
    return 1;                                           \
}                                                       \
static void __tbl_##name##_destroy(struct provctx *ctx) \
{                                                       \
    assert(ctx != NULL);                                \
}
DEFINE_TBL_UNIMPLEMENTED(digest)
DEFINE_TBL_UNIMPLEMENTED(cipher)
DEFINE_TBL_UNIMPLEMENTED(mac)
DEFINE_TBL_UNIMPLEMENTED(kdf)
DEFINE_TBL_UNIMPLEMENTED(keyexch)
DEFINE_TBL_UNIMPLEMENTED(signature)
DEFINE_TBL_UNIMPLEMENTED(asym_cipher)
DEFINE_TBL_UNIMPLEMENTED(serializer)
#undef DEFINE_TBL_UNIMPLEMENTED


static int __tbl_keymgmt_create(struct provctx *ctx)
{
    OSSL_ALGORITHM *tbl = NULL;
    int idx = 0;

    tbl = calloc(2, sizeof(*tbl));
    if (tbl == NULL)
        return 0;

    if (rsa_available(ctx) == 1) {
        tbl[idx].algorithm_names = "RSA:rsaEncryption";
        tbl[idx].property_definition = "provider=pkcs11";
        tbl[idx].implementation = rsa_keymgmt();
	idx++;
    }

    tbl[idx].algorithm_names = NULL; /* last list element */
    ctx->keymgmt = tbl;
    return 1;
}

static void __tbl_keymgmt_destroy(struct provctx *ctx)
{
    assert(ctx != NULL);

    free(ctx->keymgmt);
    ctx->keymgmt = NULL;
}
