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

#ifndef P11_PROVCTX_H
# define P11_PROVCTX_H

# ifndef CK_PTR
#  define CK_PTR *
# endif

# ifndef CK_DECLARE_FUNCTION
#  define CK_DECLARE_FUNCTION(returnType, name) \
       returnType name
# endif

# ifndef CK_DECLARE_FUNCTION_POINTER
#  define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
       returnType (CK_PTR name)
# endif

# ifndef CK_CALLBACK_FUNCTION
#  define CK_CALLBACK_FUNCTION(returnType, name) \
       returnType (CK_PTR name)
# endif

# ifndef NULL_PTR
#  include <stddef.h> /* provides NULL */
#  define NULL_PTR NULL
# endif

# ifndef PKCS11UNPACKED /* for PKCS11 modules that dont pack */
#  pragma pack(push, 1)
# endif
# include "pkcs11.h" /* official PKCS11 3.0 header */
# ifndef PKCS11UNPACKED
#  pragma pack(pop)
# endif

# include <openssl/core.h>
# include <openssl/core_names.h>
# include <openssl/core_numbers.h>

# define UNUSED(var) (void)(var)

struct provctx {
    const OSSL_PROVIDER *provider;
    OPENSSL_CTX *libctx;

    /* default core params */
    char *openssl_version;
    char *provider_name;
    char *module_filename;
    char *module;
    /* custom core params */
    char *pkcs11module;
    char *pkcs11slotid;
    char *pkcs11userpin;

    /* pkcs11 module data */
    void *so_handle;
    CK_FUNCTION_LIST *fn;
    CK_SLOT_ID slotid;
    CK_MECHANISM_TYPE *mechlist;
    CK_MECHANISM_INFO *mechinfo;
    CK_ULONG mechcount;
    CK_SESSION_HANDLE session;

    /* operation dispatch tables */
    OSSL_ALGORITHM *digest;
    OSSL_ALGORITHM *cipher;
    OSSL_ALGORITHM *mac;
    OSSL_ALGORITHM *kdf;
    OSSL_ALGORITHM *keymgmt;
    OSSL_ALGORITHM *keyexch;
    OSSL_ALGORITHM *signature;
    OSSL_ALGORITHM *asym_cipher;
    OSSL_ALGORITHM *serializer;

   /* functions offered by libcrypto to the providers */
#define CORE_FN_PTR(name) OSSL_##name##_fn *name
    CORE_FN_PTR(core_gettable_params);
    CORE_FN_PTR(core_get_params);
    CORE_FN_PTR(core_thread_start);
    CORE_FN_PTR(core_get_library_context);
    CORE_FN_PTR(core_new_error);
    CORE_FN_PTR(core_set_error_debug);
    CORE_FN_PTR(core_vset_error);
    CORE_FN_PTR(core_set_error_mark);
    CORE_FN_PTR(core_clear_last_error_mark);
    CORE_FN_PTR(core_pop_error_to_mark);
    CORE_FN_PTR(CRYPTO_malloc);
    CORE_FN_PTR(CRYPTO_zalloc);
    CORE_FN_PTR(CRYPTO_free);
    CORE_FN_PTR(CRYPTO_clear_free);
    CORE_FN_PTR(CRYPTO_realloc);
    CORE_FN_PTR(CRYPTO_clear_realloc);
    CORE_FN_PTR(CRYPTO_secure_malloc);
    CORE_FN_PTR(CRYPTO_secure_zalloc);
    CORE_FN_PTR(CRYPTO_secure_free);
    CORE_FN_PTR(CRYPTO_secure_clear_free);
    CORE_FN_PTR(CRYPTO_secure_allocated);
    CORE_FN_PTR(OPENSSL_cleanse);
    CORE_FN_PTR(BIO_new_file);
    CORE_FN_PTR(BIO_new_membuf);
    CORE_FN_PTR(BIO_read_ex);
    CORE_FN_PTR(BIO_free);
    CORE_FN_PTR(BIO_vprintf);
    CORE_FN_PTR(self_test_cb);
#undef CORE_FN
};

#endif
