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

#include <string.h>
#include <stdlib.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define UNUSED(var) (void)(var)

static const OSSL_PARAM *p11_gettable_params(const OSSL_PROVIDER *prov)
{
    static const OSSL_PARAM p11_param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };

    UNUSED(prov);

    return p11_param_types;
}

static int p11_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    UNUSED(prov);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL PKCS11 provider"))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *p11_query(OSSL_PROVIDER *prov,
                                       int operation_id,
                                       int *no_cache)
{
    UNUSED(prov);

    *no_cache = 0;

    switch (operation_id) {
    }

    return NULL;
}

/*
 * The provider initialization function of fixed name and signature must be
 * exported. Returns 1 if successful. Otherwise, 0 is returned.
 */
int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    static const OSSL_DISPATCH p11_dispatch_table[] = {
        {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))p11_gettable_params},
        {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p11_get_params},
        {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p11_query},
        {0, NULL}
    };

    UNUSED(in);

    *out = p11_dispatch_table;
    *provctx = (void *)provider;
    return 1;
}
