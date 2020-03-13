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

/*
 * Some multi-threading tests.
 */

#include <errno.h>
#include <pthread.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "test.h"

#define THREADS 1024
#define TESTS   3

static void *dedicated_ctx_dedicated_prov(void *);
static void *shared_ctx_dedicated_prov(void *);
static void *shared_ctx_shared_prov(void *);

static void use_provider(OPENSSL_CTX *, OSSL_PROVIDER *);

int main(int argc, char *argv[])
{
    pthread_t threads[TESTS * THREADS];
    OSSL_PROVIDER *prov;
    int i, rc;

    TEST_ENTRY(argc, argv);

    prov = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (prov == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_load returned NULL");

    for (i = 0; i < 1 * THREADS; i++) {
        while((rc = pthread_create(&threads[i], NULL,
                                   dedicated_ctx_dedicated_prov,
                                   NULL)) == EAGAIN) {
            if (rc != 0)
                TEST_EXIT_FAIL_MSG("%s", "pthread_create failed");
        }
    }

    for (i = 1 * THREADS; i < 2 * THREADS; i++) {
        while((rc = pthread_create(&threads[i], NULL,
                                   shared_ctx_dedicated_prov,
                                   NULL)) == EAGAIN) {
            if (rc != 0)
                TEST_EXIT_FAIL_MSG("%s", "pthread_create failed");
        }
    }
    for (i = 2 * THREADS; i < 3 * THREADS; i++) {
        while((rc = pthread_create(&threads[i], NULL,
                                   shared_ctx_shared_prov,
                                   prov)) == EAGAIN) {
            if (rc != 0)
                TEST_EXIT_FAIL_MSG("%s", "pthread_create failed");
        }
    }

    for (i = 0; i < TESTS * THREADS; i++) {
        rc = pthread_join(threads[i], NULL);
        if (rc != 0)
            TEST_EXIT_FAIL_MSG("%s", "pthread_join failed.");
    }

    rc = OSSL_PROVIDER_unload(prov);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_unload returned %d", rc);

    TEST_EXIT_SUCC();
}

/*
 * Each thread has its own library context object
 * with an associated provider opbject.
 */
static void *dedicated_ctx_dedicated_prov(void *arg)
{
    OSSL_PROVIDER *prov;
    OPENSSL_CTX *ctx;
    int rc;

    UNUSED(arg);

    ctx = OPENSSL_CTX_new();
    if (ctx == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OPENSSL_CTX_new returned NULL");

    prov = OSSL_PROVIDER_load(ctx, "pkcs11");
    if (prov == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_load returned NULL");

    use_provider(ctx, prov);

    rc = OSSL_PROVIDER_unload(prov);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_unload returned %d", rc);

    OPENSSL_CTX_free(ctx);
    return NULL;
}

/*
 * The threads share the default library context object
 * but each thread has its own associated provider object.
 */
static void *shared_ctx_dedicated_prov(void *arg)
{
    OSSL_PROVIDER *prov;
    int rc;

    UNUSED(arg);

    prov = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (prov == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_load returned NULL");

    use_provider(NULL, prov);

    rc = OSSL_PROVIDER_unload(prov);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_unload returned %d", rc);

    return NULL;
}

/*
 * The threads share the default library context object
 * and the associated provider object.
 */
static void *shared_ctx_shared_prov(void *arg)
{
    use_provider(NULL, arg);
    return NULL;
}

static void use_provider(OPENSSL_CTX *ctx, OSSL_PROVIDER *prov)
{
    const OSSL_PARAM *gettable_params;
    OSSL_PARAM get_param[3];
    const char *str;
    int rc;

    /* available */

    rc = OSSL_PROVIDER_available(ctx, "pkcs11");
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_available returned %d", rc);

    /* name */

    str = OSSL_PROVIDER_name(prov);
    if (str == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_name returned NULL");

    if (strcmp(str, "pkcs11") != 0)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_name returned \"%s\"", str);

    /* gettable params */

    gettable_params = OSSL_PROVIDER_gettable_params(prov);
    if (gettable_params == NULL) {
        TEST_EXIT_FAIL_MSG("%s",
			   "OSSL_PROVIDER_gettable_params returned NULL");
    }

    /* get params */

    get_param[0].key = OSSL_PROV_PARAM_NAME;
    get_param[0].data_type = OSSL_PARAM_UTF8_PTR;
    get_param[0].data = NULL;
    get_param[0].data_size = 0;
    get_param[0].return_size = 0;

    get_param[1].key = OSSL_PROV_PARAM_VERSION;
    get_param[1].data_type = OSSL_PARAM_UTF8_PTR;
    get_param[1].data = NULL;
    get_param[1].data_size = 0;
    get_param[1].return_size = 0;

    get_param[2].key = NULL; /* last array element */

    rc = OSSL_PROVIDER_get_params(prov, get_param);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_get_params returned %d", rc);
}
