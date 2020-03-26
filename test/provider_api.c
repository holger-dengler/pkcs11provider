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
 * Some simple tests using the OSSL_PROVIDER interface (provider.h).
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "test.h"

int main(int argc, char *argv[])
{
    const OSSL_PARAM *gettable_params;
    OSSL_PARAM get_param[3];
    OSSL_PROVIDER *prov;
    const char *str, *data[2] = {NULL, NULL};
    int rc, i;

    TEST_ENTRY(argc, argv);

    /* load */

    prov = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (prov == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_load returned NULL");

    /* available */

    rc = OSSL_PROVIDER_available(NULL, "pkcs11");
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_available returned %d", rc);

    /* name */

    str = OSSL_PROVIDER_name(prov);
    if (str == NULL)
        TEST_EXIT_FAIL_MSG("%s", "OSSL_PROVIDER_name returned NULL");

    fprintf(TEST_STREAM, "provider : %s\n", str);

    if (strcmp(str, "pkcs11") != 0)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_name returned \"%s\"", str);

    /* gettable params */

    gettable_params = OSSL_PROVIDER_gettable_params(prov);
    if (gettable_params == NULL) {
        TEST_EXIT_FAIL_MSG("%s",
                           "OSSL_PROVIDER_gettable_params returned NULL");
    }
    fprintf(TEST_STREAM, "parameters :");
    for (i = 0; gettable_params[i].key != NULL; i++)
        fprintf(TEST_STREAM, " %s", gettable_params[i].key);
    fprintf(TEST_STREAM, "\n");

    /* get params */

    get_param[0].key = OSSL_PROV_PARAM_NAME;
    get_param[0].data_type = OSSL_PARAM_UTF8_PTR;
    get_param[0].data = &data[0];
    get_param[0].data_size = 0;
    get_param[0].return_size = 0;

    get_param[1].key = OSSL_PROV_PARAM_VERSION;
    get_param[1].data_type = OSSL_PARAM_UTF8_PTR;
    get_param[1].data = &data[1];
    get_param[1].data_size = 0;
    get_param[1].return_size = 0;

    get_param[2].key = NULL; /* last array element */

    rc = OSSL_PROVIDER_get_params(prov, get_param);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_get_params returned %d", rc);

    fprintf(TEST_STREAM, "%s : %s\n",
            OSSL_PROV_PARAM_NAME, (char *)get_param[0].data);
    fprintf(TEST_STREAM, "%s : %s\n",
            OSSL_PROV_PARAM_VERSION, (char *)get_param[1].data);

    if (strcmp(data[0], "pkcs11") != 0)
        TEST_EXIT_FAIL();
    
    /* unload */

    rc = OSSL_PROVIDER_unload(prov);
    if (rc != 1)
        TEST_EXIT_FAIL_MSG("OSSL_PROVIDER_unload returned %d", rc);

    TEST_EXIT_SUCC();
}
