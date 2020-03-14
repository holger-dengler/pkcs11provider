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

#include "tables.h"

int tables_create(struct provctx *ctx)
{
    assert(ctx != NULL);

    ctx->digest = NULL;
    ctx->cipher = NULL;
    ctx->mac = NULL;
    ctx->kdf = NULL;
    ctx->keymgmt = NULL;
    ctx->keyexch = NULL;
    ctx->signature = NULL;
    ctx->asym_cipher = NULL;
    ctx->serializer = NULL;
    return 1;
}

void tables_destroy(struct provctx *ctx)
{
    assert(ctx != NULL);

    free(ctx->digest);
    free(ctx->cipher);
    free(ctx->mac);
    free(ctx->kdf);
    free(ctx->keymgmt);
    free(ctx->keyexch);
    free(ctx->signature);
    free(ctx->asym_cipher);
    free(ctx->serializer);
    ctx->digest = NULL;
    ctx->cipher = NULL;
    ctx->mac = NULL;
    ctx->kdf = NULL;
    ctx->keymgmt = NULL;
    ctx->keyexch = NULL;
    ctx->signature = NULL;
    ctx->asym_cipher = NULL;
    ctx->serializer = NULL;
}
