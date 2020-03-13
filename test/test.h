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

#ifndef TEST_H
#define TEST_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define UNUSED(x) (void)(x)

/* Write test output to .. */
#define TEST_STREAM stderr

/* Testdriver exist status */
#define TEST_SUCC  0
#define TEST_FAIL  1
#define TEST_SKIP 77
#define TEST_ERR  99

void test_entry(int, char *[]);
void test_exit(int);

#define TEST_ENTRY(argc, argv)      \
    test_entry((argc), (argv))

#define TEST_PRINT(fmt, ...)                                  \
    fprintf(TEST_STREAM, fmt, __VA_ARGS__)

#define TEST_EXIT_SUCC()                                      \
do {                                                          \
    fprintf(TEST_STREAM, "PASS\n");                           \
    test_exit(TEST_SUCC);                                     \
} while (0)

#define TEST_EXIT_FAIL()                                      \
do {                                                          \
    fprintf(TEST_STREAM, "FAIL (%s at %s:%d)\n",              \
            __func__, __FILE__, __LINE__);                    \
    test_exit(TEST_FAIL);                                     \
} while (0)

#define TEST_EXIT_FAIL_MSG(fmt, ...)                          \
do {                                                          \
    fprintf(TEST_STREAM, "FAIL (%s at %s:%d): " fmt ".\n",    \
            __func__, __FILE__, __LINE__, __VA_ARGS__);       \
    test_exit(TEST_FAIL);                                     \
} while (0)

#define TEST_EXIT_SKIP()                                      \
do {                                                          \
    fprintf(TEST_STREAM, "SKIP (%s at %s:%d)\n",              \
            __func__, __FILE__, __LINE__);                    \
    test_exit(TEST_SKIP);                                     \
} while (0)

#define TEST_EXIT_SKIP_MSG(fmt, ...)                          \
do {                                                          \
    fprintf(TEST_STREAM, "SKIP (%s at %s:%d): " fmt ".\n",    \
            __func__, __FILE__, __LINE__, __VA_ARGS__);       \
    test_exit(TEST_SKIP);                                     \
} while (0)

#define TEST_EXIT_ERR()                                       \
do {                                                          \
    fprintf(TEST_STREAM, "ERROR (%s at %s:%d)\n",             \
            __func__, __FILE__, __LINE__);                    \
    test_exit(TEST_ERR);                                      \
} while (0)

#define TEST_EXIT_ERR_MSG(fmt, ...)                           \
do {                                                          \
    fprintf(TEST_STREAM, "ERROR (%s at %s:%d): " fmt ".\n",   \
            __func__, __FILE__, __LINE__, __VA_ARGS__);       \
    test_exit(TEST_FAIL);                                     \
} while (0)

#endif
