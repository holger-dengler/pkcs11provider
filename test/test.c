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

#include "test.h"

void test_entry(int argc, char *argv[])
{
    char *testname;

    UNUSED(argc);

    assert(argc >  0);
    assert(argv != NULL);

    testname = strrchr(argv[0], '/');
    if (testname == NULL)
        TEST_EXIT_ERR();
    fprintf(TEST_STREAM, "Test: %s\n", testname + 1);
}

void test_exit(int rv)
{
    exit(rv);
}
