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
