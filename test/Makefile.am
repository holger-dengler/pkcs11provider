EXTRA_DIST = testenv.sh

AM_TESTS_ENVIRONMENT = . ${top_srcdir}/test/testenv.sh; \
    export OPENSSL_MODULES=${top_builddir}/src/.libs; \
    export LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:@OPENSSL_RPATH@;

LDADD = @OPENSSL_LIBS@ -lpthread
AM_LDFLAGS = @OPENSSL_LDFLAGS@

TESTS = \
    provider_api

noinst_PROGRAMS = \
    provider_api

provider_api_SOURCES = test.h test.c provider_api.c
