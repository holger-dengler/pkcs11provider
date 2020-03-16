AM_TESTS_ENVIRONMENT = export OPENSSL_MODULES=${top_builddir}/src/.libs; \
    export OPENSSL_CONF=${top_builddir}/test/openssl.conf; \
    export LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:@OPENSSL_RPATH@;

LDADD = @OPENSSL_LIBS@
AM_LDFLAGS = @OPENSSL_LDFLAGS@
AM_CFLAGS = -pthread

TESTS = \
    provider_api \
    thread_multi

noinst_PROGRAMS = \
    provider_api \
    thread_multi

provider_api_SOURCES = test.h test.c provider_api.c
thread_multi_SOURCES = test.h test.c thread_multi.c
