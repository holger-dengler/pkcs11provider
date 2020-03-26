EXTRA_DIST = testenv.sh

AM_TESTS_ENVIRONMENT = . ${top_srcdir}/test/testenv.sh; \
    export OPENSSL_MODULES=${top_builddir}/src/.libs; \
    export OPENSSL_CONF=${top_builddir}/test/openssl.conf;
    export LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:@OPENSSL_RPATH@;

LDADD = @OPENSSL_LIBS@
AM_LDFLAGS = @OPENSSL_LDFLAGS@
AM_CPPFLAGS = @OPENSSL_INCLUDES@
AM_CFLAGS = -pthread

TESTS = \
    provider_api \
    thread_multi \
    rsa_signatures

noinst_PROGRAMS = \
    provider_api \
    thread_multi \
    rsa_signatures

provider_api_SOURCES = test.h test.c provider_api.c
thread_multi_SOURCES = test.h test.c thread_multi.c
rsa_signatures_SOURCES = test.h test.c rsa_signatures.c
