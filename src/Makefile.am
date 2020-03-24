AM_CFLAGS = -Wall -Werror

nobase_lib_LTLIBRARIES = \
    pkcs11.la

pkcs11_la_LDFLAGS = \
    -avoid-version -module -share \
    -Wl,--version-script=${srcdir}/provider.map \
    -version-number @VERSION_MAJOR@:@VERSION_MINOR@:@VERSION_PATCH@

pkcs11_la_CPPFLAGS = \
    @OPENSSL_INCLUDES@

pkcs11_la_CFLAGS = \
    $(AM_CFLAGS) \
    -pthread

pkcs11_la_SOURCES = \
    provider.c \
    tables.h tables.c \
    rsa.h rsa.c

EXTRA_DIST = \
    provider.map
