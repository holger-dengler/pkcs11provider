nobase_lib_LTLIBRARIES = \
    pkcs11.la

pkcs11_la_LDFLAGS = \
    -avoid-version -module -share \
    -Wl,--version-script=${srcdir}/provider.map \
    -version-number @VERSION_MAJOR@:@VERSION_MINOR@:@VERSION_PATCH@

pkcs11_la_CFLAGS = \
    $(OPENSSL_INCLUDES)

pkcs11_la_SOURCES = \
    p11_init.c

EXTRA_DIST = \
    provider.map
