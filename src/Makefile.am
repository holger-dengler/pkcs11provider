nobase_lib_LTLIBRARIES = \
    pkcs11.la

pkcs11_la_LDFLAGS = \
    -avoid-version -module -share \
    -Wl,--version-script=${srcdir}/provider.map \
    -version-number @VERSION_MAJOR@:@VERSION_MINOR@:@VERSION_PATCH@

pkcs11_la_CFLAGS = \
    $(OPENSSL_INCLUDES)

pkcs11_la_SOURCES = \
    pkcs11.h \
    pkcs11t.h \
    pkcs11f.h \
    p11.h p11.c \
    p11_module.h p11_module.c

EXTRA_DIST = \
    provider.map
