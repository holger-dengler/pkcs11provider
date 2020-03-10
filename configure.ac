define([_VERSION_MAJOR_], [0])
define([_VERSION_MINOR_], [1])
define([_VERSION_PATCH_], [0])

AC_PREREQ([2.69])

AC_INIT([pkcs11provider],
        [_VERSION_MAJOR_._VERSION_MINOR_._VERSION_PATCH_],
        [https://github.com/p-steuer/pkcs11provider/issues],
        [pkcs11provider],
        [https://github.com/p-steuer/pkcs11provider])

VERSION_MAJOR=_VERSION_MAJOR_
VERSION_MINOR=_VERSION_MINOR_
VERSION_PACTH=_VERSION_PATCH_

AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_PATCH)

AC_CONFIG_SRCDIR([src/p11_init.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_CONFIG_HEADERS([config.h])

AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS([string.h])

AM_INIT_AUTOMAKE([-Wall foreign])
LT_INIT
AC_OUTPUT
