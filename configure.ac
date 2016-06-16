AC_PREREQ([2.69])
AC_INIT([Apache dovecot authetication module], [0.2.3], [boris@steki.net])
AC_CONFIG_SRCDIR([mod_authn_dovecot.c])

AC_PROG_CC
AC_PATH_PROG(APXS, 'apxs',[no])
if test "$APXS" == "no" ; then
	AC_MSG_ERROR([apxs command missing please install apache development package])
fi

PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([APR], [apr-1])
PKG_CHECK_MODULES([APRUTIL], [apr-util-1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for library functions.
AC_CHECK_FUNCS([memset select socket strncasecmp])

# substitutes
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LIBS)
AC_SUBST(APRUTIL_CFLAGS)
AC_SUBST(APRUTIL_LIBS)
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
