AC_INIT([passwdqc-plugin],[0.1])

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([.])

AC_CANONICAL_HOST
AC_PROG_CC

AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for
--enable-debug]) ;;
esac],
[debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

# Determine PIC flag, adjust default CFLAGS
pic_flag=
shared_flag=
AC_MSG_CHECKING(Determining PIC compiler/shared linker flag)
if test "$GCC" = yes; then
  AC_MSG_RESULT(-fPIC)
  pic_flag=-fPIC
  shared_flag=-shared
else
  case "$host" in
    *-*-hpux*)
      AC_MSG_RESULT("+Z")
      pic_flag="+Z"
      ;;
    *-*-solaris*)
      AC_MSG_RESULT(-Kpic)
      pic_flag=-Kpic
      shared_flag=-G
      ;;
    *-*-linux*)
      AC_MSG_RESULT(-fPIC)
      pic_flag=-fPIC
      # Any Linux compiler had better be gcc compatible.
      ;;
    *)
      echo "Host : $host"
      AC_MSG_RESULT("<none>")
      ;;
  esac
fi
AC_SUBST(pic_flag)
AC_SUBST(shared_flag)

# check for --with-nspr-inc
AC_MSG_CHECKING(for --with-nspr-inc)
AC_ARG_WITH(nspr-inc, AS_HELP_STRING([--with-nspr-inc=PATH],[Mozilla Portable Runtime include directory]),
[
  if test -e "$withval"/prtypes.h
  then
    AC_MSG_RESULT([using $withval])
    nspr_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  nspr_inc=""
])
AC_SUBST([nspr_inc])

# check for --with-ds-inc
AC_MSG_CHECKING(for --with-ds-inc)
AC_ARG_WITH(ds-inc, AS_HELP_STRING([--with-ds-inc=PATH],[Port389 DS include directory]),
[
  if test -e "$withval"/slapi-plugin.h
  then
    AC_MSG_RESULT([using $withval])
    ds_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  ds_inc=""
])
AC_SUBST([ds_inc])

# check for --with-passwdqc-inc
AC_MSG_CHECKING(for --with-passwdqc-inc)
AC_ARG_WITH(passwdqc-inc, AS_HELP_STRING([--with-passwdqc-inc=PATH],[passwdqc include directory]),
[
  if test -e "$withval"/passwdqc.h
  then
    AC_MSG_RESULT([using $withval])
    passwdqc_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  passwdqc_inc=""
])
AC_SUBST([passwdqc_inc])


CPPFLAGS="$passwdqc_inc $nspr_inc $ds_inc"
CFLAGS=""
AC_CHECK_HEADERS(ldap.h,[], [AC_MSG_ERROR([unable to find the ldap.h include])])
AC_CHECK_HEADERS(nspr.h,[], [AC_MSG_ERROR([unable to find the nspr.h include])])
AC_CHECK_HEADERS(slapi-plugin.h,[], [AC_MSG_ERROR([unable to find the slapi-plugin.h include])])
AC_CHECK_HEADERS(passwdqc.h,[], [AC_MSG_ERROR([unable to find the passwdqc.h include])])
AC_SEARCH_LIBS([passwdqc_params_reset], [passwdqc],[],[
  AC_MSG_ERROR([unable to find the passwdqc library])
])


AC_OUTPUT([
Makefile
])
