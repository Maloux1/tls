AC_INIT([tls], [1.0], [https://github.com/Maloux1/tls.git])

AM_INIT_AUTOMAKE([-Wall])

AC_PROG_CXX

AM_PROG_AR([])

LT_INIT

AC_CHECK_HEADER([stdint.h])
AC_CHECK_HEADER([unistd.h])
AC_CHECK_HEADER([string.h])
AC_CHECK_HEADER([sys/types.h])
AC_CHECK_HEADER([sys/socket.h])
AC_CHECK_HEADER([netinet/in.h])
AC_CHECK_HEADER([arpa/inet.h])
AC_CHECK_HEADER([fcntl.h])
AC_CHECK_HEADER([signal.h])
AC_CHECK_HEADER([openssl/ssl.h])
AC_CHECK_HEADER([netdb.h])
AC_CHECK_HEADER([errno.h])

AC_LANG_PUSH([C++])

AC_CHECK_HEADER([string])
AC_CHECK_HEADER([cstdint])
AC_CHECK_HEADER([list])

AC_LANG_POP([C++])


AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([
src/server/Makefile
src/client/Makefile
src/Makefile
Makefile
])

AX_CXX_COMPILE_STDCXX_11

AC_OUTPUT
