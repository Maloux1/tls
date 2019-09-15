AC_INIT([tls], [1.0], [https://github.com/Maloux1/tls.git])

AM_INIT_AUTOMAKE([-Wall])

AC_PROG_CPP

AM_PROG_AR([])

LT_INIT

AC_CHECK_HEADERS(
stdint.h
unistd.h
string.h
sys/types.h
sys/socket.h
netinet/in.h
arpa/inet.h
fcntl.h
signal.h
openssl/ssl.h
string
cstdint
list
netdb.h
)

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([
src/server/Makefile
src/client/Makefile
Makefile
])

AC_OUTPUT



