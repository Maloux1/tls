#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <fcntl.h>

#include <string>

#include "error.hpp"

#define MAX_BUFFER_SIZE 8192

class client
{
public:
	client(bool tlsMode, bool blocking, std::string serverIP_URL, std::string serverPort, std::string pathToCAFile = "");
	~client();
	bool connect();
	void disconnect();
	bool write(char const buffer[MAX_BUFFER_SIZE]);
private:
	int32_t m_socket;
	bool m_tlsMode;
	bool m_blocking;
	struct sockaddr_in m_serverAddress;
	std::string m_pathToCAFile;
	SSL_CTX * m_sslContext;
	SSL * m_ssl;
};

#endif /* CLIENT_HPP */
