#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#include <cstdint>

#include "error.hpp"

#define MAX_BUFFER_SIZE 8192

class client
{
public:
	client(bool tlsMode, bool blocking);
	~client();
	int32_t getSocket() const;
	bool accept(int32_t mainSocket, SSL_CTX * sslContext);
	bool doHandshake();
	void disconnect();
	bool isTls() const;
	bool isBlocking() const;
	bool ishandshakeMade() const;
	uint32_t inactivityCounter() const;
	bool readFromClient(char buffer[MAX_BUFFER_SIZE]);
	bool writeToClient(char buffer[MAX_BUFFER_SIZE]);
	void identifyClient(int64_t id);
	int64_t getClientId() const;
private:
	bool m_tlsMode;
	bool m_blocking;
	bool m_handshakeMade;
	int32_t m_socket;
	sockaddr_in m_clientAddress;
	SSL * m_ssl;
	uint32_t m_inactivityCounter;
	int64_t m_id;
};

#endif /* CLIENT_HPP */
