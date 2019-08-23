#ifndef SERVER_HPP
#define SERVER_HPP

#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#include <cstdint>
#include <string>
#include <list>

#include "error.hpp"
#include "client.hpp"

class server
{
public:
	server(uint16_t port, uint32_t maxClients, bool tlsMode, bool blocking, uint32_t maxInactivityCounter = 0, const std::string& pathToKeyFile = "", const std::string& pathToCertFile = "");
	~server();
	bool launch();
	void shutdown();
	uint32_t maxClients() const;
	uint32_t connectedClients() const;
	bool acceptClient();
	void handshakeClients();
	void cleanupClients();
	void readFromClients(int64_t callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data);
	void writeToClients(bool callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data	);
private:
	void kickClient(client * c);
	bool m_tlsMode;
	bool m_blocking;
	uint16_t m_port;
	struct sockaddr_in m_serverAddress;
	int32_t m_mainSocket;
	SSL_CTX * m_sslContext;
	std::string m_pathToKeyFile;
	std::string m_pathToCertFile;
	uint32_t m_maxClients;
	std::list<client*> m_clients;
	uint32_t m_maxInactivityCounter;
};

#endif /* SERVER_HPP */
