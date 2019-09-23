#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <openssl/ssl.h>

#include <string>
#include <cstdint>

#define MAX_BUFFER_SIZE 8192

#include "error.hpp"
/* this class is used by the server class and handles one connexion
 */
class connection
{
public:
	connection(bool tlsMode, bool blocking);
	~connection();
	int32_t getSocket() const;
	/* returns the socket fileno
	 */
	bool accept(int32_t mainSocket, SSL_CTX * sslContext);
	/* accept a connection
	 * mainSocket is the server socket and sslContext is the ssl context of the server in tls mode
	 */
	bool doHandshake();
	/* handshake negociation
	 * returns true on success, false otherwise
	 */
	void disconnect();
	/* disconnect connection
	 */
	bool isTls() const;
	bool isBlocking() const;
	bool ishandshakeMade() const;
	uint32_t inactivityCounter() const;
	/* the inactvityCounter increases by one each unscessfull call to readFromConnection
	 */
	uint32_t connectionCounter() const;
	/* the connectionCounter increases by one each call to readFromConnection
	 */
	bool readFromConnection(char buffer[MAX_BUFFER_SIZE]);
	/* tries to read from the connection, result is stored in buffer
	 * returns true on success, false otherwise
	 */
	bool writeToConnection(char buffer[MAX_BUFFER_SIZE]);
	/* tries to write buffer to the connection
	 * returns true on success, false otherwise
	 */
	void identifyConnection(int64_t id);
	/* replace connection id (m_id) by id
	 */
	int64_t getConnectionId() const;
private:
	bool m_tlsMode;
	bool m_blocking;
	bool m_handshakeMade;
	int32_t m_socket;
	sockaddr_in m_connectionAddress;
	SSL * m_ssl;
	uint32_t m_inactivityCounter;
	uint32_t m_connectionCounter;
	int64_t m_id;
	/* connection id is used to differenciate connections
	 * it is by default to -1
	 */
};

#endif /* CONNECTION_HPP */
