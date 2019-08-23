#ifndef CLIENT_HPP
#define CLIENT_HPP

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
/* this class is used by the server class and handles one connexion with a client
 */
class client
{
public:
	client(bool tlsMode, bool blocking);
	~client();
	int32_t getSocket() const;
	/* returns the socket fileno
	 */
	bool accept(int32_t mainSocket, SSL_CTX * sslContext);
	/* accept a client
	 * mainSocket is the server socket and sslContext is the ssl context of the server in tls mode
	 */
	bool doHandshake();
	/* handshake negociation
	 * returns true on success, false otherwise
	 */
	void disconnect();
	/* disconnect client
	 */
	bool isTls() const;
	bool isBlocking() const;
	bool ishandshakeMade() const;
	uint32_t inactivityCounter() const;
	/* the inactvityCounter increases by one each unscessfull call to readFromClient
	 */
	bool readFromClient(char buffer[MAX_BUFFER_SIZE]);
	/* tries to read from the client result is stored in buffer
	 * returns true on success, false otherwise
	 */
	bool writeToClient(char buffer[MAX_BUFFER_SIZE]);
	/* tries to write buffer to the client
	 * returns true on success, false otherwise
	 */
	void identifyClient(int64_t id);
	/* replace client id (m_id) by id
	 */
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
	/* client id is used to differentiate clients
	 *it is by default to 1
	 */
};

#endif /* CLIENT_HPP */
