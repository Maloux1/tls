#ifndef SERVER_HPP
#define SERVER_HPP

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>

#include <openssl/ssl.h>

#include <string>
#include <cstdint>
#include <list>

#include "connection.hpp"
#include "error.hpp"
/* this class is used to setup a server which handles cyphered or uncyphered connections
 */
class server
{
public:
	server(uint16_t port, uint32_t maxConnections, bool tlsMode, bool blocking, uint32_t maxInactivityCounter = 0, const std::string& pathToKeyFile = "", const std::string& pathToCertFile = "");
	/* port : the port of the server
	 * maxConnections : the maximum number of connections that can be connected simultaneously
	 * tlsMode : enabled : connection is cyphered with tls, disabled : simple sockets
	 * blocking : blocking calls
	 * maxInactivityCounter : maximum number of unsuccessfull calls to readFromClient before autokick client (0 to never kick)
	 * pathToKeyFile : path to the encryption key used (tls mode)
	 * pathToCertFile : path to the certificate used (tls mode)
	 */
	~server();
	bool launch();
	/* launches the server, must be called before any other call
	 * returns true on success, false otherwise
	 */
	void shutdown();
	/* shutdowns the server and kicks every connection
	 */
	uint32_t maxConnections() const;
	/* returns the max number of connections
	 */
	uint32_t connectedConnections() const;
	/* returns the number of currently connected connections
	 */
	bool acceptConnection();
	/* accepts one connection waiting of being accepted
	 * returns true on success, false otherwise
	 */
	void handshakeConnections();
	/* try to negociate handshake with connections (tls mode)
	 */
	void cleanupConnections();
	/* kick connections which haven't send a single packet maxInactivityCounter times consecutively or which have left
	 */
	void readFromConnections(int64_t callback(int64_t, char [MAX_BUFFER_SIZE], void *, bool *), void * data);
	/* read data from connections and call the callback function (for each connection that as send a packet) with :
	 * the client id as an int64_t (-1 default after connection)
	 * a buffer with the packet received
	 * the pointer data is passed to callback as a void *
	 * a pointer to a boolean, if callback returns >= 0 and this boolean is true, content of buffer is immediatly sent to the client
	 * the callback must return an int64_t which is the new connection id (0 for unchanged, -1 will kick connection, positive will change connection id)
	 */
	void writeToConnections(bool callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data	);
	/* calls a callback for each connection with :
	 * the connection id as an int64_t (-1 default after connection)
	 * a buffer with the packet to be sent
	 * the pointer data is passed to callback as a void *
	 * if the callback returns true buffer is sent to connection, otherwise nothing is done
	 */
private:
	void kickConnection(connection * c);
	bool m_tlsMode;
	bool m_blocking;
	uint16_t m_port;
	struct sockaddr_in m_serverAddress;
	int32_t m_mainSocket;
	SSL_CTX * m_sslContext;
	std::string m_pathToKeyFile;
	std::string m_pathToCertFile;
	uint32_t m_maxConnections;
	std::list<connection*> m_connections;
	uint32_t m_maxInactivityCounter;
};

#endif /* SERVER_HPP */
