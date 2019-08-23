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

#include "client.hpp"
#include "error.hpp"
/* this class is used to setup a server which handles cyphered or uncyphered connexions with clients
 */
class server
{
public:
	server(uint16_t port, uint32_t maxClients, bool tlsMode, bool blocking, uint32_t maxInactivityCounter = 0, const std::string& pathToKeyFile = "", const std::string& pathToCertFile = "");
	/* port : the port of the server
	 * maxClients : the maximum number of clients that can connect simultaneously
	 * tlsMode : enabled connexion is cyphered with tls, disabled simple sockets
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
	/* shutdowns the server and kicks everyone
	 */
	uint32_t maxClients() const;
	/* returns the max number of clients
	 */
	uint32_t connectedClients() const;
	/* returns the number of currently connected clients
	 */
	bool acceptClient();
	/* accepts one client waiting of being accepted
	 * returns true on success, false otherwise
	 */
	void handshakeClients();
	/* try to negociate handshake with clients (tls mode)
	 */
	void cleanupClients();
	/* kick clients which haven't send a single packet maxInactivityCounter times consecutively or which have left
	 */
	void readFromClients(int64_t callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data);
	/* read data from clients and call the callback function (for each client that as send a packet) with :
	 * the client id as an int64_t (-1 default after connexion)
	 * a buffer with the packet received
	 * the pointer data is passed to callback as a void *
	 * the callback must return an int64_t which is the new client id (0 for unchanged, -1 will kick client, positive will change client id)
	 */
	void writeToClients(bool callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data	);
	/* calls a callback for each client with :
	 * the client id as an int64_t (-1 default after connexion)
	 * a buffer with the packet to be sent
	 * the pointer data is passed to callback as a void *
	 * if the callback returns true buffer is sent to client, otherwise nothing is done
	 */
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
