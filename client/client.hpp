#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <string>

#include "error.hpp"

#define MAX_BUFFER_SIZE 8192

class client
{
public:
	client(bool tlsMode, bool blocking, std::string serverIP_URL, std::string serverPort, std::string pathToCAFile = "");
	/*
	 * tlsMode : true if tls connexion should be enabled
	 * blocking : true if server should be on blocking mode
	 * serverIP_URL : string containing the ip or url of the server
	 * serverPort : string containing the port of the server
	 * pathToCAFile : if tlsMode is true, this specifies an certifiacte which will be trusted by the client
	 */
	~client();
	bool connect();
	/* this function tries to etablish a connection to the server
	 * returns true on success, false otherwise
	 */
	void disconnect();
	/* disconnect client
	 */
	bool write(char const buffer[MAX_BUFFER_SIZE]);
	/* write data to server
	 * returns true on success, false otherwise
	 */
	bool read(char buffer[MAX_BUFFER_SIZE]);
	/* read data from server
	 * returns true on success, false otherwise
	 */
private:
	int32_t m_socket;
	bool m_tlsMode;
	bool m_blocking;
	bool m_resolveHostname;
	bool m_connected;
	struct sockaddr_in m_serverAddress;
	std::string m_pathToCAFile;
	SSL_CTX * m_sslContext;
	SSL * m_ssl;
};

#endif /* CLIENT_HPP */
