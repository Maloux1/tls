#include "client.hpp"

using namespace std;

client::client(bool tlsMode, bool blocking, string serverIP_URL, string serverPort, string pathToCAFile, bool checkServer) : m_socket(-1), m_tlsMode(tlsMode), m_blocking(blocking), m_resolveHostname(false), m_connected(false), m_checkServer(checkServer), m_pathToCAFile(pathToCAFile), m_sslContext(NULL){
	signal(SIGPIPE, SIG_IGN);
	if (tlsMode){
		SSL_library_init();
	}
	struct addrinfo * res;
	struct addrinfo hints;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;
	if (getaddrinfo(serverIP_URL.c_str(), serverPort.c_str(), &hints, &res) != 0){
		m_resolveHostname = false;
	}
	else {
		m_resolveHostname = true;
		m_serverAddress = *(struct sockaddr_in*)(res->ai_addr);
		freeaddrinfo(res);
	}
}

client::~client(){
	disconnect();
}

bool client::connect(){
	try{
		if (!m_resolveHostname){
			throw serverError("host unreachable", ERROR_CLIENT_RESOLVE_HOSTNAME);
		}
		if (m_connected){
			throw(serverError("trying to connect with an already connected client", ERROR_CLIENT_UNCONNECTED));
		}
		if ((m_socket = socket(m_serverAddress.sin_family, SOCK_STREAM, 0)) == -1){
			throw(serverError("can't create socket", ERROR_CLIENT_CONNECT));
		}
		if (!m_blocking){
			int options;
			if ((options = fcntl(m_socket, F_GETFL)) == -1){
				throw serverError("fcntl error", ERROR_CLIENT_CONNECT);
			}
			if (fcntl(m_socket, F_SETFL, options | O_NONBLOCK) == -1){
				throw serverError("fcntl error", ERROR_CLIENT_CONNECT);
			}
		}
		while (::connect(m_socket, (struct sockaddr*)&m_serverAddress, sizeof(m_serverAddress)) != 0){
			if (errno != EINPROGRESS){
				throw(serverError("can't connect to server", ERROR_CLIENT_CONNECT));
			}
		}
		if (m_tlsMode){
			if ((m_sslContext = SSL_CTX_new(TLS_client_method())) == NULL){
				throw(serverError("can't create SSL_CTX", ERROR_CLIENT_CONNECT));
			}
			if (SSL_CTX_set_min_proto_version(m_sslContext, TLS1_3_VERSION) == 0){
				throw(serverError("SSL_CTX_set_min_proto_version error", ERROR_CLIENT_CONNECT));
			}
			if (m_checkServer){
				if (SSL_CTX_load_verify_locations(m_sslContext, m_pathToCAFile.c_str(), NULL) != 1){
					throw(serverError("can't load file " + m_pathToCAFile, ERROR_CLIENT_CONNECT));
				}
				SSL_CTX_set_verify(m_sslContext, SSL_VERIFY_PEER, NULL);
				SSL_CTX_set_verify_depth(m_sslContext, 1);
			}
			else {
				SSL_CTX_set_verify(m_sslContext, SSL_VERIFY_NONE, NULL);
			}
			m_ssl = SSL_new(m_sslContext);
			if (m_ssl == NULL){
				throw serverError("can't create SSL", ERROR_CLIENT_CONNECT);
			}
			if (SSL_set_fd(m_ssl, m_socket) == 0){
				throw serverError("SSL_set_fd error", ERROR_CLIENT_CONNECT);
			}
			SSL_set_connect_state(m_ssl);
			int ret;
			while((ret = SSL_connect(m_ssl)) != 1){
				if (ret < 0 && SSL_get_error(m_ssl, ret) != SSL_ERROR_WANT_WRITE && SSL_get_error(m_ssl, ret) != SSL_ERROR_WANT_READ){
					throw serverError("SSL_connect error", ERROR_CLIENT_CONNECT);
				}
			}
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
		return false;
	}
	m_connected = true;
	return true;
}

void client::disconnect(){
	if (m_socket != -1){
		shutdown(m_socket, SHUT_RDWR);
		close(m_socket);
		m_socket = -1;
	}
	if (m_sslContext != NULL){
		SSL_CTX_free(m_sslContext);
		m_sslContext = NULL;
	}
	m_connected = false;
}

bool client::write(char const buffer[MAX_BUFFER_SIZE]){
	try {
		if (!m_connected){
			throw serverError("trying to write on unconnected client", ERROR_CLIENT_UNCONNECTED);
		}
		int max_buffer_size;
		if (strlen(buffer) < MAX_BUFFER_SIZE){
			max_buffer_size = strlen(buffer);
		}
		else {
			max_buffer_size = MAX_BUFFER_SIZE;
		}
		if (m_tlsMode){
			int ret;
			if ((ret = SSL_write(m_ssl, buffer, max_buffer_size)) <= 0){
				int tmp = SSL_get_error(m_ssl, ret);
				if (tmp != SSL_ERROR_WANT_WRITE && tmp != SSL_ERROR_WANT_READ){
					throw serverError("error while writing to client (tls)", ERROR_CLIENT_WRITE);
				}
			}
		}
		else {
			if (send(m_socket, buffer, max_buffer_size, 0) == -1 && errno != EWOULDBLOCK){
				throw serverError("error while writing to client (non-tls)", ERROR_CLIENT_WRITE);
			}
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
		return false;
	}
	return true;
}

bool client::read(char buffer[MAX_BUFFER_SIZE]){
	try{
		if (!m_connected){
			throw serverError("trying to read on unconnected client", ERROR_CLIENT_UNCONNECTED);
		}
		memset(buffer, 0, MAX_BUFFER_SIZE*sizeof(char));
		if (m_tlsMode){
			int ret;
			if ((ret = SSL_read(m_ssl, buffer, MAX_BUFFER_SIZE)) <= 0){
				int tmp = SSL_get_error(m_ssl, ret);
				if (tmp != SSL_ERROR_WANT_WRITE && tmp != SSL_ERROR_WANT_READ){
					throw serverError("error while reading from client (tls)", ERROR_CLIENT_READ);
				}
			}
		}
		else {
			if (recv(m_socket, buffer, MAX_BUFFER_SIZE, 0) == -1 && errno != EWOULDBLOCK){
				throw serverError("error while reading from client (non-tls)", ERROR_CLIENT_READ);
			}
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
		return false;
	}
	return true;
}
