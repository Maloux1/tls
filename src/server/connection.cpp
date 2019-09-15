#include "connection.hpp"

using namespace std;

connection::connection(bool tlsMode, bool blocking) : m_tlsMode(tlsMode), m_blocking(blocking), m_handshakeMade(false), m_socket(-1), m_ssl(NULL), m_inactivityCounter(0), m_id(-1){
	memset(&m_connectionAddress, 0, sizeof(m_connectionAddress));
}

connection::~connection(){
	disconnect();
}

int32_t connection::getSocket() const{
	return m_socket;
}

bool connection::accept(int32_t mainSocket, SSL_CTX * sslContext){
	try {
		socklen_t addressLen = sizeof(m_connectionAddress);
		int32_t ret = ::accept(mainSocket, (struct sockaddr *)&m_connectionAddress, &addressLen);
		if (ret == -1 && errno != EWOULDBLOCK){
			throw serverError("can't accept connection", ERROR_CLIENT_ACCEPT);
		}
		else if (ret == -1 && errno == EWOULDBLOCK){
			return false;
		}
		else {
			m_socket = ret;
			if (!m_blocking){
				int options;
				if ((options = fcntl(m_socket, F_GETFL)) == -1){
					throw serverError("can't set non blocking mode", ERROR_CLIENT_ACCEPT);
				}
				if (fcntl(m_socket, F_SETFL, options | O_NONBLOCK) == -1){
					throw serverError("can't set non blocking mode", ERROR_CLIENT_ACCEPT);
				}
			}
			if (m_tlsMode){
				m_ssl = SSL_new(sslContext);
				if (m_ssl == NULL){
					throw serverError("can't create SSL", ERROR_CLIENT_ACCEPT);
				}
				if (SSL_set_fd(m_ssl, m_socket) == 0){
					throw serverError("SSL_set_fd error", ERROR_CLIENT_ACCEPT);
				}
				SSL_set_accept_state(m_ssl);
			}
			return true;
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
	}
	return false;
}

bool connection::doHandshake(){
	try {
		if (m_tlsMode && !m_handshakeMade){
			int ret = SSL_accept(m_ssl);
			if (ret != 1){
				int tmp = SSL_get_error(m_ssl, ret);
				if (tmp != SSL_ERROR_WANT_READ && tmp != SSL_ERROR_WANT_WRITE && tmp != SSL_ERROR_WANT_CONNECT && tmp != SSL_ERROR_WANT_ACCEPT){
					throw serverError("handshake can't be made (ssl_get_error returns : " + to_string(tmp) + ")", ERROR_CLIENT_HANDSHAKE);
					return false;
				}
			}
			else {
				m_handshakeMade = true;
				return true;
			}
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
	}
	return false;
}

bool connection::isTls() const{
	return m_tlsMode;
}

bool connection::isBlocking() const{
	return m_blocking;
}

bool connection::ishandshakeMade() const{
	return m_handshakeMade;
}

uint32_t connection::inactivityCounter() const{
	return m_inactivityCounter;
}

void connection::disconnect(){
	memset(&m_connectionAddress, 0, sizeof(m_connectionAddress));
	if (m_socket != -1){
		shutdown(m_socket, SHUT_RDWR);
		close(m_socket);
		m_socket = -1;
	}
	if (m_ssl != NULL){
		SSL_shutdown(m_ssl);
		SSL_free(m_ssl);
		m_ssl = NULL;
	}
	m_handshakeMade = false;
	m_inactivityCounter = 0;
	m_id = -1;
}

bool connection::readFromConnection(char buffer[MAX_BUFFER_SIZE]){
	try {
		m_inactivityCounter++;
		if (m_tlsMode && m_handshakeMade){
			int ret;
			if ((ret = SSL_read(m_ssl, buffer, MAX_BUFFER_SIZE)) <= 0){
				int tmp = SSL_get_error(m_ssl, ret);
				if (tmp != SSL_ERROR_WANT_WRITE && tmp != SSL_ERROR_WANT_READ){
					throw serverError("error while reading from connection (tls)", ERROR_CLIENT_READ);
				}
			}
			else {
				m_inactivityCounter = 0;
			}
		}
		else if (!m_tlsMode){
			int ret;
			if ((ret = recv(m_socket, buffer, MAX_BUFFER_SIZE, 0)) < 0){
				if (errno != EWOULDBLOCK){
					throw serverError("error while reading from connection (non-tls)", ERROR_CLIENT_READ);
				}
			}
			else if (ret != 0) {
				m_inactivityCounter = 0;
			}
			else {
				disconnect();
			}
		}
		return true;
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
	}
	return false;
}

bool connection::writeToConnection(char buffer[MAX_BUFFER_SIZE]){
	try {
		int max_buffer_size;
		if (strlen(buffer) < MAX_BUFFER_SIZE){
			max_buffer_size = strlen(buffer);
		}
		else {
			max_buffer_size = MAX_BUFFER_SIZE;
		}
		if (m_tlsMode && m_handshakeMade){
			int ret;
			if ((ret = SSL_write(m_ssl, buffer, max_buffer_size)) <= 0){
				int tmp = SSL_get_error(m_ssl, ret);
				if (tmp != SSL_ERROR_WANT_WRITE && tmp != SSL_ERROR_WANT_READ){
					throw serverError("error while writing to connection (tls)", ERROR_CLIENT_WRITE);
				}
			}
		}
		else if (!m_tlsMode){
			if (send(m_socket, buffer, max_buffer_size, 0) <= 0){
				if (errno != EWOULDBLOCK){
					throw serverError("error while writing to connection (non-tls)", ERROR_CLIENT_WRITE);
				}
			}
		}
		return true;
	}
	catch (const serverError& error){
		error.outputMessage();
		disconnect();
	}
	return false;
}

void connection::identifyConnection(int64_t id){
	m_id = id;
}

int64_t connection::getConnectionId() const{
	return m_id;
}
