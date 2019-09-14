#include "server.hpp"

using namespace std;

server::server(uint16_t port, uint32_t maxConnections, bool tlsMode, bool blocking, uint32_t maxInactivityCounter, const string& pathToKeyFile, const string& pathToCertFile) : m_tlsMode(tlsMode), m_blocking(blocking), m_port(port), m_mainSocket(-1), m_sslContext(NULL), m_pathToKeyFile(pathToKeyFile), m_pathToCertFile(pathToCertFile), m_maxConnections(maxConnections), m_maxInactivityCounter(maxInactivityCounter){
	if (tlsMode){
		SSL_library_init();
	}
	signal(SIGPIPE, SIG_IGN);
	memset(&m_serverAddress, 0, sizeof(m_serverAddress));
}

server::~server(){
	shutdown();
}

bool server::launch(){
	try {
		if (m_mainSocket != -1){
			throw serverError("server is already launched", ERROR_SERVER_LAUNCH);
		}
		m_serverAddress.sin_family = AF_INET;
		m_serverAddress.sin_port = htons(m_port);
		m_serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
		if ((m_mainSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
			throw serverError("can't create socket", ERROR_SERVER_LAUNCH);
		}
		if (!m_blocking){
			int options;
			if ((options = fcntl(m_mainSocket, F_GETFL)) == -1){
				throw serverError("fcntl error", ERROR_SERVER_LAUNCH);
			}
			if (fcntl(m_mainSocket, F_SETFL, options | O_NONBLOCK) == -1){
				throw serverError("fcntl error", ERROR_SERVER_LAUNCH);
			}
		}
		if (bind(m_mainSocket, (sockaddr *)&m_serverAddress, sizeof(sockaddr)) != 0){
			throw serverError("can't bind socket", ERROR_SERVER_LAUNCH);
		}
		if (listen(m_mainSocket, 5) == -1){
			throw serverError("can't call listen on socket", ERROR_SERVER_LAUNCH);
		}
		if (m_tlsMode){
			if ((m_sslContext = SSL_CTX_new(TLS_server_method())) == NULL){
				throw serverError("can't create a SSL_CTX", ERROR_SERVER_LAUNCH);
			}
			if (SSL_CTX_set_min_proto_version(m_sslContext, TLS1_3_VERSION) == 0){
				throw serverError("SSL_CTX_set_min_proto_version error", ERROR_SERVER_LAUNCH);
			}
			if (SSL_CTX_use_PrivateKey_file(m_sslContext, m_pathToKeyFile.c_str(), SSL_FILETYPE_PEM) != 1){
				throw serverError("SSL_CTX_use_PrivateKey_file error", ERROR_SERVER_LAUNCH);
			}
			if (SSL_CTX_use_certificate_file(m_sslContext, m_pathToCertFile.c_str(), SSL_FILETYPE_PEM) != 1){
				throw serverError("SSL_CTX_use_certificate_file error", ERROR_SERVER_LAUNCH);
			}
			SSL_CTX_set_verify(m_sslContext, SSL_VERIFY_NONE, NULL);
		}
	}
	catch (const serverError& error){
		error.outputMessage();
		shutdown();
		return false;
	}
	return true;
}

void server::shutdown(){
	for (auto i=m_connections.begin(); i!=m_connections.end(); i++){
		kickConnection(*i);
		m_connections.erase(i);
	}
	if (m_mainSocket != -1){
		close(m_mainSocket);
		m_mainSocket = -1;
	}
	if (m_sslContext != NULL){
		SSL_CTX_free(m_sslContext);
		m_sslContext = NULL;
	}
	memset(&m_serverAddress, 0, sizeof(m_serverAddress));
	return;
}

uint32_t server::maxConnections() const{
	return m_maxConnections;
}
uint32_t server::connectedConnections() const{
	return m_connections.size();
}

bool server::acceptConnection(){
	try {
		if (m_mainSocket == -1){
			throw serverError("trying to accept client on an unlaunched server", ERROR_SERVER_NOT_LAUNCHED);
		}
		if (m_maxConnections <= m_connections.size()){
			throw serverError("server is full can't accept client (" + to_string(m_connections.size()) + "/" + to_string(m_maxConnections) + ")", ERROR_SERVER_FULL);
		}
		connection * tmpConnection = new connection(m_tlsMode, m_blocking);
		if (tmpConnection->accept(m_mainSocket, m_sslContext) == true){
			m_connections.push_back(tmpConnection);
		}
		else {
			delete tmpConnection;
			return false;
		}
		return true;
	}
	catch (const serverError& error){
		error.outputMessage();
	}
	return false;
}

void server::handshakeConnections(){
	try {
		if (m_mainSocket == -1){
			throw serverError("trying to handshake on an unlaunched server", ERROR_SERVER_NOT_LAUNCHED);
		}
		if (!m_tlsMode){
			throw serverError("trying to handshake on an non-tls server", ERROR_SERVER_NOT_TLS);
		}
		for (auto i = m_connections.begin(); i != m_connections.end(); i++){
			if (!(*i)->ishandshakeMade() && (*i)->isTls()){
				(*i)->doHandshake();
			}
		}
	}
	catch (const serverError& error){
		error.outputMessage();
	}
}

void server::kickConnection(connection * c){
	delete c;
}

void server::cleanupConnections(){
	try {
		if (m_mainSocket == -1){
			throw serverError("trying to cleanup clients on an unlaunched server", ERROR_SERVER_NOT_LAUNCHED);
		}
		for (auto i = m_connections.begin(); i != m_connections.end();){
			auto j=i;
			j++;
			if (((*i)->inactivityCounter() >= m_maxInactivityCounter && m_maxInactivityCounter != 0) || (*i)->getSocket() == -1){
				kickConnection(*i);
				m_connections.erase(i);
			}
			i=j;
		}
	}
	catch (const serverError& error){
		error.outputMessage();
	}
}

void server::readFromConnections(int64_t callback(int64_t, char [MAX_BUFFER_SIZE], void *, bool *), void * data){
	try {
		if (m_mainSocket == -1){
			throw serverError("trying to read from clients on an unlaunched server", ERROR_SERVER_NOT_LAUNCHED);
		}
		char * buffer = (char*) malloc(sizeof(char) * MAX_BUFFER_SIZE);
		for (auto i = m_connections.begin(); i != m_connections.end();){
			auto j = i;
			j++;
			memset(buffer, 0, sizeof(char) * MAX_BUFFER_SIZE);
			if ((*i)->readFromConnection(buffer)){
				if (callback != NULL){
					bool response = false;
					int tmp = callback((*i)->getConnectionId(), buffer, data, &response);
					if (tmp > 0){
						(*i)->identifyConnection(tmp);
					}
					else if (tmp == -1){
						kickConnection(*i);
						m_connections.erase(i);
					}
					if (tmp >= 0 && response){
						(*i)->writeToConnection(buffer);
					}
				}
			}
			else{
				kickConnection(*i);
				m_connections.erase(i);
			}
			i=j;
		}
		free(buffer);
	}
	catch (const serverError& error){
		error.outputMessage();
	}
}

void server::writeToConnections(bool callback(int64_t, char [MAX_BUFFER_SIZE], void *), void * data){
	try {
		if (m_mainSocket == -1){
			throw serverError("trying to write to clients on an unlaunched server", ERROR_SERVER_NOT_LAUNCHED);
		}
		char * buffer = (char*) malloc(sizeof(char) * MAX_BUFFER_SIZE);
		for (auto i = m_connections.begin(); i != m_connections.end();){
			auto j = i;
			j++;
			memset(buffer, 0, sizeof(char) * MAX_BUFFER_SIZE);
			if (callback != NULL){
				if (callback((*i)->getConnectionId(), buffer, data)){
					if (!(*i)->writeToConnection(buffer)){
						kickConnection(*i);
						m_connections.erase(i);
					}
				}
			}
			i=j;
		}
		free(buffer);
	}
	catch (const serverError& error){
		error.outputMessage();
	}
}
