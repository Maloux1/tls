#include "error.hpp"

using namespace std;

serverError::serverError(const std::string& s, uint16_t errorType) : m_errorType(errorType), errtmp(errno){
	m_message = "";
	string errorMessage("");
	if (m_errorType == ERROR_CLIENT_RESOLVE_HOSTNAME){
		errorMessage += "can't access to provided hostname";
	}
	else if (m_errorType == ERROR_CLIENT_CONNECT){
		errorMessage += "error while initiating connexion";
	}
	else if (m_errorType == ERROR_CLIENT_WRITE){
		errorMessage += "error while sending data";
	}
	else if (m_errorType == ERROR_CLIENT_READ){
		errorMessage += "error while reading data";
	}
	else if (m_errorType == ERROR_CLIENT_UNCONNECTED){
		errorMessage += "client is not connected";
	}
	else {
		errorMessage += "unknown error";
	}
	if (isatty(fileno(stderr))){
		m_message += "\x1b[31;1m=== " + errorMessage + " ===\x1b[0m\n\x1b[33merrno is : ";
	}
	else {
		m_message += "=== " + errorMessage + " ===\nerrno is : ";
	}
	m_message += to_string(errtmp);
	m_message += "\n" + s + " : " + strerror(errtmp);
	if (isatty(fileno(stderr))){
		m_message += "\x1b[0m";
	}
	m_message += "\n";
}

serverError::~serverError(){

}

const char * serverError::getMessage() const{
	return m_message.c_str();
}

void serverError::outputMessage() const{
	fprintf(stderr, "%s", m_message.c_str());
}
