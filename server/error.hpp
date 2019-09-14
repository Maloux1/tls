#ifndef ERROR_HPP
#define ERROR_HPP

#include <unistd.h>
#include <string.h>

#include <string>

#define ERROR_SERVER_LAUNCH 1
#define ERROR_CLIENT_ACCEPT 2
#define ERROR_CLIENT_HANDSHAKE 3
#define ERROR_CLIENT_READ 4
#define ERROR_SERVER_NOT_LAUNCHED 5
#define ERROR_SERVER_NOT_TLS 6
#define ERROR_SERVER_FULL 7
#define ERROR_CLIENT_WRITE 8


/* this class handles error output for the server and connection classes 
 */
class serverError
{
public:
	serverError(const std::string& s, uint16_t errorType);
	~serverError();
	const char * getMessage() const;
	void outputMessage() const;
private:
	std::string m_message;
	uint16_t m_errorType;
	uint32_t errtmp;
};

#endif /* ERROR_HPP */
