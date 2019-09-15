#ifndef ERROR_HPP
#define ERROR_HPP

#include <unistd.h>
#include <string.h>

#include <string>

#define ERROR_CLIENT_RESOLVE_HOSTNAME 1
#define ERROR_CLIENT_CONNECT 2
#define ERROR_CLIENT_WRITE 3
#define ERROR_CLIENT_READ 4
#define ERROR_CLIENT_UNCONNECTED 5

/* this class handles error output for the client class
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
