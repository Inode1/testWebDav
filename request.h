/*
 * request.h
 */

#ifndef REQUEST_H_
#define REQUEST_H_

#include <openssl/ssl.h>

int RequestGetFile(SSL* ssl, const char *basicAuth, char *file);
int RequestPutFile(SSL* ssl, const char *basicAuth, char *file);

#endif /* REQUEST_H_ */
