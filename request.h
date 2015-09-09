/*
 * request.h
 */

#ifndef REQUEST_H_
#define REQUEST_H_

#include <openssl/ssl.h>

enum EMethod
{
    None,
    Put,
    Get
};

int MakeRequestFile(SSL* ssl, enum EMethod method, const char *basicAuth, char *file);

#endif /* REQUEST_H_ */
