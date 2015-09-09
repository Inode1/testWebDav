#ifndef WEBDAV_UTILITY_H_
#define WEBDAV_UTILITY_H_

#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// Basic auth = base64(login:pass)
int Base64Encode(const char* buffer, size_t length, char** b64text);
// Get MD5 hash for file
int TakeMD5HashForFile(const char* filename, char result[2*MD5_DIGEST_LENGTH + 1]);
// Get Sha256 hash for file
int TakeSHA256HashForFile(const char* filename, char result[2*SHA256_DIGEST_LENGTH + 1]);
/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection(const char *hostname, int port);
/*---------------------------------------------------------------------*/
/*--- InitSSL - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitSSL(void);
/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl);
#endif
