#ifndef WEBDAV_UTILITY_H_
#define WEBDAV_UTILITY_H_
#include <openssl/md5.h>
#include <openssl/sha256.h>

int Base64Encode(const char* buffer, size_t length, char** b64text);
int TakeMD5HashForFile(const char* filename, char result[2*MD5_DIGEST_LENGTH + 1]);
int TakeSHA256HashForFile(const char* filename, char result[2*SHA256_DIGEST_LENGTH + 1]);

#endif
