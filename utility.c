#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>

#include "utility.h"

int Base64Encode(const char* buffer, size_t length, char** b64text) 
{   //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return 0;
}

int TakeMD5HashForFile(const char* filename, char result[2*MD5_DIGEST_LENGTH + 1])
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf ("%s can't opened.\n", filename);
        return 1;
    }
    MD5_CTX md5Context;
    unsigned char data[1024];
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Init (&md5Context);
    int bytes;
    while ((bytes = fread (data, 1, 1024, file)) != 0)
    {
        MD5_Update(&md5Context, data, bytes);
    }

    MD5_Final (hash, &md5Context);
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(result + (i * 2), "%02x", hash[i]);
    }
    result[2*MD5_DIGEST_LENGTH + 1] = 0;
    fclose (file);
    return 0;
}

int TakeSHA256HashForFile(const char* filename, char result[2*SHA256_DIGEST_LENGTH + 1])
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf ("%s can't opened.\n", filename);
        return 1;
    }
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char data[1024];
    int bytes;
    while ((bytes = fread (data, 1, 1024, file)) != 0)
    {
        SHA256_Update(&sha256Context, data, bytes);
    }
    SHA256_Final(hash, &sha256Context);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(result + (i * 2), "%02x", hash[i]);
    }
    result[2*SHA256_DIGEST_LENGTH + 1] = 0;

    fclose(file);
    return 0;
}
