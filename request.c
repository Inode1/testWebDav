/*
 * request.c
 */
#include <libgen.h>
#include <sys/stat.h>

#include "header_template.h"
#include "utility.h"

#define BUFFER_SIZE 1024
#define HEADER_SIZE 500

static char header[HEADER_SIZE];

enum HttpStatusCode
{
	None,
	Informational = 1, // 1xx
	Successful    = 2, // 2xx
	Redirection   = 3, // 3xx
	ClientError   = 4, // 4xx
	ServerError   = 5  // 5xx
};

struct ResponeHeader
{
	enum HttpStatusCode Status;
	uint32_t            ContentLength;
};

int ConstructHeaderGet(const char *basicAuth, char *file)
{
    int write_byte = snprintf(header, HEADER_SIZE, template_header_get, basename(file), basicAuth);
    if (write_byte < 0 || write_byte >= HEADER_SIZE)
    {
        fprintf(stderr, "Get header construct, need resize buffer\n");
        return 1;
    }
    return 0;
}

int32_t FileSize(const char *filename)
{
    struct stat st;

    if (stat(filename, &st) == 0)
    {
        return st.st_size;
    }

    fprintf(stderr, "Cannot determine size of %s: %s\n",
            filename, strerror(errno));

    return -1;
}

int ConstructHeaderPut(const char *basicAuth, char *file)
{
	char md5HashSum[2*MD5_DIGEST_LENGTH + 1];
	if (TakeMD5HashForFile(file, md5HashSum))
	{
        fprintf(stderr, "Error md5 hash fail\n");
        return 1;
	}

	char sha256HashSum[2*SHA256_DIGEST_LENGTH + 1];
	if (TakeSHA256HashForFile(file, sha256HashSum))
	{
        fprintf(stderr, "Error sha256 hash fail\n");
        return 1;
	}

	int32_t size;
	if ( (size = FileSize(file)) == -1)
	{
		return 1;
	}

    int write_byte = snprintf(header, HEADER_SIZE, template_header_put, basename(file),
    						  basicAuth, md5HashSum, sha256HashSum, size);
    if (write_byte < 0 || write_byte >= HEADER_SIZE)
    {
        fprintf(stderr, "Put header construct, need resize buffer\n");
        exit(0);
    }
    return 0;
}

int ParseResponeHeader()
{
	return 0;
}

int RequestGetFile(SSL* ssl, const char *basicAuth, char *file)
{
	if (ConstructHeaderGet(basicAuth, file))
	{
        fprintf(stderr, "Error construct header for Get method\n");
        return 1;
	}

#ifdef DEBUG
    printf("Send : %s\n", header);
#endif

    char buf[BUFFER_SIZE];
    // send header
    SSL_write(ssl, header, strlen(header));			/* encrypt & send message */
    // get response header
    int bytes = SSL_read(ssl, buf, BUFFER_SIZE);	    /* get reply & decrypt */
    buf[bytes] = 0;


#ifdef DEBUG
    printf("Received byte: %d\n", bytes);
    printf("Received: %s\n", buf);
#endif
	return 0;
}

int RequestPutFile(SSL* ssl, const char *basicAuth, char *file)
{
	if (ConstructHeaderPut(basicAuth, file))
	{
        fprintf(stderr, "Error construct header for Put method\n");
        return 1;
	}
#ifdef DEBUG
    printf("Send : %s\n", header);
#endif

    char buf[BUFFER_SIZE];
    // send header
    SSL_write(ssl, header, strlen(header));			/* encrypt & send message */
    // get response header
    int bytes = SSL_read(ssl, buf, BUFFER_SIZE);	    /* get reply & decrypt */
    buf[bytes] = 0;

#ifdef DEBUG
    printf("Received byte: %d\n", bytes);
    printf("Received: %s\n", buf);
#endif

    return 0;
}
