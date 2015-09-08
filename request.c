/*
 * request.c
 */
#include "header_template.h"
#define HEADER_SIZE 400

static char header[HEADER_SIZE];

int RequestGetFile(int sslSocket, const char *basicAuth, char *file)
{

    write_byte = snprintf(header, HEADER_SIZE, template_header_propfind, base64EncodeOutput);
    if (write_byte < 0 || write_byte >= HEADER_SIZE)
    {
        fprintf(stderr, "Header construct, need resize buffer\n");
        exit(0);
    }
}

int RequestPutFile(int sslSocket, const char *basicAuth, char *file)
{

}

int ConstructHeaderGet()
{

}

int ConstructHeaderPut()
{

}
