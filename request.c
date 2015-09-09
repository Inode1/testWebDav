/*
 * request.c
 */
#include <stdint.h>
#include <fcntl.h>
#include <sys/epoll.h>

// none modified basename function
#define _GNU_SOURCE
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>

#include "header_template.h"
#include "utility.h"
#include "request.h"

#define BUFFER_SIZE 16384
#define HEADER_SIZE 500
#define RESPONESTATUS 50

static char header[HEADER_SIZE];

enum HttpStatusCode
{
	NoneStatus,
	Informational = 1, // 1xx
	Successful    = 2, // 2xx
	Redirection   = 3, // 3xx
	ClientError   = 4, // 4xx
	ServerError   = 5  // 5xx
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

enum HttpStatusCode ParseResponeHeader(const char *responseData, int *contentLength)
{
    char *findSubstring;
    if ((findSubstring = strstr(responseData, "HTTP/1.1 ")) == NULL)
    {
        fprintf(stderr, "Error it`s not a header\n");
        return 1;
    }
    // position status code
    char status = (*(findSubstring + 9)) - '0';
    *contentLength = 0;
    if ((findSubstring = strstr(responseData, "Content-Length: ")) != NULL)
    {
        findSubstring += 16;
        *contentLength = atoi(findSubstring);
    }
    if (status > 0 && status <= 5)
    {
         return (enum HttpStatusCode)(status);
    }
    else
    {
        fprintf(stderr, "Error it`s not a status code: %d\n", status);
        return None;
    }
}

int PutMethod(char *buf, SSL *ssl, char *file)
{
    // put method
    int temp;
    enum HttpStatusCode statusCode = ParseResponeHeader(buf, &temp);
    if (statusCode == Successful)
    {
        fprintf(stderr, "Successful\n");
        return 0;
    }
    if (statusCode != Informational)
    {
        fprintf(stderr, "Server not get permission\n");
        return 1;
    }
    FILE *fd = fopen(file, "rb");
    if (file == NULL)
    {
        printf ("%s can't opened.\n", file);
        return 1;
    }
    // write in socket file
    int bytes;
    while ((bytes = fread (buf, 1, BUFFER_SIZE, fd)) != 0)
    {
        #ifdef DEBUG
        printf("Send : %s\n", buf);
        #endif

        // SSL_MODE_AUTO_RETRY don`t work. Maybe I do something wrong.
        while(1)
        {
            int err = SSL_write(ssl, buf, bytes);

            if (err > 0)
            {
                break;
            }
            int err2 = SSL_get_error(ssl,err);
            switch(err2) {
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                        break;
                    default:
                        printf("SSL_write err=%s\n", ERR_error_string(err2,0));
                        return 1;
                        break;
            }
        }
    }
    fclose(fd);
    return 0;
}

int GetMethod(char *buf, SSL *ssl, int *content)
{
    // get method
    enum HttpStatusCode statusCode = ParseResponeHeader(buf, content);
    if (statusCode != Successful)
    {
        fprintf(stderr, "non Successful status return\n");
        return 1;
    }
    return 0;
}

int MakeRequestFile(SSL* ssl, enum EMethod method, const char *basicAuth, char *file)
{
	if (method == Put)
	{
        if (ConstructHeaderPut(basicAuth, file))
        {
            fprintf(stderr, "Error construct header for Put method\n");
            return 1;
        }
	}
	else
	{
        if (ConstructHeaderGet(basicAuth, file))
        {
            fprintf(stderr, "Error construct header for Put method\n");
            return 1;
        }
	}
#ifdef DEBUG
    printf("Send : %s\n", header);
#endif

    // send header
    SSL_write(ssl, header, strlen(header));			/* encrypt & send message */
    // get response header

    struct epoll_event event, events;
    int epoll;
    if ( (epoll = epoll_create1(0)) == -1)
    {
        perror ("epoll_create");
        return 1;
    }

    int sd = SSL_get_fd(ssl);
    if (sd == -1)
    {
        fprintf(stderr, "SSl get file descriptor fail\n");
        return 1;
    }

    event.data.fd = sd;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl (epoll, EPOLL_CTL_ADD, sd, &event) == -1)
    {
        perror ("epoll_ctl");
        abort ();
    }

    char buf[BUFFER_SIZE];
    int n;
    int content = 0;
    int fd;
    while(1)
    {
        if ((n = epoll_wait (epoll, &events, 1, -1)) <= 0)
        {
            if (n == 0)
            {
                printf("Timeout exceed\n");
                break;
            }
            perror ("epoll waite");
            close(epoll);
            return 1;
        }
        if ((events.events & EPOLLERR) || (events.events & EPOLLHUP) ||
           (!events.events & EPOLLIN))
        {
            fprintf (stderr, "epoll error\n");
            close (epoll);
            return 1;
        }
        else
        {
            while (1)
            {
                n = SSL_read (ssl, buf, BUFFER_SIZE);
                if (n <= 0)
                {
                    break;
                }
                buf[n] = 0;
                /* Write the buffer to standard output */
                #ifdef DEBUG
                    printf("Recv : %s\n", buf);
                #endif

                if (method == Put)
                {
                    if (PutMethod(buf, ssl, file))
                    {
                        close(epoll);
                        return 1;
                    }
                    else
                    {
                        close(epoll);
                        return 0;
                    }
                }
                else
                {
                    if (!content)
                    {
                        if (GetMethod(buf, ssl, &content))
                        {
                            close(epoll);
                            return 1;
                        }
                        printf("Remaining get: %d bytes\n", content);
                        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
                        fd = creat(file, mode);
                    }
                    else
                    {
                        #ifdef DEBUG
                            printf("Content: %d\n", content);
                            printf("Recv data len: %d\n", n);
                            printf("Recv : %s\n", buf);
                        #endif
                        printf("Remaining get: %d bytes\n", content);
                        write(fd, buf, n);
                        content -= n;
                        if (!content)
                        {
                            close(epoll);
                            return 0;
                        }
                    }

                }
            }

        }
    }
    close(epoll);
    return 0;
}
