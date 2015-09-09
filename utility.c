#include <stdint.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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
    int i = 0;
    for(; i < MD5_DIGEST_LENGTH; i++)
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
    int i = 0;
    for(; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(result + (i * 2), "%02x", hash[i]);
    }
    result[2*SHA256_DIGEST_LENGTH + 1] = 0;

    fclose(file);
    return 0;
}

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    printf("Connect openned\n");

    sd = socket(PF_INET, SOCK_STREAM, 0);

    if (fcntl (sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK) == -1)
    {
        perror ("fcntl");
        abort();
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    int status = connect(sd, (struct sockaddr *)&addr, sizeof(addr));

    if (status < 0 && errno != EINPROGRESS)
    {
        close(sd);
        perror(hostname);
        abort();
    }
    if (status != 0)
    {
        struct epoll_event event;
        status = epoll_create1 (0);
        if (status == -1)
        {
        	perror ("epoll_create");
            abort ();
        }
        event.data.fd = sd;
        event.events = EPOLLOUT;
        if (epoll_ctl (status, EPOLL_CTL_ADD, sd, &event) == -1)
        {
        	perror ("epoll_ctl");
            abort ();
        }
        struct epoll_event events;
        if (epoll_wait (status, &events, 1, 2000) <= 0) // 2 second
        {
        	perror ("connect wait error");
            abort ();
        }
        else
        {
        	if (events.events & EPOLLOUT)
        	{
        		int result;
        		socklen_t result_len = sizeof(result);
        		if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0)
        		{
        			perror ("get sock fail");
        			abort ();
        		}

        		if (result != 0) {
        			perror ("get socket error");
        			abort ();
        		}
        	}
        	else
        	{
    			perror ("connect fail");
    			abort ();
        	}

        }
        close(status);

    }

    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitSSL - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitSSL(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();       /* Load cryptos, et.al. */
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();


    //SSL_load_error_strings();         /* Bring in and register error messages */
    if (SSL_library_init() < 0)
    {
        printf("Could not initialize the OpenSSL library");
    }
    method = SSLv23_client_method();        /* Create new client-method instance */
    ctx = SSL_CTX_new(method);          /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);   /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);                         /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);                         /* free the malloc'ed string */
        X509_free(cert);                    /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}
