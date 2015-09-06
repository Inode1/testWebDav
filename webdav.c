// ssl_client.c

/*****************************************************************************/
/*** ssl_client.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL client.                                            ***/
/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utility.h"

#define FAIL    -1
#define AUTH_DATA_LENGHT 150

/*--------------------------------------------------------------------*/
static const char template_header[] = "PROPFIND / HTTP/1.1\r\n"
									  "Host: webdav.yandex.ru\r\n"
								      "Accept: */*\r\n""Depth: 1\r\n"
								      "Authorization: Basic %s\r\n\r\n";
static char auth_data[AUTH_DATA_LENGHT];

#define HEADER_SIZE (AUTH_DATA_LENGHT + sizeof(template_header))
static char header[HEADER_SIZE];



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

	bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
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

    OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();    


	//SSL_load_error_strings();			/* Bring in and register error messages */
	if (SSL_library_init() < 0)
	{
		printf("Could not initialize the OpenSSL library");    
	}
    method = SSLv23_client_method();		/* Create new client-method instance */
    ctx = SSL_CTX_new(method);			/* Create new context */
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

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);							/* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);							/* free the malloc'ed string */
        X509_free(cert);					/* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   
	SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;

    if ( count != 3 )
    {
        printf("usage: %s <login name> <password>\n", strings[0]);
        exit(0);
    }
	int write_byte = snprintf(auth_data, AUTH_DATA_LENGHT, "%s:%s", strings[1], strings[2]);
	if (write_byte < 0 || write_byte >= AUTH_DATA_LENGHT)
	{
		fprintf(stderr, "login name and pass to big, need resize buffer\n");
		exit(0);
	}

	char* base64EncodeOutput;
	Base64Encode(auth_data, strlen(auth_data), &base64EncodeOutput);	

	write_byte = snprintf(header, HEADER_SIZE, template_header, base64EncodeOutput);                                       
    if (write_byte < 0 || write_byte >= HEADER_SIZE)
	{
		fprintf(stderr, "Header construct, need resize buffer\n");
		exit(0);
	}
    ctx = InitSSL();
    server = OpenConnection("webdav.yandex.ru", 443);
	printf("Connect openned\n");
    ssl = SSL_new(ctx);						/* create new SSL connection state */
	SSL_set_fd(ssl, server);				/* attach the socket descriptor */
   
    if (SSL_connect(ssl) == FAIL )			/* perform the connection */
    {
		ERR_print_errors_fp(stderr);
    }
	else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);								/* get any certs */
        printf("Send : %s\n", header);        
        SSL_write(ssl, header, strlen(header));			/* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf));	/* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

        SSL_free(ssl);								/* release connection state */
    }
    close(server);									/* close socket */
    SSL_CTX_free(ctx);								/* release context */
}
