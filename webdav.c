// swebdav.c
#include "utility.h"
#include "header_template.h"

#define FAIL    -1
#define AUTH_DATA_LENGHT 150
#define HEADER_SIZE 400

/*--------------------------------------------------------------------*/
static char auth_data[AUTH_DATA_LENGHT];
static char header[HEADER_SIZE];
enum EMethod
{
    None,
    Put,
    Get
};

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
    enum EMethod method = None;


    if ( count != 5 )
    {
        printf("usage: %s <login name> <password> <method=[put|get]> <file>\n", strings[0]);
        exit(0);
    }
    // --- get user data ---
	int write_byte = snprintf(auth_data, AUTH_DATA_LENGHT, "%s:%s", strings[1], strings[2]);
	if (write_byte < 0 || write_byte >= AUTH_DATA_LENGHT)
	{
		fprintf(stderr, "login name and pass to big, need resize buffer\n");
		exit(0);
	}

	char* base64EncodeOutput;
	Base64Encode(auth_data, strlen(auth_data), &base64EncodeOutput);	

	write_byte = snprintf(header, HEADER_SIZE, template_header_propfind, base64EncodeOutput);
    if (write_byte < 0 || write_byte >= HEADER_SIZE)
	{
		fprintf(stderr, "Header construct, need resize buffer\n");
		exit(0);
	}
    // --- get user data end ---
    // --- check method ---
    if (!strcmp(strings[3], "put"))
    {
        method = Put;
    }
    else if (!strcmp(strings[3], "get"))
    {
        method = Get;
    }
    else
    {
        fprintf(stderr, "Wrong method use %s. Method support [get and put]\n", strings[3]);
        exit(0);
    }
    // --- check method end---
    // --- check file ---
    if (method == Put)
    {
        if (access(strings[4], R_OK) == FAIL)
        {
            fprintf(stderr, "Can`t access file %s\n", strings[4]);
            exit(0);
        }
    }
    // --- check file end---
    ctx = InitSSL();
    server = OpenConnection("webdav.yandex.ru", 443);
    ssl = SSL_new(ctx);						/* create new SSL connection state */
	SSL_set_fd(ssl, server);				/* attach the socket descriptor */
   
    if (SSL_connect(ssl) == FAIL )			/* perform the connection */
    {
		ERR_print_errors_fp(stderr);
    }
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);								/* get any certs */
    if (method == Put)
    {

    }
    else
    {

    }


    printf("Send : %s\n", header);
    SSL_write(ssl, header, strlen(header));			/* encrypt & send message */
    bytes = SSL_read(ssl, buf, sizeof(buf));	/* get reply & decrypt */
    buf[bytes] = 0;
    printf("Received: \"%s\"\n", buf);

    SSL_free(ssl);								/* release connection state */

    close(server);									/* close socket */
    SSL_CTX_free(ctx);								/* release context */
    return 0;
}
