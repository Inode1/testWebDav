// swebdav.c
#include "utility.h"
#include "request.h"

#define FAIL    -1
#define AUTH_DATA_LENGHT 150

/*--------------------------------------------------------------------*/
static char auth_data[AUTH_DATA_LENGHT];
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
   
	while(1)
	{
		int err = SSL_connect(ssl);			/* perform the connection */

		if (err == 1)
		{
			break;
		}
		int err2 = SSL_get_error(ssl,err);
		switch(err2) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					break;
				default:
					printf("SSL_connect err=%s\n",ERR_error_string(err2,0));
					abort();
					break;
		}
	}

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);							/* get any certs */
    if (method == Put)
    {
    	if (RequestPutFile(ssl, auth_data, strings[4]))
    	{
            fprintf(stderr, "Put method fail\n");
            exit(0);
    	}
    }
    else
    {
    	if (RequestGetFile(ssl, auth_data, strings[4]))
    	{
            fprintf(stderr, "Get method fail\n");
            exit(0);
    	}
    }

    SSL_free(ssl);								/* release connection state */
    close(server);									/* close socket */
    SSL_CTX_free(ctx);								/* release context */
    return 0;
}
