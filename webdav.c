/*
 * webdav.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NE_DEBUGGING

#include <neon/ne_utils.h>
#include <neon/ne_socket.h>
#include <neon/ne_session.h>
#include <neon/ne_auth.h>
#include <neon/ne_request.h>

void dump_cert(const ne_ssl_certificate *cert) {
  const char *id = ne_ssl_cert_identity(cert);
  char *dn;

  if (id)
    printf("Certificate was issued for '%s'.\n", id);

  dn = ne_ssl_readable_dname(ne_ssl_cert_subject(cert));
  printf("Subject: %s\n", dn);
  free(dn);

  dn = ne_ssl_readable_dname(ne_ssl_cert_issuer(cert));
  printf("Issuer: %s\n", dn);
  free(dn);
}

static int
my_verify(void *userdata, int failures, const ne_ssl_certificate *cert)
{
  const char *hostname = userdata;

  dump_cert(cert);

  puts("Certificate verification failed - the connection may have been "
       "intercepted by a third party!");

  if (failures & NE_SSL_IDMISMATCH) {
    const char *id = ne_ssl_cert_identity(cert);
    if (id)
      printf("Server certificate was issued to '%s' not '%s'.\n",
             id, hostname);
    else
      printf("The certificate was not issued for '%s'\n", hostname);
  }

  if (failures & NE_SSL_UNTRUSTED)
    puts("The certificate is not signed by a trusted Certificate Authority.");

  /* ... check for validity failures ... */

/*  if (prompt_user())
    return 1;  fail verification
  else
    return 0;  trust the certificate anyway */
    return 0;
}

static int
my_auth(void *userdata, const char *realm, int attempts,
        char *username, char *password)
{
    printf("Use pass and username\n");
    strncpy(username, "iv.test2016", 50);
    strncpy(password, "zreirby", 50);
    return attempts;
}

int main()
{
    // init neon lib
    if (ne_sock_init())
    {
        printf("Error when try init neon library\n");
    }

    ne_session *sess = ne_session_create("https", "webdav.yandex.ru", 443);
    printf("Error was: %s\n", ne_get_error(sess));
    ne_ssl_set_verify(sess, my_verify, "webdav.yandex.ru");
    ne_set_server_auth(sess, my_auth, NULL);
    /* ne_request_dispatch: Sends the given request, and reads the
     * response.  Returns:
     *  - NE_OK if the request was sent and response read successfully
     *  - NE_AUTH, NE_PROXYAUTH for a server or proxy server authentication error
     *  - NE_CONNECT if connection could not be established
     *  - NE_TIMEOUT if an timeout occurred sending or reading from the server
     *  - NE_ERROR for other fatal dispatch errors
     * On any error, the session error string is set.  On success or
     * authentication error, the actual response-status can be retrieved using
     * ne_get_status(). */
    ne_request *req = ne_request_create(sess, "PROPFIND", "/Music");
    int status;

    if ((status = ne_request_dispatch(req)) == NE_OK) {
        ne_read_response_to_fd(req, 1);
/*        int status = ne_discard_response(req);
        printf("Status: %d", status);
        const char *mtime = ne_get_response_header(req, "Last-Modified");
        if (mtime) {
            printf("/foo.txt has last-modified value %s\n", mtime);
        }*/
    }
    ne_request_destroy(req);
    printf("Status: %d", status);
    printf("Error was: %s\n", ne_get_error(sess));
    ne_sock_exit();
    return 0;

}
