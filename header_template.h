/*
 * header_template.h
 */

#ifndef HEADER_TEMPLATE_H_
#define HEADER_TEMPLATE_H_

// PROPFIND
static const char template_header_propfind[] = "PROPFIND / HTTP/1.1\r\n"
                                                 "Host: webdav.yandex.ru\r\n"
                                                 "Accept: */*\r\n""Depth: 1\r\n"
                                                 "Authorization: Basic %s\r\n\r\n";
// GET. Upload file
static const char template_header_get[] = "GET /%s HTTP/1.1\r\n"
                                            "Host: webdav.yandex.ru\r\n"
                                            "Accept: */*\r\n""Depth: 1\r\n"
                                            "Authorization: Basic %s\r\n\r\n";
// PUT. Load file
static const char template_header_put[] = "PUT /%s HTTP/1.1\r\n"
                                            "Host: webdav.yandex.ru\r\n"
                                            "Accept: */*\r\n""Depth: 1\r\n"
                                            "Authorization: Basic %s\r\n"
                                            "Etag: %s\r\n"          // md5 hash sum
                                            "Sha256: %s\r\n"        // sha256
                                            "Expect: 100-continue/r/n"  // server verify load file
                                            "Content-Type: application/binary/r/n"
                                            "Content-Length: %s/r/n/r/n";

#endif /* HEADER_TEMPLATE_H_ */
