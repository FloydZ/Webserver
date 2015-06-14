/*

  SERVREQ.H
  =========
  (c) Copyright Paul Griffiths 1999
  Email: mail@paulgriffiths.net

  Interface to function to server connections.

*/


#ifndef PG_SERVREQ_H
#define PG_SERVREQ_H

/*  Function prototypes  */


#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/opensslconf.h>


int Service_Request(int conn, SSL* ssl);


#endif  /*  PG_SERVREQ_H  */










