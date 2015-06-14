/*

  SERVREQ.C
  =========
  (c) Copyright Paul Griffiths 1999
  Email: mail@paulgriffiths.net

  Implementation of function to service requests.

*/


#include <stdio.h>
#include <errno.h>

#include "helper.h"
#include "reqhead.h"
#include "resphead.h"
#include "resource.h"
#include "logger.h"


#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/opensslconf.h>


/*  Service an HTTP request  */

int Service_Request(int conn, SSL* ssl) {

    struct ReqInfo  reqinfo;
    int             resource = 0;


    InitReqInfo(&reqinfo);

    /*  Get HTTP request  */


    if ( SSL_accept(ssl) == SSL_ERROR_SSL )					/* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        char buf[1024];
        int bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);

        }
    }

    if ( Get_Request(conn, &reqinfo) < 0 )
    return -1;

    tp_syslog(1, "Requested %s by %s", reqinfo.resource, reqinfo.useragent);

    /*  Check whether resource exists, whether we have permission
	to access it, and update status code accordingly.          */

    if ( reqinfo.status == 200 )
	if ( (resource = Check_Resource(&reqinfo)) < 0 ) {
	    if ( errno == EACCES )
		reqinfo.status = 401;
	    else
		reqinfo.status = 404;
	}

    /*  Output HTTP response headers if we have a full request  */

    if ( reqinfo.type == FULL )
	Output_HTTP_Headers(conn, &reqinfo);


    /*  Service the HTTP request  */

    if ( reqinfo.status == 200 ) {
	if ( Return_Resource(conn, resource, &reqinfo) )
	    Error_Quit("Something wrong returning resource.");
    }
    else
	Return_Error_Msg(conn, &reqinfo);

    if ( resource > 0 )
	if ( close(resource) < 0 )
	    Error_Quit("Error closing resource.");
    FreeReqInfo(&reqinfo);

    return 0;
}




