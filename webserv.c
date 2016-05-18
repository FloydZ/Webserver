#include <sys/socket.h>       /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <sys/wait.h>         /*  for waitpid()             */
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <unistd.h>           /*  misc. UNIX functions      */


#include <stdio.h>
#include <stdlib.h>


#include "helper.h"
#include "logger.h"
#include "servreq.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/opensslconf.h>


#define SERVER_PORT            (8087)

static char server_log[100] = "/Users/floyd/Downloads/webserv/log.txt";

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

SSL_CTX* InitServerCTX(void){
    SSL_CTX *ctx;

    (void)SSL_library_init();
    SSL_load_error_strings();
    /*OPENSSL_config(NULL);*/



    #if defined (OPENSSL_THREADS)
        fprintf(stdout, "Warning: thread locking is not implemented\n");
    #endif

    OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
    SSL_METHOD *method = SSLv2_server_method();		/* create new server-method instance */
    ctx = SSL_CTX_new(method);			/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl){
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*  main() funcion  */

int main(int argc, char *argv[]) {
    int    listener, conn;
    pid_t  pid;
    SSL *ssl;
    SSL_CTX *ctx;
    struct sockaddr_in servaddr, addr;

    tp_log_init("log.txt",1);

    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "servercert.pem", "serverkey.pem"); /* load certs */

    /*SSL_library_init();*/


    /*  Create socket  */
    if ( (listener = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
	Error_Quit("Couldn't create listening socket.");

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(SERVER_PORT);

    if ( bind(listener, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 )
	Error_Quit("Couldn't bind listening socket.");

    if ( listen(listener, LISTENQ) < 0 )
	Error_Quit("Call to listen failed.");

    while ( 1 ) {
        int len = sizeof(addr);
        if ( (conn = accept(listener, (struct sockaddr *) &addr, &len)) < 0 )
            Error_Quit("Error calling accept()");

        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        if ( (pid = fork()) == 0 ) {
            /*  This is now the forked child process, so
            close listening socket and service request   */

            if ( close(listener) < 0 )
                Error_Quit("Error closing listening socket in child.");

            ssl = SSL_new(ctx);                  /* get new SSL state with context */
            SSL_set_fd(ssl, conn);              /* set connection socket to SSL state */

            Service_Request(conn, ssl);
            ShowCerts(ssl);
            if ( close(conn) < 0 )
                Error_Quit("Error closing connection socket.");
            exit(EXIT_SUCCESS);
	}

	if ( close(conn) < 0 )
	    Error_Quit("Error closing connection socket in parent.");

	waitpid(-1, NULL, WNOHANG);
    }

    return EXIT_FAILURE;    /*  We shouldn't get here  */
}


