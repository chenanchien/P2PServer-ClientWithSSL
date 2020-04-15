#include <stdio.h>
#include <errno.h>
#include <unistd.h>
//#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1

int myPort = 0;
int clientPortInt = 0;
char clientIP[12];
char clientPort[10];
char threadMessage[100];

struct test
{
    char ip[14];
    SSL* ssl;
};
typedef struct test struct1;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    //puts("Connection OK");
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method = TLSv1_2_client_method();;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    //method  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method = TLSv1_2_server_method();
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    //method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
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

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

void* ListenPayment(void* a){
    SSL_CTX *ctx;
    //Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    int socket_desc, new_socket;
    pthread_t tid[2];
    int threadAmount = 0;
    int bytes = 0;
    struct1 *new_sock;
    socklen_t c;
    struct sockaddr_in server , client;
    char client_message[1024] = {0};
    struct1 *b;
    b=(struct1*)a;
    SSL* serverSSL = (SSL *)b->ssl;



    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    socket_desc = OpenListener(myPort);    /* create server socket */
    

    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, &c)) )
    {    
        //puts("1111");
        //printf("%s\n", inet_ntoa(client.sin_addr));
        //printf("Connection: %s:%d\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        SSL *ssl;
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, new_socket);      /* set connection socket to SSL state */

        
        if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
            ERR_print_errors_fp(stderr);
        else
        {
            //puts("2222");
            bytes = SSL_read(ssl, client_message, sizeof(client_message));
            //puts(client_message);
            client_message[bytes] = '\0';
            //puts("4444");
            SSL_write(serverSSL,client_message, sizeof(client_message));
            //puts("5555");
        }
        SSL_CTX_free(ctx);/* release context */
        close(new_socket);
    }
             
}

void* sendClient(){
    struct sockaddr_in serverAddrPayment;
    socklen_t addr_sizePayment;
    int clientSocketPayment = socket(PF_INET, SOCK_STREAM, 0);
    SSL_CTX *ctxPayment;
    SSL *sslPayment;
    ctxPayment = InitCTX();
    serverAddrPayment.sin_port = htons(clientPortInt);
    serverAddrPayment.sin_family = AF_INET;

    //Set IP address to localhost
    serverAddrPayment.sin_addr.s_addr = inet_addr(clientIP);
    memset(serverAddrPayment.sin_zero, '\0', sizeof(serverAddrPayment.sin_zero));
    //Connect the socket to the server using the address
    addr_sizePayment = sizeof(serverAddrPayment);
    connect(clientSocketPayment, (struct sockaddr *) &serverAddrPayment, addr_sizePayment);  
    sslPayment = SSL_new(ctxPayment);      /* create new SSL connection state */
    SSL_set_fd(sslPayment, clientSocketPayment);    /* attach the socket descriptor */
    if ( SSL_connect(sslPayment) == FAIL ){   /* perform the connection */
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(sslPayment));
        ShowCerts(sslPayment);
        //SSL_write(sslPayment,message,sizeof(message));
        if( SSL_write(sslPayment,threadMessage, strlen(threadMessage)) < 0)
        {
            printf("Send failed\n-------------\n");
        }
    }
    SSL_free(sslPayment);        /* release connection state */
    close(clientSocketPayment);
    SSL_CTX_free(ctxPayment);        /* release context */  
    return;
}

int main()
{
    SSL_library_init();
    SSL_CTX *ctx;
    SSL *ssl;
    ctx = InitCTX();
    char buf[1024];
    char acClientRequest[1024] = {0};
    char message[100];
    char buffer[1024];
    char List[1024];
    char IP[20] = "127.0.0.1";
    //char message[100];
    int i = 0;
    int bytes;
    int clientSocket;
    //int portNum = 3000;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    puts("¯|(ツ)_/¯******LINK START*******¯|_(ツ)_/¯");
    puts("--GUI--GUI--GUI--GUI--GUI--GUI--");
    //Set IP
    printf("------------\nPlease set the IP address : ");
    //scanf("%s", IP);
    puts("------------");
    //Set port number, using htons function
    printf("Port number: ");
    scanf("%d", &myPort);
    puts("------------"); 
    serverAddr.sin_port = htons(8888);
    
    //Set IP address to localhost
    serverAddr.sin_addr.s_addr = inet_addr(IP);
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
    //Connect the socket to the server using the address
    addr_size = sizeof(serverAddr);
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
    

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, clientSocket);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

        pthread_t sniffer_thread;
        struct1 *new_sock;
        new_sock = (struct1 *)malloc(sizeof(struct1));
        new_sock->ssl = ssl;
        
        if(pthread_create( &sniffer_thread , NULL ,  ListenPayment , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
        
        while(1){
            //memset(buffer, 0, 1024);
            //Read the message from the server into the buffer
            memset(message, 0, strlen(message));
             /* get reply & decrypt */
            
            printf("Your message: ");
            scanf("%s", message);
            printf("-------------\n");



            strcat(message,"\n");


            //transaction
            //char List[1024];

            char tempMessage[100];
            char* found;
            char* found2 = NULL;
            char* found3;
            char* foundName;
            int poundNext = 0;
            int poundNext2 = 0;
            int endPlace = 0;

            //strcat(List, "kevin#127.0.0.1#3000\ncoco#127.0.0.1#8888\n");
            //strcat(client_message, "jojo#3000#kevin\n");

            found = strchr(message, '#');
            if(found != NULL){
                found2 = strchr(found+1, '#');
                found3 = strchr(message, '\n');
                poundNext = found3 - found2;//find the next place of #

            }
            endPlace = strlen(message);

            if(found2 != NULL){
                strncpy(tempMessage, found2+1, poundNext-1);
                //puts(tempMessage);
                foundName = strstr(List, tempMessage);
                if(foundName != NULL){
                    found = strchr(foundName, '#');
                    found2 = strchr(found+1, '#');
                    found3 = strchr(found2+1, '\n');
                    endPlace = strlen(foundName);
                    poundNext = found2 - found;
                    poundNext2 = found3 - found2;

                    if(found3 != NULL){
                        strncpy(clientIP, found+1, poundNext-1);
                        strncpy(clientPort, found2+1, poundNext2-1);
                        clientPortInt = atoi(clientPort);

                        pthread_t payThread;
                        memset(threadMessage, 0, strlen(threadMessage));
                        strcpy(threadMessage, message);
                        if(pthread_create( &payThread , NULL ,  sendClient))
                        {
                            perror("could not create thread");
                            return 1;
                        }
                        
                    }
                }
                found2 = NULL; 
                memset(tempMessage, 0 ,100);
            }
            //transaction
            else{
                memset(buffer, 0, 1024);
                /* encrypt & send message */
                if( SSL_write(ssl,message, strlen(message)) < 0)
                {
                    printf("Send failed\n-------------\n");
                }
                bytes = SSL_read(ssl, buffer, sizeof(buffer));
                if(bytes < 0)
                {
                   printf("Receive failed\n-------------\n");
                }
                //Print the received message
                buffer[bytes] = 0;
                if(strcmp(message, "List\n") == 0 || strcmp(buffer, "100OK\n") == 0){
                    strcpy(List, buffer);
                }
                printf("Server: %s------------\n",buffer);
                if(strcmp(buffer, "Bye") == 0){
                    break;
                }
            }            
        }  
    }
    SSL_free(ssl);        /* release connection state */
    printf("¯|_(ツ)_/¯Connection end¯|_(ツ)_/¯");
    close(clientSocket);
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
 

