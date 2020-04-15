#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <pthread.h>
#include <stdbool.h>
#define FAIL    -1


socklen_t addr_size;
const char REGIS[10] = "REGISTER#";
const char EXIT[5] = "Exit";
const char LIST[5] = "LIST";
char accountList[100][100] = {0};
char ipList[100][100] = {0};
char portList[100][100] = {0};
int balanceList[100] = {0};
int accountListLength = 0;
bool onlineList[100] = {0};
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
//pthread_cond_t condVar = PTHREAD_COND_INITIALIZER;
//int serverSocket, newSocket;
//struct sockaddr_in serverAddr;
//struct sockaddr_storage serverStorage;


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
    puts("Connection OK");
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
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
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
void * Servlet(void *a) /* Serve the connection -- threadable */
{
    int count = 0;
    char countStr[3]={0};
    struct1 *b;
    b=(struct1*)a;
    bool login = false;
    char accountName[100] = {0};
    char buffer[1024];
    char client_message[100] = {0};
    char portNum[100] = {0};
    char receivedMessage[100] = {0};
    char ipAddr[14];
    SSL* newSocket = (SSL *)b->ssl;
    strcpy(ipAddr, b->ip);

    //char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse = "Hello";
    if ( SSL_accept(newSocket) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        //ShowCerts(newSocket);        /* get any certificates */
        //bytes = SSL_read(ssl, client_message, sizeof(client_message)); /* get request */
        //client_message[bytes] = '\0';
        //printf("Client msg: \"%s\"\n", client_message);
        //if ( bytes > 0 )
        //    SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
        //else
        //    ERR_print_errors_fp(stderr);

        strcpy(buffer, "Connection accepted\r\n");
        SSL_write(newSocket,buffer,sizeof(buffer));
        while((bytes = SSL_read(newSocket, client_message, sizeof(client_message))))
        {


            char *message = malloc(1024);
            char* found;
            char* found2 = NULL;
            char tempAcc[1024];
            int poundNext = 0;
            int endPlace = 0;
            bool accountExist = 0;
            bool registered = 0;
            bool payBool = false;
            memset(receivedMessage, 0, sizeof(receivedMessage));
            char tempClientMessage[100];
            memset(tempClientMessage, 0, 100);
            memset(buffer,0,1024);
            memset(message,0,1024);
            client_message[bytes] = '\0';
            if(strcmp(client_message, "") != 0)
                printf("Client msg: \"%s\"\n", client_message);
            strcpy(tempClientMessage, client_message);
            //printf("Client msg: \"%s\"\n", tempClientMessage);

            pthread_mutex_lock(&lock);
            found = strchr(client_message, '#');
            if(found != NULL)
                found2 = strchr(found+1, '#');
            endPlace = strlen(client_message);
            poundNext = found - client_message + 1;//find the next place of #
            if(endPlace-poundNext > 1 &&  endPlace-poundNext < 101){
                //found = strstr(client_message, "\r\n");
                //endPlace = found - client_message;
                strncpy(receivedMessage, client_message, poundNext);
                if(strcmp(receivedMessage,REGIS) == 0){
                    if(endPlace - poundNext != 0){
                        for(int i = 0; i < endPlace - poundNext; i++){
                            accountName[i] = client_message[poundNext+i];
                        }
                        for(int i = 0; i < accountListLength; i++){
                            if(strcmp(accountName, accountList[i]) == 0){
                                accountExist = true;
                                strcpy(message,"210 FAIL\r\n");
                            }
                        }
                    }
                    else{
                        strcpy(message,"210 FAIL\r\n");
                    }
                    //Check if the account name already exists.
                    if(!accountExist){
                        if(accountListLength < 100){
                            strcpy(message,"100 OK\r\n");
                            strcpy(portList[accountListLength], "0");
                            strcpy(ipList[accountListLength], ipAddr);
                            balanceList[accountListLength] = 10000;
                            onlineList[accountListLength] = 0;
                            strcpy(accountList[accountListLength], accountName);
                            accountListLength++;
                        }
                        else
                            strcpy(message,"The amount of accounts is out of range.\r\n");
                    }
                }
                else if(!login){
                    if(endPlace - poundNext == 0){
                        strcpy(message,"Port number can't be blank\r\n");
                    }
                    strncpy(accountName, client_message, poundNext-1);
                    for(int i = 0; i < endPlace - poundNext; i++){
                        portNum[i] = client_message[poundNext+i];
                    }
                    for(int i = 0; i <= accountListLength; i++){
                        if(strcmp(accountName, accountList[i]) == 0){
                            registered = 1;
                            int onlineCount = 0;
                            onlineList[i] = 1;
                            login = true;
                            strcpy(portList[i], portNum);
                            for(int j = 0; j <= accountListLength; j++){
                                if(onlineList[j] == 1)
                                    onlineCount++;
                            }
                            char balanceChar[10];
                            char onlineChar[10];
                            sprintf(balanceChar,"%d",balanceList[i]);
                            sprintf(onlineChar,"%d",onlineCount);
                            strcat(message, "Balance: ");
                            strcat(message, balanceChar);
                            strcat(message, "\r\n");
                            strcat(message, "Accounts online: ");
                            strcat(message, onlineChar);
                            strcat(message, "\r\n");
                            for(int j = 0; j <= accountListLength; j++){
                                if(onlineList[j] == 1){
                                    strcat(message, accountList[j]);
                                    strcat(message, "#");
                                    strcat(message, ipList[j]);
                                    strcat(message, "#");
                                    strcat(message, portList[j]);
                                    strcat(message, "\r\n");
                                }
                            }
                        }
                    }
                    if(!registered)
                        strcpy(message,"220 AUTH_FAIL1\r\n");
                    
                }
                else if(found2 != NULL && login){
                        char* poundNext2;
                        char* poundNext3;
                        char* found3 = strchr(client_message, '\n');
                        char* foundName;
                        char clientA[100];
                        char clientB[100];
                        char moneyChar[100];
                        int money = 0;
                        endPlace = strlen(client_message);
                        poundNext = found3 - found2;//find the next place of #

                        strncpy(clientA, found2+1, poundNext-1);
                        //puts(receivedMessage);
                        
                        found = strchr(client_message, '#');
                        found2 = strchr(found+1, '#');
                        found3 = strchr(found2+1, '\n');
                        endPlace = strlen(client_message);
                        poundNext = found - client_message;
                        poundNext2 = found2 - found;
                        poundNext3 = found3 - found2;
                        if(endPlace - poundNext > 1 && endPlace - poundNext < 1000){
                            memset(clientA, 0, 100);
                            memset(moneyChar, 0,100);
                            memset(clientB, 0, 100);
                            strncpy(clientA, client_message, poundNext);
                            strncpy(moneyChar, found+1, poundNext2-1);
                            strncpy(clientB, found2+1, poundNext3-1);
                            //puts(clientA);
                            //puts(moneyChar);
                            //puts(clientB);
                            money = atoi(moneyChar);
                        }
                        strcat(clientA,"\n");
                        strcat(clientB,"\n");
                        for(int i = 0; i <= accountListLength; i++){
                            //memset(tempAcc, 0, 1024);
                            //strcpy(tempAcc,accountList[i]);
                            //puts(accountList[i]);
                            //puts("///");
                            //puts(clientA);
                            //puts("----");
                            if(strcmp(clientA, accountList[i]) == 0){
                                for(int j = 0; j <= accountListLength; j++){
                                    if(strcmp(clientB, accountList[j]) == 0){
                                        balanceList[i] = balanceList[i] - money;
                                        balanceList[j] = balanceList[j] + money;
                                        puts("success");
                                        payBool = true;
                                        //strcat(message, "PaymentSuccess");
                                    }
                                } 
                            }
                        } 
                        found2 = NULL;      
                    }
            }
            else if((strcmp(client_message, "List\n") == 0 || strcmp(tempClientMessage, "List\n") == 0) && login){
                //printf("444: \"%s\"\n", tempClientMessage);
                for(int i = 0; i <= accountListLength; i++){
                    if(strcmp(accountName, accountList[i]) == 0){
                        registered = 1;
                        int onlineCount = 0;
                        onlineList[i] = 1;
                        login = true;
                        strcpy(portList[i], portNum);
                        for(int j = 0; j <= accountListLength; j++){
                            if(onlineList[j] == 1)
                                onlineCount++;
                        }
                        char balanceChar[10];
                        char onlineChar[10];
                        sprintf(balanceChar,"%d",balanceList[i]);
                        sprintf(onlineChar,"%d",onlineCount);
                        strcat(message, "Balance: ");
                        strcat(message, balanceChar);
                        strcat(message, "\r\n");
                        strcat(message, "Accounts online: ");
                        strcat(message, onlineChar);
                        strcat(message, "\r\n");
                        for(int j = 0; j <= accountListLength; j++){
                            if(onlineList[j] == 1){
                                strcat(message, accountList[j]);
                                strcat(message, "#");
                                strcat(message, ipList[j]);
                                strcat(message, "#");
                                strcat(message, portList[j]);
                                strcat(message, "\r\n");
                            }
                        }
                    }
                }
            }
            else if(login && strcmp(client_message, "Exit\n") == 0){
                for(int i = 0; i <= accountListLength; i++){
                    if(strcmp(accountName, accountList[i]) == 0)
                        onlineList[i] = 0;
                }
                strcpy(message, "Bye\r\n");
                strcpy(buffer,message);
                SSL_write(newSocket, buffer, strlen(buffer)); /* send reply */
                //send(newSocket,buffer,sizeof(buffer),0);
                pthread_mutex_unlock(&lock);
                sleep(1);
                break;
            }
            else{
                //printf("555: \"%s\"\n", tempClientMessage);
                if(login){
                    strcat(message, "220 AUTH_FAIL2");
                    strcat(message,tempClientMessage);
                    strcat(message, "\n");
                }
                else
                    strcat(message, "220 AUTH_FAIL3\r\n");
            }
            //printf("666: \"%s\"\n", tempClientMessage);
            
            //strcat(message, client_message);
            strcpy(buffer,message);
            //if ( bytes > 0 )
            if(!payBool && strcmp(client_message,"") != 0)
                SSL_write(newSocket, buffer, strlen(buffer)); /* send reply */
            //else
                //ERR_print_errors_fp(stderr);    
            //write(newSocket,buffer,sizeof(buffer));
            memset(client_message, 0, sizeof(client_message));
            //sleep(1);
            pthread_mutex_unlock(&lock);
            sleep(1);
            
            //free(client_message);
            //free(buffer);

        }
    close(newSocket);
    //free(message);
    sleep(1);
    printf("Exit socketThread \n");
    pthread_exit(NULL); 


    }
    sd = SSL_get_fd(newSocket);       /* get socket connection */
    SSL_free(newSocket);         /* release SSL state */
    close(sd);          /* close connection */
}


int main()
{
    SSL_CTX *ctx;
    //int server;
    int PORTNUM = 8888;
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    int socket_desc, new_socket;
    pthread_t tid[2];
    int threadAmount = 0;
    struct1 *new_sock;
    socklen_t c;
    struct sockaddr_in server , client;
    char *message;

    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    socket_desc = OpenListener(PORTNUM);    /* create server socket */
    SSL *ssl;

    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, &c)) )
    {    
        printf("Connection: %s:%d\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, new_socket);      /* set connection socket to SSL state */
        char ip[INET_ADDRSTRLEN];
        inet_ntop(PF_INET, &(client.sin_addr), ip, INET_ADDRSTRLEN);
        
        pthread_t sniffer_thread;
        new_sock = (struct1 *)malloc(sizeof(struct1));
        new_sock->ssl = ssl;
        strcpy(new_sock->ip, ip);

        
        if(pthread_create( &sniffer_thread , NULL ,  Servlet , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
        
        if(threadAmount >= 2)
        {
          threadAmount = 0;
          while(threadAmount < 2)
          {
            pthread_join(tid[threadAmount++],NULL);
          }
          threadAmount = 0;
        }
        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( sniffer_thread , NULL);
        puts("Handler assigned");
    }
    close(new_socket);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
