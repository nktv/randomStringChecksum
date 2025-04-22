#include "common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#define SECURE_FREE_SSL_CONTEXT(sslContext) \
    if (sslContext) { \
        SSL_CTX_free(sslContext); \
        sslContext = nullptr; \
    } \

#define SECURE_FREE_SSL(ssl) \
    if (ssl) { \
        SSL_shutdown(ssl); \
        SSL_free(ssl); \
        ssl = nullptr; \
    } \

class ServerConnection {
    public:
        ServerConnection(string hostName, int port, string certificate, string pvtKey);        
        ~ServerConnection();
        bool Connect();
        string ReadLine();
        void writeLine(string data);

        void DestroySSL();
        

    private:
        string hostName;
        int port;
        string certificate;
        string pvtKey;
      
        SSL_CTX* sslContext{nullptr};
        SSL* ssl{nullptr};

        void InitializeSSL();
};