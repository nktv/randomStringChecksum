#include "ServerConnection.h"


ServerConnection::ServerConnection(string hostName, int port, string certificate, string pvtKey) {
    this->hostName = hostName;
    this->port = port;
    this->certificate = certificate;
    this->pvtKey = pvtKey;
}

ServerConnection::~ServerConnection() {
    DestroySSL();
}

void ServerConnection::InitializeSSL()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void ServerConnection::DestroySSL()
{
    SECURE_FREE_SSL(ssl);
    SECURE_FREE_SSL_CONTEXT(sslContext);
    ERR_free_strings();
    EVP_cleanup();
}

bool ServerConnection::Connect()
{
    InitializeSSL();    

    sslContext = SSL_CTX_new(TLS_client_method());
    if (!sslContext) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Failed to create SSL context");
        return false;
    }

    INFO_LOG("hostname: " << this->hostName);
    INFO_LOG("port: " << this->port);
    INFO_LOG("certificate: " << this->certificate);
    INFO_LOG("private key: " << this->pvtKey);

    if (SSL_CTX_use_certificate_file(sslContext, certificate.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Unable to load certificate file");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, pvtKey.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Unable to load private key file");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        return false;
    }

    if (!SSL_CTX_check_private_key(sslContext)) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Private key does not match the certificate public key");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        return false;
    }

    INFO_LOG("SSL context initialized successfully");


    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Unable to create socket connection");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        return false;
    }


    struct hostent* host = gethostbyname(this->hostName.c_str());
    if (host == nullptr) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Unable to resolve host name");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        close(fd);
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(this->port);
    server_addr.sin_addr = *(struct in_addr*)host->h_addr;

    if (connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Connection failed!");
        SECURE_FREE_SSL_CONTEXT(sslContext);
        close(fd);
        return false;
    }

    INFO_LOG("Connected to server successfully");

    ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("SSL handshake failed");
        DestroySSL();
        close(fd);
        return false;
    }

    INFO_LOG("SSL handshake completed successfully");
    return true;
}

string ServerConnection::ReadLine() {
    char buffer[1024] ={0};
    int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytesRead <= 0) {
        int ssl_err = SSL_get_error(ssl, bytesRead);
        std::cerr << "SSL_read failed with code: " << ssl_err << std::endl;

        switch (ssl_err) {
            case SSL_ERROR_ZERO_RETURN:
                std::cerr << "Connection closed cleanly by peer\n";
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                std::cerr << "Non-blocking mode: try again\n";
                break;
            case SSL_ERROR_SYSCALL:
                perror("Syscall error");
                break;
            default:
                ERR_print_errors_fp(stderr);
                break;
        }

        ERROR_LOG("SSL_read failed with error code: " << ssl_err);
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Failed to read from server. BytesRead: " << bytesRead);
        return "";
    }

    buffer[bytesRead] = '\0';
    string dataRead = string(buffer);
    INFO_LOG("Data read from server: " << dataRead);
    return dataRead;
}

void ServerConnection::writeLine(string data) {
    if(!ssl) {
        ERROR_LOG("SSL connection is not established");
        return;
    }
    
    int bytesWritten = SSL_write(ssl, data.c_str(), data.length());
    if (bytesWritten <= 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Failed to write data to server" << data);
        return;
    }

    INFO_LOG("Data written to server: " << data << " bytes: " << bytesWritten);
    return;
}

/*
void ServerConnection::writeLine(const char* data, size_t len) {
    int bytesWritten = SSL_write(ssl, data, len);
    if (bytesWritten <= 0) {
        ERR_print_errors_fp(stderr);
        ERROR_LOG("Failed to write data to server" << data);
        return;
    }

    INFO_LOG("Data written to server: " << data << " bytes: " << bytesWritten);
    return;
}
*/
