#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

const int CLIENT_BUFFER_SIZE = 4096;
const int SERVER_BUFFER_SIZE = 4096;

int main()
{
    // Create a socket to listen for incoming client connections
    int proxySocket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxySocket == -1)
    {
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    // Define the proxy server's address
    struct sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(3490); // Use the port you want to listen on
    proxyAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the proxy server's address
    if (bind(proxySocket, (struct sockaddr *)&proxyAddr, sizeof(proxyAddr)) == -1)
    {
        std::cerr << "Error binding socket." << std::endl;
        return 1;
    }

    // Start listening for incoming client connections
    if (listen(proxySocket, 10) == -1)
    {
        std::cerr << "Error listening on socket." << std::endl;
        return 1;
    }

    std::cout << "Proxy server is listening on port ..." << std::endl;

    while (true)
    {
        // Accept an incoming client connection
        int clientSocket = accept(proxySocket, NULL, NULL);
        if (clientSocket == -1)
        {
            std::cerr << "Error accepting client connection." << std::endl;
            continue; // Continue listening for other connections
        }
        else
        {
            std::cout << "clientSocket " << clientSocket << std::endl;
        }
        // Create a new thread or process to handle the client request (recommended for concurrent handling)

        // In this example, we handle the request in the main thread
        char clientBuffer[CLIENT_BUFFER_SIZE];
        ssize_t bytesRead;

        // Read the client's request
        bytesRead = recv(clientSocket, clientBuffer, sizeof(clientBuffer), 0);
        if (bytesRead <= 0)
        {
            std::cerr << "Error reading client request." << std::endl;
            close(clientSocket);
            continue; // Continue listening for other connections
        }
        std::cout << clientBuffer << std::endl;
        // Resolve the server's IP address
        struct hostent *server = gethostbyname("zebroid.ida.liu.se");
        if (server == nullptr)
        {
            perror("Host not found");
            return 1;
        }
        // Set up the server address struct
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(atoi("80"));
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

        // Create a socket to connect to the target server
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1)
        {
            std::cerr << "Error creating server socket." << std::endl;
            close(clientSocket);
            continue; // Continue listening for other connections
        }

        // Connect to the target server
        if (connect(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        {
            std::cerr << "Error connecting to target server." << std::endl;
            close(clientSocket);
            close(serverSocket);
            continue; // Continue listening for other connections
        }

        // Forward the client's request to the target server
        if (send(serverSocket, clientBuffer, bytesRead, 0) == -1)
        {
            std::cerr << "Error forwarding request to target server." << std::endl;
            close(clientSocket);
            close(serverSocket);
            continue; // Continue listening for other connections
        }

        // Receive the server's response
        char serverBuffer[SERVER_BUFFER_SIZE];
        bytesRead = recv(serverSocket, serverBuffer, sizeof(serverBuffer), 0);
        if (bytesRead <= 0)
        {
            std::cerr << "Error receiving server response." << std::endl;
            close(clientSocket);
            close(serverSocket);
            continue; // Continue listening for other connections
        }

        // Forward the server's response to the client
        if (send(clientSocket, serverBuffer, bytesRead, 0) == -1)
        {
            std::cerr << "Error forwarding response to client." << std::endl;
            close(clientSocket);
            close(serverSocket);
            continue; // Continue listening for other connections
        }

        // Close both client and server sockets
        close(clientSocket);
        close(serverSocket);
    }

    // Close the proxy socket (not reached in this example)
    close(proxySocket);

    return 0;
}
