#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

int main()
{
    // Define the server information
    const char *server_host = "zebroid.ida.liu.se"; // Replace with the server's hostname
    const char *server_port = "80";                 // HTTP default port

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Socket creation failed");
        return 1;
    }

    // Resolve the server's IP address
    struct hostent *server = gethostbyname(server_host);
    if (server == nullptr)
    {
        perror("Host not found");
        close(sockfd);
        return 1;
    }

    // Set up the server address struct
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(server_port));
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Connection failed");
        close(sockfd);
        return 1;
    }

    // Construct the HTTP GET request
    const char *request = "GET http://zebroid.ida.liu.se/fakenews/test1.txt HTTP/1.1\r\n"
                          "Host: zebroid.ida.liu.se\r\n"
                          "Connection: close\r\n\r\n";

    // Send the request
    if (send(sockfd, request, strlen(request), 0) == -1)
    {
        perror("Send failed");
        close(sockfd);
        return 1;
    }

    // Receive and print the response
    char buffer[1024];
    ssize_t bytes_received;
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0)
    {
        buffer[bytes_received] = '\0';
        std::cout << buffer;
    }

    if (bytes_received == -1)
    {
        perror("Receive failed");
    }

    // Close the socket
    close(sockfd);

    return 0;
}
