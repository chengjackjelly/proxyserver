#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <arpa/inet.h>
#include <iostream>

#define MAXDATASIZE 100 // max number of bytes we can get at once
using std::string;
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int transfer(char const *host, char const *request, char *result)
{
    int sockfd, numbytes;
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char recvBuf[1024] = {0};

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, "80", &hints, &servinfo)) != 0) // TODO first parameter should be delivered from proxy server
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure
    // Set a timeout for the recv operation
    struct timeval timeout;
    timeout.tv_sec = 10; // 10-second timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // test
    request = "GET / HTTP/1.1\r\n"
              "Host: www.example.com\r\n"
              "Connection: close\r\n\r\n";

    // test
    int ret = send(sockfd, request, strlen(request), 0);
    if (ret == -1)
    {
        perror("transfer: send");
        return -1;
    }
    printf("request being sent : %s\n", request);

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

    result = buffer;
    std::cout << "received result : " << result << std::endl;
    close(sockfd);

    return 0;
}
