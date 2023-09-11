/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include <algorithm>
#include <cstring>

#include "transfer.cpp"

const size_t BUFFER_SIZE = 2048; //
#define PORT "3490"              // the port users will be connecting to
#define BACKLOG 10               // how many pending connections queue will hold
bool isGetRequest(char *request)
{
    char *get = strstr(request, "GET");
    return get != NULL;
}
int getHostFromRequest(char *request, char *&host)
{
    char *hostHeader = strstr(request, "Host:");
    if (hostHeader != NULL)
    {
        hostHeader += strlen("Host:");
        while (*hostHeader == ' ' || *hostHeader == '\t')
        {
            hostHeader++;
        }
        char *hostEnd = strpbrk(hostHeader, "\r\n");
        if (hostEnd != NULL)
        {
            size_t hostLength = hostEnd - hostHeader;

            host = (char *)malloc(hostLength + 1);
            strncpy(host, hostHeader, hostLength);
            host[hostLength] = '\0';
            printf("Host: %s\n", host);
            return 1;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
}
void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

int main(void)
{
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char recvBuf[2048] = {0};

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        // encope with "Address already in use" error msg by reusing the port
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while (1)
    {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);

        int num = recv(new_fd, recvBuf, sizeof(recvBuf), 0);
        if (num == -1)
        {
            perror("read");
            exit(-1);
        }
        else if (num > 0)
        {

            printf("recv client data : %s\n", recvBuf);
            // transfer request to target server
            if (!isGetRequest(recvBuf))
            {
                std::cout << "Proxy only support GET Request!" << std::endl;
                close(new_fd);
                continue;
            }
            char *host;
            if (getHostFromRequest(recvBuf, host) == -1)
            {
                std::cerr << "Error occur when try to Parse host from request";
                const char *BAD_REQUEST_400 = "HTTP/1.1 400 Bad Request\r\n"
                                              "Content-Type: text/plain\r\n"
                                              "Content-Length: 23\r\n\r\n"
                                              "Bad Request: Invalid URL\r\n";

                int ret = send(new_fd, BAD_REQUEST_400, sizeof(BAD_REQUEST_400), 0);
                if (ret == -1)
                {
                    perror("sent: ");
                }
                close(new_fd);
                continue;
            }
            // TODO change the URL for image in GET request
            char *request = recvBuf;
            char *response_from_proxy_client;
            size_t total_size_of_response;
            size_t bytes_sent = 0;

            if (transfer(host, request, response_from_proxy_client, total_size_of_response) == -1)
            {
                perror("client: transfer");
                close(new_fd);
                continue;
            }
            int sent_bytes = send(new_fd, response_from_proxy_client, total_size_of_response, 0);
            if (sent_bytes == -1)
            {
                perror("sent: ");
            }

            free(host);
            free(response_from_proxy_client);
        }
        else if (num == 0)
        {

            printf("client closed...");
        }

        close(new_fd);
    }
    close(sockfd);

    return 0;
}