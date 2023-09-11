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
#include <vector>
#include "transfer.cpp"

const size_t BUFFER_SIZE = 2048; //
#define PORT "3490"              // the port users will be connecting to
#define BACKLOG 10               // how many pending connections queue will hold
#define MAXDATASIZE 1024         // max number of bytes we can get at once
using std::string;
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
int get_listener_socket(int &listener)
{

    int rv;
    int yes = 1;
    struct addrinfo hints, *ai, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &ai)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    for (p = ai; p != NULL; p = p->ai_next)
    {
        if ((listener = socket(p->ai_family, p->ai_socktype,
                               p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        // encope with "Address already in use" error msg by reusing the port
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            return -1;
        }

        if (bind(listener, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(listener);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(ai); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    if (listen(listener, BACKLOG) == -1)
    {
        perror("listen");
        return -1;
    }
    return 1;
}
void modify_http_request(char *&request)
{
    char const *replace = "trolly.jpg";
    char *found = strstr(request, "smiley.jpg");
    if (found)
    {
        for (int it = 0; it < sizeof(replace); ++it)
        {
            *(found + it) = *(replace + it);
        }
    }
}
void modify_http_response(std::string &header, std::string &body)
{

    // image case
    std::vector<std::pair<int, int>> image_pos;
    int index_left = 0;
    int index_right = 0;
    std::string img_tag = "<img";
    while (1)
    {
        index_left = body.find(img_tag, index_left);
        if (index_left != std::string::npos)
        {
            index_right = body.find(">", index_left);
            if (index_right == std::string::npos)
            {
                break;
            }
            else
            {
                image_pos.push_back(std::make_pair(index_left, index_right));
                index_left = index_right;
            }
        }
        else
        {
            break;
        }
    }
    // Smiley to Trolly
    std::string pre_name = "Smiley";
    std::string replace_name = "Trolly";
    int index = 0;
    while ((index = body.find(pre_name, index)) != std::string::npos)
    {
        body.replace(index, replace_name.length(), replace_name);
        index += pre_name.length();
    }
    // Stockholm TO Linkoping
    std::string pre_city = "Stockholm";
    std::string replace_city = "Linkoping";
    index = 0;
    bool inside_img_tag = false;
    while ((index = body.find(pre_city, index)) != std::string::npos)
    {
        inside_img_tag = false;
        for (const auto &pos_pair : image_pos)
        {
            if (index < pos_pair.second && index > pos_pair.first)
            {
                inside_img_tag = true;
                break;
            }
        }
        if (!inside_img_tag)
        {
            body.replace(index, pre_city.length(), replace_city);
        }
        index += pre_city.length();
    }
}
bool is_content_type_text_based(std::string &header)
{
    size_t content_type_start = header.find("Content-Type");
    size_t found = header.find("text", content_type_start);
    return found != std::string::npos;
}
int process_http_response(int sockfd, char *&response_after_modified, size_t &response_size)
{
    char buffer[1024] = {0};
    std::string header;
    std::string text_body;
    std::vector<char> binary_body;
    bool header_found = false;
    bool is_binary = false;
    while (1)
    {
        ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received == -1)
        {
            perror("recv:");
            return -1;
        }
        if (bytes_received == 0)
        {
            break;
        }
        buffer[bytes_received] = '\0';
        if (!header_found)
        {
            char *t = strstr(buffer, "\r\n\r\n");
            if (t == NULL)
            {
                // all of content in buffer is a part of header.
                header.insert(header.end(), buffer, buffer + bytes_received);
            }
            else
            {
                // content contained half header and half body
                header.insert(header.end(), buffer, t + 4);
                header_found = 1;
                if (!is_content_type_text_based(header))
                {
                    is_binary = true;
                    binary_body.insert(binary_body.end(), t + 4, buffer + bytes_received);
                }
                else
                {
                    text_body.insert(text_body.end(), t + 4, buffer + bytes_received);
                }
            }
        }
        else
        {
            if (is_binary)
            {
                binary_body.insert(binary_body.end(), buffer, buffer + bytes_received);
            }
            else
            {
                text_body.insert(text_body.end(), buffer, buffer + bytes_received);
            }
        }
    }
    // modify the text body
    if (is_binary)
    {
        size_t total_size = header.size() + binary_body.size();
        response_after_modified = (char *)malloc(total_size + 1);
        if (response_after_modified != nullptr)
        {
            memcpy(response_after_modified, header.data(), header.size());
            memcpy(response_after_modified + header.size(), binary_body.data(), binary_body.size());
            response_after_modified[total_size] = '\0';
            response_size = total_size;
            return 1;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        modify_http_response(header, text_body);
        size_t total_size = header.size() + text_body.size();
        response_after_modified = (char *)malloc(total_size + 1);
        if (response_after_modified != nullptr)
        {
            memcpy(response_after_modified, header.data(), header.size());
            memcpy(response_after_modified + header.size(), text_body.data(), text_body.size());
            response_after_modified[total_size] = '\0';
            response_size = total_size;
            return 1;
        }
        else
        {
            return -1;
        }
    }
}

int get_response_from_target_server(char const *host, char *&request, char *&result, size_t &total_size)
{
    int client_socket;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char recvBuf[MAXDATASIZE] = {0};

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, "80", &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((client_socket = socket(p->ai_family, p->ai_socktype,
                                    p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(client_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(client_socket);
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
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    modify_http_request(request);
    int ret = send(client_socket, request, strlen(request), 0);
    if (ret == -1)
    {
        perror("transfer: send");
        close(client_socket);
        return -1;
    }
    printf("request being sent : %s\n", request);

    if (process_http_response(client_socket, result, total_size) == -1)
    {
        perror("process");
        close(client_socket);
        return -1;
    }
    printf("response from target server : %s\n", result);

    close(client_socket);

    return 0;
}

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

int main(int argc, char *argv[])
{
    int server_socket, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char recvBuf[2048] = {0};

    if (get_listener_socket(server_socket) == -1)
    {
        std::cerr << "error getting listening socket\n";
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
        new_fd = accept(server_socket, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork())
        {
            close(server_socket);
            int num = recv(new_fd, recvBuf, sizeof(recvBuf), 0);
            if (num == -1)
            {
                perror("read");
                exit(1);
            }
            else if (num > 0)
            {

                printf("recv client data : %s\n", recvBuf);
                // transfer request to target server
                if (!isGetRequest(recvBuf))
                {
                    std::cout << "Proxy only support GET Request!" << std::endl;
                    close(new_fd);
                    exit(1);
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
                    exit(1);
                }
                char *request = recvBuf;
                char *response_from_proxy_client;
                size_t total_size_of_response;
                size_t bytes_sent = 0;

                if (get_response_from_target_server(host, request, response_from_proxy_client, total_size_of_response) == -1)
                {
                    perror("client: transfer");
                    close(new_fd);
                    exit(1);
                }
                int sent_bytes = send(new_fd, response_from_proxy_client, total_size_of_response, 0);
                if (sent_bytes == -1)
                {
                    perror("sent: ");
                    exit(1);
                }

                free(host);
                free(response_from_proxy_client);
            }
            else if (num == 0)
            {

                printf("client closed...");
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd); // parent doesn't need
    }
    close(server_socket);

    return 0;
}