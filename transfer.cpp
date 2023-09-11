#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
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
char *removeHTTPHeader(char *buffer, int &bodySize)
{
    char *t = strstr(buffer, "\r\n\r\n");
    t = t + 4;

    for (auto it = buffer; it != t; ++it)
    {
        ++bodySize;
    }

    return t;
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
    // Smiley to Trolly
    std::string pre_name = "Smiley";
    std::string replace_name = "Trolly";
    int index = 0;
    while ((index = body.find(pre_name, index)) != std::string::npos)
    {
        body.replace(index, pre_name.length(), replace_name);
        index += pre_name.length();
    }

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
int process_http_response2(int sockfd, char *&response_after_modified, size_t &response_size)
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
int process_http_response(int sockfd, char *&response_after_modified, size_t &response_size)
{
    char buffer[1024] = {0};
    std::vector<char> header;
    std::vector<char> body;
    int header_found = 0;
    while (1)
    {
        ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received == 0)
        {
            break;
        }
        buffer[bytes_received] = '\0';
        if (header_found == 0)
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
                body.insert(body.end(), t + 4, buffer + bytes_received);
                header_found = 1;
            }
        }
        else
        {
            body.insert(body.end(), buffer, buffer + bytes_received);
        }
    }
    if (header_found == 0)
    {
        return -1;
    }
    size_t total_size = header.size() + body.size();
    response_after_modified = (char *)malloc(total_size + 1);
    if (response_after_modified != nullptr)
    {
        memcpy(response_after_modified, header.data(), header.size());
        memcpy(response_after_modified + header.size(), body.data(), body.size());
        response_after_modified[total_size] = '\0';
        response_size = total_size;
        return 1;
    }
    else
    {
        return -1;
    }
}
int transfer(char const *host, char *&request, char *&result, size_t &total_size)
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
    modify_http_request(request);
    int ret = send(sockfd, request, strlen(request), 0);
    if (ret == -1)
    {
        perror("transfer: send");
        close(sockfd);
        return -1;
    }
    printf("request being sent : %s\n", request);

    if (process_http_response2(sockfd, result, total_size) == -1)
    {
        perror("process");
        close(sockfd);
        return -1;
    }
    printf("response from target server : %s\n", result);

    close(sockfd);

    return 0;
}
