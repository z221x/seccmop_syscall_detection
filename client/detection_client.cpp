#include "detection_client.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

int32_t connect_serve()
{
    int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        std::cerr << "socket failed: " << strerror(errno) << std::endl;
        return 0;
    }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(23711);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "connect failed: " << strerror(errno) << std::endl;
        close(fd);
        return 0;
    }
    return fd;
}
void interact(int32_t fd)
{
    std::cout << "Connected to server. Type 'exit' to quit." << std::endl;
    char recv_buf[1024] = {0};
    while (true)
    {
        std::string message;
        std::cout << ">> ";
        std::getline(std::cin, message);
        // std::cout << "[send]" << message << std::endl;
        if (message == "exit")
        {
            send(fd, message.c_str(), message.length(), 0);
            break;
        }
        if (message.empty())
            continue;
        if (send(fd, message.c_str(), message.length(), 0) < 0)
        {
            std::cerr << "send failed: " << strerror(errno) << std::endl;
            break;
        }
        if (strncmp(message.c_str(), "show", 4) == 0)
        {
            int syscall_num = 0;
            ssize_t n = recv(fd, recv_buf, sizeof(recv_buf) - 1, 0);
            if (n <= 0)
            {
                std::cerr << "recv failed: " << strerror(errno) << std::endl;
                break;
            }
            recv_buf[n] = '\0';
            if (strstr(recv_buf, "no syscall detected") != nullptr)
            {
                std::cout << recv_buf;
                continue;
            }
            else
            {
                sscanf(recv_buf, "syscall num: %d\n", &syscall_num);
                char *tmp = strtok(recv_buf, "\n");
                for (int i = 0; i < syscall_num; i++)
                {
                    tmp = strtok(NULL, " ");
                    if (tmp != nullptr)
                    {
                        std::cout << "[" << i << "] " << "syscall num: " << atoi(tmp) << std::endl;
                    }
                }
            }
        }
        if (strncmp(message.c_str(), "list", 4) == 0)
        {
            int syscall_num = 0;
            ssize_t n = recv(fd, recv_buf, sizeof(recv_buf) - 1, 0);
            if (n <= 0)
            {
                std::cerr << "recv failed: " << strerror(errno) << std::endl;
                break;
            }
            recv_buf[n] = '\0';
            if (strstr(recv_buf, "no syscall") != nullptr)
            {
                std::cout << recv_buf;
                continue;
            }
            else
            {
                sscanf(recv_buf, "syscall num: %d\n", &syscall_num);
                char *tmp = strtok(recv_buf, "\n");
                for (int i = 0; i < syscall_num; i++)
                {
                    tmp = strtok(NULL, " ");
                    if (tmp != nullptr)
                    {
                        std::cout << "[" << i << "] " << "syscall num: " << atoi(tmp) << std::endl;
                    }
                }
            }
        }
    }
    close(fd);
}

int main()
{
    int32_t fd = connect_serve();
    if (fd)
        interact(fd);
    return 0;
}