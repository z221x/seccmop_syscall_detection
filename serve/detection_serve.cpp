#include "detection_serve.h"
volatile uint32_t targetfd;
volatile uint32_t socketfd;
volatile filter_syscalls filter;
SyscallDeque syscall_deque(MAX_SYSCALL_DEQUE_SIZE);
void setup_seccomp()
{
    uint32_t ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret < 0)
    {
        LOGI("prctl failed: %s\n", strerror(errno));
        exit(-1);
    }
    targetfd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (targetfd < 0)
    {
        LOGI("seccomp failed: %s\n", strerror(errno));
        exit(-1);
    }
}
void process_notifications(uint32_t notifyfd)
{

    uint64_t id;
    seccomp_notif_sizes sizes;
    seccomp_notif *req;
    seccomp_notif_resp *resp;
    uint8_t path[PATH_MAX];
    uint32_t memfd;
    ssize_t s;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1)
    {
        LOGI("seccomp failed: %s", strerror(errno));
        exit(-1);
    }
    assert((req = static_cast<seccomp_notif *>(malloc(sizes.seccomp_notif))));
    assert((resp = static_cast<seccomp_notif_resp *>(malloc(sizes.seccomp_notif_resp))));
    memset(req, 0, sizes.seccomp_notif);
    memset(resp, 0, sizes.seccomp_notif_resp);
    if (ioctl(notifyfd, (uint32_t)SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
    {
        LOGI("ioctl RECV failed: %s\n", strerror(errno));
        return;
    }
    id = req->id;
    if (ioctl(notifyfd, (uint32_t)SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == -1)
    {
        LOGI("Notification ID check: target has died: %s\n",
             strerror(errno));
        exit(-1);
    }
    if (filter.nrs[req->data.nr] == 1)
    {
        LOGI("syscall %d", req->data.nr);
        syscall_deque.push_back(req->data.nr);
    }
    resp->error = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp->id = req->id;
    if (filter.nrs[req->data.nr] == 2)
    {
        resp->flags = SECCOMP_RET_KILL;
    }
    if (ioctl(notifyfd, (uint32_t)SECCOMP_IOCTL_NOTIF_SEND, resp) == -1)
    {
        if (errno == ENOENT)
        {
            LOGI("Response failed with ENOENT; perhaps target "
                 "process's syscall was interrupted by signal?\n");
        }
        else
        {
            LOGI("ioctl SEND failed: %s\n", strerror(errno));
            exit(-1);
        }
    }
    free(req);
    free(resp);
}
void *syscall_detection(void *argc)
{
    uint64_t pidfd;
    uint64_t notifyfd;
    pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    assert(pidfd >= 0);
    notifyfd = syscall(SYS_pidfd_getfd, pidfd, targetfd, 0);
    assert(notifyfd >= 0);
    while (notifyfd)
    {
        process_notifications(notifyfd);
    }
    return nullptr;
}
void *listen_client(void *argc)
{
    while (true)
    {
        int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            LOGI("socket failed: %s\n", strerror(errno));
            return 0;
        }
        socketfd = fd;
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(23711);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            LOGI("bind failed: %s\n", strerror(errno));
            close(fd);
            return 0;
        }
        if (listen(fd, 5) < 0)
        {
            LOGI("listen failed: %s\n", strerror(errno));
            close(fd);
            return 0;
        }
        LOGI("Listening on port 23711\n");
        while (1)
        {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(fd, (sockaddr *)&client_addr, &client_len);
            if (client_fd < 0)
            {
                LOGI("accept failed: %s\n", strerror(errno));
                continue;
            }
            LOGI("Client connected\n");
            char buf[1024] = {0};
            char message[1024] = {0};
            while (1)
            {
                ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
                if (n <= 0)
                {
                    LOGI("client disconnected or recv failed\n");
                    break;
                }
                buf[n] = '\0';
                // 解析输入增加syscall filter
                if (strncmp(buf, "add ", 4) == 0)
                {
                    char *p = buf + 4;
                    int syscall_num = atoi(p);
                    if (filter.nrs[syscall_num] == 0)
                    {
                        filter.nrs[syscall_num] = 1;
                        filter.syscall_num++;
                        LOGI("Added syscall: %d\n", syscall_num);
                    }
                }
                if (strncmp(buf, "del ", 4) == 0)
                {
                    char *p = buf + 4;
                    int syscall_num = atoi(p);
                    if (filter.nrs[syscall_num] == 1)
                    {
                        filter.nrs[syscall_num] = 0;
                        filter.syscall_num--;
                        LOGI("Deleted syscall: %d\n", syscall_num);
                    }
                }
                // 回显消息
                if (strncmp(buf, "show", 4) == 0)
                {
                    int num = syscall_deque.size();
                    if (num > 0)
                    {
                        snprintf(message, sizeof(message), "syscall num: %d\n", num);
                        for (int i = 0; i < num; i++)
                        {
                            snprintf(message + strlen(message), sizeof(message) - strlen(message), "%d ", syscall_deque[i]);
                        }
                        snprintf(message + strlen(message), sizeof(message) - strlen(message), "\n");
                    }
                    else
                    {
                        snprintf(message, sizeof(message), "no syscall detected\n");
                    }
                    if (send(client_fd, message, strlen(message), 0) < 0)
                    {
                        LOGI("send failed: %s\n", strerror(errno));
                        break;
                    }
                }
                // 如果收到exit则关闭连接
                if (strcmp(buf, "exit") == 0)
                {
                    LOGI("client requested exit\n");
                    break;
                }
                if (strncmp(buf, "clear", 5) == 0)
                {
                    syscall_deque.clear();
                }
                if (strncmp(buf, "intercept ", 10) == 0)
                {
                    char *p = buf + 10;
                    int syscall_num = atoi(p);
                    if (filter.nrs[syscall_num] == 0)
                    {
                        filter.nrs[syscall_num] = 2;
                        filter.syscall_num++;
                    }
                    else
                    {
                        filter.nrs[syscall_num] = 2;
                    }
                    LOGI("Intercepted syscall: %d", syscall_num);
                }
                // 打印过滤的syscall list
                if (strncmp(buf, "list", 4) == 0)
                {
                    if (filter.syscall_num == 0)
                    {
                        snprintf(message, sizeof(message), "no syscall filted\n");
                    }
                    else
                    {
                        snprintf(message, sizeof(message), "syscall num: %d\n", filter.syscall_num);
                        for (int i = 0; i < MAX_SYSCALL_NUM; i++)
                        {
                            if (filter.nrs[i])
                            {
                                snprintf(message + strlen(message), sizeof(message) - strlen(message), "%d ", i);
                            }
                        }
                    }
                    if (send(client_fd, message, strlen(message), 0) < 0)
                    {
                        LOGI("send failed: %s\n", strerror(errno));
                        break;
                    }
                }
                memset(buf, 0, sizeof(buf));
                memset(message, 0, sizeof(message));
            }
            close(client_fd);
            if (strcmp(buf, "exit") == 0)
            {
                break;
            }
            LOGI("Client disconnected\n");
        }
        close(fd);
    }
    return nullptr;
}
void unlisten_client(int32_t fd)
{
    if (fd > 0)
    {
        close(fd);
    }
}
void init()
{
    targetfd = 0;
    socketfd = 0;
    filter.syscall_num = 0;
    memset((void *)&filter.nrs, 0, sizeof(filter.nrs));
}
static void my_init()
{
    pthread_t tid[2];
    init();
    pthread_create(&tid[1], nullptr, listen_client, nullptr);
    pthread_create(&tid[0], nullptr, syscall_detection, nullptr);
    pthread_detach(tid[0]);
    pthread_detach(tid[1]);
    setup_seccomp();
}
__attribute__((section(".init_array"))) typeof(my_init) *my_init_p = my_init;
static void my_fini()
{
    unlisten_client(socketfd);
    close(targetfd);
}
__attribute__((section(".fini_array"))) typeof(my_fini) *my_fini_p = my_fini;