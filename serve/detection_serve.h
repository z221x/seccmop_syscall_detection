#include <iostream>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <csignal>
#include <sys/endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ucontext.h>
#include <linux/filter.h>
#include <android/log.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <cassert>
#include <deque>
#include <mutex>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Native", __VA_ARGS__)
#define MAX_SYSCALL_NUM 500
const size_t MAX_SYSCALL_DEQUE_SIZE = 100;
// 过滤所有syscall
struct sock_filter bpf[] = {
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
};
struct sock_fprog prog = {
    .len = sizeof(bpf) / sizeof(bpf[0]),
    .filter = bpf,
};
struct filter_syscalls
{
    uint8_t nrs[MAX_SYSCALL_NUM];
    uint32_t syscall_num;
};
class SyscallDeque
{
public:
    int max_size_;
    SyscallDeque(int max_size)
    {
        max_size_ = max_size;
    }
    void push_back(int syscall_num)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (deque_.size() >= max_size_)
        {
            deque_.pop_front();
        }
        deque_.push_back(syscall_num);
    }
    void pop_back()
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!deque_.empty())
            deque_.pop_back();
    }
    void clear()
    {
        std::lock_guard<std::mutex> lock(mtx_);
        deque_.clear();
    }
    size_t size() const
    {
        std::lock_guard<std::mutex> lock(mtx_);
        return deque_.size();
    }
    int get(int index) const
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (index < 0 || index >= deque_.size())
            return -1;
        return deque_[index];
    }
    void set(int index, int syscall_num)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (index < 0 || index >= deque_.size())
            return;
        deque_[index] = syscall_num;
    }
    int operator[](int index) const
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (index < 0 || index >= deque_.size())
            return -1;
        return deque_[index];
    }

private:
    mutable std::mutex mtx_;
    std::deque<int> deque_;
};