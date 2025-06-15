#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 1024
#define AF_INET 2
#define SOL_SOCKET 1
#define SO_TYPE 3
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

typedef unsigned int socklen_t;

struct connection_event {
    __u32 pid;
    __u32 tgid;
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u16);
} socket_types SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct trace_event_raw_sys_enter *ctx)
{
    int domain = (int)ctx->args[0];
    int type = (int)ctx->args[1];
    int protocol = (int)ctx->args[2];
    
    // Only track AF_INET sockets
    if (domain != AF_INET)
        return 0;
        
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 socktype = (__u16)type;
    
    // Store socket type temporarily with pid_tgid as key
    // We'll update this with the actual fd in sys_exit_socket
    bpf_map_update_elem(&socket_types, &pid_tgid, &socktype, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_sys_exit_socket(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int sockfd = (int)ctx->ret;
    
    // Only track successful socket creation  
    if (sockfd < 0) {
        // Remove the temporary entry
        bpf_map_delete_elem(&socket_types, &pid_tgid);
        return 0;
    }
        
    // Get the socket type we stored in sys_enter_socket
    __u16 *socktype = bpf_map_lookup_elem(&socket_types, &pid_tgid);
    if (socktype) {
        // Create a new key combining pid and fd
        __u64 key = ((__u64)pid_tgid << 32) | ((__u64)sockfd & 0xFFFFFFFF);
        bpf_map_update_elem(&socket_types, &key, socktype, BPF_ANY);
        
        // Remove the temporary entry
        bpf_map_delete_elem(&socket_types, &pid_tgid);
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connection_event *event;
    __u64 pid_tgid;
    __u32 pid, tgid;
    struct sockaddr_in *addr;
    __u32 daddr = 0;
    __u16 dport = 0;
    int sockfd;
    __u16 socktype = SOCK_STREAM; // Default to TCP

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    // Get socket file descriptor
    sockfd = (int)ctx->args[0];

    // Look up socket type from our map
    __u64 key = ((__u64)pid_tgid << 32) | ((__u64)sockfd & 0xFFFFFFFF);
    __u16 *stored_socktype = bpf_map_lookup_elem(&socket_types, &key);
    if (stored_socktype) {
        socktype = *stored_socktype;
    }

    addr = (struct sockaddr_in *)ctx->args[1];

    if (addr) {
        __u16 family;
        bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
        if (family == AF_INET) {
            bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
        }
    }

    if (daddr == 0)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tgid = tgid;
    event->src_addr = 0;
    event->dst_addr = daddr;
    event->src_port = 0;
    event->dst_port = dport;
    // Set protocol based on socket type
    event->protocol = (socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct connection_event *event;
    __u64 pid_tgid;
    __u32 pid, tgid;
    struct sockaddr_in *addr;
    __u32 daddr = 0;
    __u16 dport = 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    addr = (struct sockaddr_in *)ctx->args[4];

    if (addr) {
        __u16 family;
        bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
        if (family == AF_INET) {
            bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
        }
    }

    if (daddr == 0)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tgid = tgid;
    event->src_addr = 0;
    event->dst_addr = daddr;
    event->src_port = 0;
    event->dst_port = dport;
    event->protocol = IPPROTO_UDP;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";