#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 1024
#define AF_INET 2

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

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
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
    event->protocol = IPPROTO_TCP;
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