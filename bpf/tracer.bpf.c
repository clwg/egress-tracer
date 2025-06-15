#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 1024
#define AF_INET 2
#define SOL_SOCKET 1
#define SO_TYPE 3
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5

// Protocol constants
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_SCTP 132

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
    __u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct socket_info {
    __u16 type;      // Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW)
    __u16 protocol;  // Protocol (for raw sockets: IPPROTO_ICMP, etc.)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct socket_info);
} socket_types SEC(".maps");

// Temporary storage for socket creation (enter -> exit)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, struct socket_info);
} temp_socket_info SEC(".maps");

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
    
    // Set default protocol based on socket type if protocol is 0
    __u16 actual_protocol = (__u16)protocol;
    if (actual_protocol == 0) {
        if (type == SOCK_STREAM) {
            actual_protocol = IPPROTO_TCP;
        } else if (type == SOCK_DGRAM) {
            actual_protocol = IPPROTO_UDP;
        } else if (type == SOCK_SEQPACKET) {
            actual_protocol = IPPROTO_SCTP;
        }
        // For SOCK_RAW, keep protocol as 0 if not specified
    }
    
    struct socket_info sockinfo = {
        .type = (__u16)type,
        .protocol = actual_protocol
    };
    
    // Store socket info temporarily with full pid_tgid as key
    // This will be moved to the proper key in sys_exit_socket
    int ret = bpf_map_update_elem(&temp_socket_info, &pid_tgid, &sockinfo, BPF_ANY);
    if (ret != 0)
        return 0;
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_sys_exit_socket(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int sockfd = (int)ctx->ret;
    
    // Get the socket info we stored in sys_enter_socket
    struct socket_info *sockinfo = bpf_map_lookup_elem(&temp_socket_info, &pid_tgid);
    
    // Always clean up the temporary entry
    bpf_map_delete_elem(&temp_socket_info, &pid_tgid);
    
    // Only store in main map if socket creation was successful
    if (sockfd < 0 || !sockinfo) {
        return 0;
    }
        
    // Create a new key: full pid_tgid in upper 32 bits, sockfd in lower 32 bits
    __u64 key = (pid_tgid << 32) | ((__u64)sockfd & 0xFFFFFFFFULL);
    int ret = bpf_map_update_elem(&socket_types, &key, sockinfo, BPF_ANY);
    if (ret != 0) {
        // Failed to store, but we already cleaned up temp entry
        return 0;
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
    __u8 flags = 0;
    int sockfd;
    struct socket_info sockinfo = {.type = 0, .protocol = 0}; // Initialize to unknown

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    // Get socket file descriptor
    sockfd = (int)ctx->args[0];

    // Look up socket info from our map - use full pid_tgid in upper 32 bits, sockfd in lower 32 bits
    __u64 key = (pid_tgid << 32) | ((__u64)sockfd & 0xFFFFFFFFULL);
    struct socket_info *stored_sockinfo = bpf_map_lookup_elem(&socket_types, &key);
    if (stored_sockinfo) {
        sockinfo = *stored_sockinfo;
    }

    addr = (struct sockaddr_in *)ctx->args[1];
    socklen_t addrlen = (socklen_t)ctx->args[2];

    // Validate address pointer and length
    if (!addr || addrlen < sizeof(struct sockaddr_in))
        return 0;

    if (addr) {
        __u16 family;
        int ret = bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
        if (ret != 0) {
            flags |= (1 << 2); // FLAG_FAMILY_READ_FAILED
        } else if (family == AF_INET) {
            ret = bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            if (ret != 0) {
                flags |= (1 << 0); // FLAG_ADDR_READ_FAILED
            }
            ret = bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
            if (ret != 0) {
                flags |= (1 << 1); // FLAG_PORT_READ_FAILED
                dport = 0; // Explicitly set to 0 for failed reads
            }
        }
    }

    // Only skip if we couldn't read the destination address AND it's not a read failure
    if (daddr == 0 && !(flags & ((1 << 0) | (1 << 2))))
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
    event->flags = flags;
    
    // Set protocol based on socket type and stored protocol
    // First try to use the stored socket information
    if (stored_sockinfo) {
        if (stored_sockinfo->type == SOCK_DGRAM) {
            // SOCK_DGRAM can be UDP or other datagram protocols
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_UDP) {
                event->protocol = IPPROTO_UDP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_STREAM) {
            // SOCK_STREAM is typically TCP
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_TCP) {
                event->protocol = IPPROTO_TCP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_SEQPACKET) {
            // SOCK_SEQPACKET can be SCTP or other reliable packet protocols
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_SCTP) {
                event->protocol = IPPROTO_SCTP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_RAW) {
            // For raw sockets, use the protocol field directly
            event->protocol = stored_sockinfo->protocol;
        } else {
            // Unknown socket type, assume TCP for connect() calls
            event->protocol = IPPROTO_TCP;
        }
    } else {
        // No stored socket info, make educated guess based on syscall
        // connect() is typically used with TCP (SOCK_STREAM)
        event->protocol = IPPROTO_TCP;
    }
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    
    // Create key and check if it exists before attempting to delete
    __u64 key = (pid_tgid << 32) | ((__u64)fd & 0xFFFFFFFFULL);
    struct socket_info *sockinfo = bpf_map_lookup_elem(&socket_types, &key);
    if (sockinfo) {
        bpf_map_delete_elem(&socket_types, &key);
    }
    
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
    __u8 flags = 0;
    int sockfd;
    struct socket_info sockinfo = {.type = 0, .protocol = 0}; // Initialize to unknown

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    // Get socket file descriptor
    sockfd = (int)ctx->args[0];

    // Look up socket info from our map
    __u64 key = (pid_tgid << 32) | ((__u64)sockfd & 0xFFFFFFFFULL);
    struct socket_info *stored_sockinfo = bpf_map_lookup_elem(&socket_types, &key);
    if (stored_sockinfo) {
        sockinfo = *stored_sockinfo;
    }

    addr = (struct sockaddr_in *)ctx->args[4];
    socklen_t addrlen = (socklen_t)ctx->args[5];

    // Validate address pointer and length  
    if (!addr || addrlen < sizeof(struct sockaddr_in))
        return 0;

    if (addr) {
        __u16 family;
        int ret = bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
        if (ret != 0) {
            flags |= (1 << 2); // FLAG_FAMILY_READ_FAILED
        } else if (family == AF_INET) {
            ret = bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            if (ret != 0) {
                flags |= (1 << 0); // FLAG_ADDR_READ_FAILED
            }
            ret = bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
            if (ret != 0) {
                flags |= (1 << 1); // FLAG_PORT_READ_FAILED
                dport = 0; // Explicitly set to 0 for failed reads
            }
        }
    }

    // Only skip if we couldn't read the destination address AND it's not a read failure
    if (daddr == 0 && !(flags & ((1 << 0) | (1 << 2))))
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
    event->flags = flags;
    
    // Set protocol based on socket type and stored protocol
    // First try to use the stored socket information
    if (stored_sockinfo) {
        if (stored_sockinfo->type == SOCK_DGRAM) {
            // SOCK_DGRAM can be UDP or other datagram protocols
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_UDP) {
                event->protocol = IPPROTO_UDP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_STREAM) {
            // SOCK_STREAM is typically TCP, but sendto can be used with connected TCP sockets
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_TCP) {
                event->protocol = IPPROTO_TCP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_SEQPACKET) {
            // SOCK_SEQPACKET can be SCTP or other reliable packet protocols
            if (stored_sockinfo->protocol == 0 || stored_sockinfo->protocol == IPPROTO_SCTP) {
                event->protocol = IPPROTO_SCTP;
            } else {
                event->protocol = stored_sockinfo->protocol;
            }
        } else if (stored_sockinfo->type == SOCK_RAW) {
            // For raw sockets, use the protocol field directly
            event->protocol = stored_sockinfo->protocol;
        } else {
            // Unknown socket type, assume UDP for sendto() calls
            event->protocol = IPPROTO_UDP;
        }
    } else {
        // No stored socket info, make educated guess based on syscall
        // sendto() is typically used with UDP (SOCK_DGRAM), but can be used with connected TCP
        event->protocol = IPPROTO_UDP;
    }
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";