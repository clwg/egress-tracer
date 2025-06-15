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

// Protocol constants
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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

struct socket_info {
    __u16 type;      // Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW)
    __u16 protocol;  // Protocol (for raw sockets: IPPROTO_ICMP, etc.)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct socket_info);
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
    struct socket_info sockinfo = {
        .type = (__u16)type,
        .protocol = (__u16)protocol
    };
    
    // Store socket info temporarily with pid_tgid as key
    // We'll update this with the actual fd in sys_exit_socket
    int ret = bpf_map_update_elem(&socket_types, &pid_tgid, &sockinfo, BPF_ANY);
    if (ret != 0)
        return 0;
    
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
        
    // Get the socket info we stored in sys_enter_socket
    struct socket_info *sockinfo = bpf_map_lookup_elem(&socket_types, &pid_tgid);
    if (sockinfo) {
        // Create a new key combining pid and fd - use upper 32 bits for pid_tgid, lower for sockfd
        __u64 key = (pid_tgid & 0xFFFFFFFF00000000ULL) | ((__u64)sockfd & 0xFFFFFFFFULL);
        int ret = bpf_map_update_elem(&socket_types, &key, sockinfo, BPF_ANY);
        if (ret != 0) {
            bpf_map_delete_elem(&socket_types, &pid_tgid);
            return 0;
        }
        
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
    struct socket_info sockinfo = {.type = SOCK_STREAM, .protocol = IPPROTO_TCP}; // Default

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    // Get socket file descriptor
    sockfd = (int)ctx->args[0];

    // Look up socket info from our map - use upper 32 bits for pid_tgid, lower for sockfd
    __u64 key = (pid_tgid & 0xFFFFFFFF00000000ULL) | ((__u64)sockfd & 0xFFFFFFFFULL);
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
        if (ret != 0)
            return 0;
        if (family == AF_INET) {
            ret = bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            if (ret != 0)
                return 0;
            ret = bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
            if (ret != 0)
                return 0;
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
    // Set protocol based on socket type and stored protocol
    if (sockinfo.type == SOCK_DGRAM) {
        event->protocol = IPPROTO_UDP;
    } else if (sockinfo.type == SOCK_RAW) {
        // For raw sockets, use the protocol field directly
        event->protocol = sockinfo.protocol;
    } else {
        event->protocol = IPPROTO_TCP; // SOCK_STREAM default
    }
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int sockfd = (int)ctx->args[0];
    
    // Create key and remove from socket_types map
    __u64 key = (pid_tgid & 0xFFFFFFFF00000000ULL) | ((__u64)sockfd & 0xFFFFFFFFULL);
    bpf_map_delete_elem(&socket_types, &key);
    
    return 0;
}

// Network-level tracepoint for more reliable protocol detection
SEC("tracepoint/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
    struct connection_event *event;
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    __u64 pid_tgid;
    __u32 pid, tgid;
    
    if (!skb)
        return 0;
        
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;
    
    // Skip if this is kernel traffic (pid 0)
    if (pid == 0)
        return 0;
    
    // Try to extract protocol info from skb
    __u16 protocol = 0;
    int ret = bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (ret != 0 || protocol != bpf_htons(0x0800)) // ETH_P_IP
        return 0;
    
    // Get network header offset
    __u16 network_header = 0;
    ret = bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    if (ret != 0)
        return 0;
    
    // Get head pointer
    unsigned char *head = NULL;
    ret = bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    if (ret != 0 || !head)
        return 0;
    
    // Calculate IP header location
    struct iphdr *iph = (struct iphdr *)(head + network_header);
    
    // Read IP header fields
    __u8 ip_protocol = 0;
    __u32 saddr = 0, daddr = 0;
    ret = bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &iph->protocol);
    if (ret != 0) return 0;
    ret = bpf_probe_read_kernel(&saddr, sizeof(saddr), &iph->saddr);
    if (ret != 0) return 0;
    ret = bpf_probe_read_kernel(&daddr, sizeof(daddr), &iph->daddr);
    if (ret != 0) return 0;
    
    // Only track TCP, UDP, and ICMP
    if (ip_protocol != IPPROTO_TCP && ip_protocol != IPPROTO_UDP && ip_protocol != IPPROTO_ICMP)
        return 0;
    
    // Skip loopback traffic
    if ((daddr & 0xFF) == 127) // 127.x.x.x
        return 0;
    
    __u16 sport = 0, dport = 0;
    
    // Extract ports for TCP/UDP (ICMP doesn't have ports)
    if (ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP) {
        __u8 version_ihl = 0;
        ret = bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl), iph);
        if (ret != 0) return 0;
        
        __u8 ihl = version_ihl & 0x0F; // Extract IHL from lower 4 bits
        void *l4_header = (void *)iph + (ihl * 4);
        
        if (ip_protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)l4_header;
            bpf_probe_read_kernel(&sport, sizeof(sport), &tcph->source);
            bpf_probe_read_kernel(&dport, sizeof(dport), &tcph->dest);
        } else { // UDP
            struct udphdr *udph = (struct udphdr *)l4_header;
            bpf_probe_read_kernel(&sport, sizeof(sport), &udph->source);
            bpf_probe_read_kernel(&dport, sizeof(dport), &udph->dest);
        }
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tgid = tgid;
    event->src_addr = saddr;
    event->dst_addr = daddr;
    event->src_port = sport;
    event->dst_port = dport;
    event->protocol = ip_protocol;
    
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
    int sockfd;
    struct socket_info sockinfo = {.type = SOCK_DGRAM, .protocol = IPPROTO_UDP}; // Default

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid;
    tgid = pid_tgid >> 32;

    // Get socket file descriptor
    sockfd = (int)ctx->args[0];

    // Look up socket info from our map
    __u64 key = (pid_tgid & 0xFFFFFFFF00000000ULL) | ((__u64)sockfd & 0xFFFFFFFFULL);
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
        if (ret != 0)
            return 0;
        if (family == AF_INET) {
            ret = bpf_probe_read_user(&daddr, sizeof(daddr), &addr->sin_addr.s_addr);
            if (ret != 0)
                return 0;
            ret = bpf_probe_read_user(&dport, sizeof(dport), &addr->sin_port);
            if (ret != 0)
                return 0;
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
    // Set protocol based on socket type and stored protocol
    if (sockinfo.type == SOCK_DGRAM) {
        event->protocol = IPPROTO_UDP;
    } else if (sockinfo.type == SOCK_RAW) {
        // For raw sockets, use the protocol field directly
        event->protocol = sockinfo.protocol;
    } else {
        event->protocol = IPPROTO_TCP; // SOCK_STREAM default
    }
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";