// implementation was originally borrowed from tracee

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"
#include "include/cgroups.h"

#define PF_INET 2
#define PF_INET6 10
#define IPPROTO_ICMPV6 58

typedef union iphdrs_t
{
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef union protohdrs_t
{
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
    union
    {
        u8 tcp_extra[40]; // data offset might set it up to 60 bytes
    };
} protohdrs;

typedef struct nethdrs_t
{
    iphdrs iphdrs;
    protohdrs protohdrs;
} nethdrs;

typedef struct
{
    u64 ts;
    u16 ip_csum;
    struct in6_addr src;
    struct in6_addr dst;
} indexer_t;

typedef struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096); // 800 KB    // simultaneous cgroup/skb ingress/eggress progs
    __type(key, indexer_t);    // layer 3 header fields used as indexer
    __type(value, __u64);      // cgroup_id
} cgrpctxmap_t;
cgrpctxmap_t cgrpctxmap_in SEC(".maps"); // saved info SKB caller <=> SKB ingress
cgrpctxmap_t cgrpctxmap_eg SEC(".maps"); // saved info SKB caller <=> SKB egress

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535); // 9 MB     // simultaneous sockets being traced
    __type(key, __u64);         // socket inode number ...
    __type(value, __u64);       // cgroup_id
} inodemap SEC(".maps");        // relate sockets and tasks

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535); // 9 MB     // simultaneous sockets being cloned
    __type(key, u64);           // *(struct sock *newsock) ...
    __type(value, u64);         // ... old sock->socket inode number
} sockmap SEC(".maps");         // relate a cloned sock struct with

static __always_inline bool is_family_supported(struct socket *sock)
{
    struct sock *sk = (void *)BPF_CORE_READ(sock, sk);
    struct sock_common *common = (void *)sk;
    u8 family = BPF_CORE_READ(common, skc_family);

    switch (family)
    {
    case PF_INET:
    case PF_INET6:
        break;
    // case PF_UNSPEC:
    // case PF_LOCAL:      // PF_UNIX or PF_FILE
    // case PF_NETLINK:
    // case PF_VSOCK:
    // case PF_XDP:
    // case PF_BRIDGE:
    // case PF_PACKET:
    // case PF_MPLS:
    // case PF_BLUETOOTH:
    // case PF_IB:
    // ...
    default:
        return 0; // not supported
    }

    return 1; // supported
}

struct sock___old
{
    struct sock_common __sk_common;
    unsigned int __sk_flags_offset[0];
    unsigned int sk_padding : 1,
        sk_kern_sock : 1,
        sk_no_check_tx : 1,
        sk_no_check_rx : 1,
        sk_userlocks : 4,
        sk_protocol : 8,
        sk_type : 16;
    u16 sk_gso_max_segs;
};

static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset))
    {
        check = (struct sock___old *)sock;
        bpf_core_read(&protocol, 1, (void *)(&check->sk_gso_max_segs) - 3);
    }
    else
    {
        protocol = BPF_CORE_READ(sock, sk_protocol);
    }

    return protocol;
}

static __always_inline bool is_socket_supported(struct socket *sock)
{
    struct sock *sk = (void *)BPF_CORE_READ(sock, sk);
    u16 protocol = get_sock_protocol(sk);
    switch (protocol)
    {
    // case IPPROTO_IPIP:
    // case IPPROTO_DCCP:
    // case IPPROTO_SCTP:
    // case IPPROTO_UDPLITE:
    case IPPROTO_IP:
    case IPPROTO_IPV6:
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        break;
    default:
        return 0; // not supported
    }

    return 1; // supported
}

static __always_inline __u32 update_net_inodemap(struct socket *sock, __u64 cgroup_id)
{
    struct file *sock_file = BPF_CORE_READ(sock, file);
    if (!sock_file)
        return 0;

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    bpf_map_update_elem(&inodemap, &inode, &cgroup_id, BPF_ANY);

    return 0;
}

// runs BEFORE the CGROUP/SKB eBPF program
SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(cgroup_bpf_run_filter_skb)
{
    void *cgrpctxmap = NULL;

    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
    int type = PT_REGS_PARM3(ctx);

    if (!sk || !skb)
        return 0;

    switch (type)
    {
    case BPF_CGROUP_INET_INGRESS:
        cgrpctxmap = &cgrpctxmap_in;
        // packet_dir_flag = packet_ingress;
        break;
    case BPF_CGROUP_INET_EGRESS:
        cgrpctxmap = &cgrpctxmap_eg;
        // packet_dir_flag = packet_egress;
        break;
    default:
        return 0; // other attachment type, return fast
    }

    struct sock_common *common = (void *)sk;
    u8 family = BPF_CORE_READ(common, skc_family);

    switch (family)
    {
    case PF_INET:
    case PF_INET6:
        break;
    default:
        return 1; // return fast for unsupported socket families
    }

    bool mightbecloned = false; // cloned sock structs come from accept()

    // obtain the socket inode using current "sock" structure
    u64 inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        mightbecloned = true; // kernel threads might have zero inode

    __u64 *cgroup_id_ptr;

    // obtain the task ctx using the obtained socket inode
    if (!mightbecloned)
    {
        // pick network context from the inodemap (inode <=> task)
        cgroup_id_ptr = bpf_map_lookup_elem(&inodemap, &inode);
        if (!cgroup_id_ptr)
            mightbecloned = true; // e.g. task isn't being traced
    }
    // If inode is zero, or task context couldn't be found, try to find it using
    // the "sock" pointer from sockmap (this sock struct might be new, just
    // cloned, and a socket might not exist yet, but the sockmap is likely to
    // have the entry). Check trace_security_sk_clone() for more details.

    if (mightbecloned)
    {
        // pick network context from the sockmap (new sockptr <=> old inode <=> task)
        u64 skptr = (u64)(void *)sk;
        u64 *o = bpf_map_lookup_elem(&sockmap, &skptr);
        if (o == 0)
        {
            return 0;
        }
        u64 oinode = *o;

        // with the old inode, find the netctx for the task
        cgroup_id_ptr = bpf_map_lookup_elem(&inodemap, &oinode);
        if (!cgroup_id_ptr)
            return 0; // old inode wasn't being traced as well

        // update inodemap w/ new inode <=> task context (faster path next time)
        bpf_map_update_elem(&inodemap, &oinode, cgroup_id_ptr, BPF_ANY);
    }

    u32 l3_size = 0;
    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    // inform userland about protocol family (for correct L3 header parsing)...
    switch (family)
    {
    case PF_INET:
        // eventctx->retval |= family_ipv4;
        l3_size = bpf_core_type_size(struct iphdr);
        break;
    case PF_INET6:
        // eventctx->retval |= family_ipv6;
        l3_size = bpf_core_type_size(struct ipv6hdr);
        break;
    default:
        return 1;
    }

    // Read packet headers from the skb.
    void *data_ptr = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
    bpf_core_read(nethdrs, l3_size, data_ptr);

    // Prepare the inter-eBPF-program indexer.
    indexer_t indexer = {0};
    indexer.ts = BPF_CORE_READ(skb, tstamp);

    u8 proto = 0;

    // Parse the packet layer 3 headers.
    __u8 ip_version = 0;
    switch (family)
    {
    case PF_INET:
        if (nethdrs->iphdrs.iphdr.version != 4)
        {
            return 1;
        }
        ip_version = nethdrs->iphdrs.iphdr.version;
        break;

    case PF_INET6:
        ip_version = nethdrs->iphdrs.ipv6hdr.version;
        break;

    default:
        return 1;
    }

    switch (ip_version)
    {
    case 4:
        if (nethdrs->iphdrs.iphdr.ihl > 5)
        { // re-read IP header if needed
            l3_size -= bpf_core_type_size(struct iphdr);
            l3_size += nethdrs->iphdrs.iphdr.ihl * 4;
            bpf_core_read(nethdrs, l3_size, data_ptr);
        }

        proto = nethdrs->iphdrs.iphdr.protocol;
        switch (proto)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
            break;
        default:
            return 1; // ignore other protocols
        }

        // Update inter-eBPF-program indexer with IPv4 header items.
        indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
        indexer.src.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
        indexer.dst.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
        break;

    case 6:
        proto = nethdrs->iphdrs.ipv6hdr.nexthdr;
        switch (proto)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMPV6:
            break;
        default:
            return 1; // ignore other protocols
        }

        // Update inter-eBPF-program indexer with IPv6 header items.
        __builtin_memcpy(&indexer.src.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
        __builtin_memcpy(&indexer.dst.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
        break;

    default:
        return 1;
    }

    // TODO: log collisions
    bpf_map_update_elem(cgrpctxmap, &indexer, cgroup_id_ptr, BPF_NOEXIST);

    return 0;
}

typedef struct entry
{
    long unsigned int args[6];
} entry_t;

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);   // simultaneous tasks being traced for entry/exit
    __type(key, u32);            // host thread group id (tgid or tid) ...
    __type(value, struct entry); // ... linked to entry ctx->args
} entrymap SEC(".maps");         // can't use args_map (indexed by existing events only)

SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(sock_alloc_file)
{
    // runs every time a socket is created (entry)

    struct socket *sock = (void *)PT_REGS_PARM1(ctx);

    if (!is_family_supported(sock))
        return 0;

    if (!is_socket_supported(sock))
        return 0;

    struct entry entry = {0};

    // save args for retprobe
    entry.args[0] = PT_REGS_PARM1(ctx); // struct socket *sock
    entry.args[1] = PT_REGS_PARM2(ctx); // int flags
    entry.args[2] = PT_REGS_PARM2(ctx); // char *dname

    // prepare for kretprobe using entrymap
    u32 host_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&entrymap, &host_tid, &entry, BPF_ANY);

    return 0;
}

SEC("kretprobe/sock_alloc_file")
int BPF_KRETPROBE(sock_alloc_file_ret)
{
    // runs every time a socket is created (return)

    // pick from entry from entrymap
    u32 host_tid = bpf_get_current_pid_tgid();
    struct entry *entry = bpf_map_lookup_elem(&entrymap, &host_tid);
    if (!entry) // no entry == no tracing
        return 0;

    // pick args from entry point's entry
    // struct socket *sock = (void *) entry->args[0];
    // int flags = entry->args[1];
    // char *dname = (void *) entry->args[2];
    struct file *sock_file = (void *)PT_REGS_RC(ctx);

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &host_tid);

    if (!sock_file)
        return 0; // socket() failed ?

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
    if (inode == 0)
        return 0;

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &cgroup_id, BPF_ANY);

    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg)
{
    struct socket *s = (void *)PT_REGS_PARM1(ctx);
    if (s == NULL)
        return 0;
    if (!is_family_supported(s))
        return 0;
    if (!is_socket_supported(s))
        return 0;

    struct sock *sk = BPF_CORE_READ(s, sk);

    return update_net_inodemap(s, compat_get_current_cgroup_id(NULL));
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg)
{
    struct socket *s = (void *)PT_REGS_PARM1(ctx);
    if (s == NULL)
        return 0;
    if (!is_family_supported(s))
        return 0;
    if (!is_socket_supported(s))
        return 0;

    struct sock *sk = BPF_CORE_READ(s, sk);

    return update_net_inodemap(s, compat_get_current_cgroup_id(NULL));
}

SEC("kprobe/security_sk_clone")
int BPF_KPROBE(security_sk_clone)
{
    if (!CGROUP_V1 && !PREFER_CGROUP_V1_EBPF_CAPTURE)
        return 0;
    struct sock *osock = (void *)PT_REGS_PARM1(ctx);
    struct sock *nsock = (void *)PT_REGS_PARM2(ctx);

    struct socket *osocket = BPF_CORE_READ(osock, sk_socket);
    if (!osocket)
    {
        return 0;
    }

    // obtain old socket inode
    u64 inode = BPF_CORE_READ(osocket, file, f_inode, i_ino);
    if (inode == 0)
    {
        return 0;
    }

    // check if old socket family is supported
    if (!is_family_supported(osocket))
        return 0;

    // if the original socket isn't linked to a task, then the newly cloned
    // socket won't need to be linked as well: return in that case

    __u64 *cgroup_id_ptr = bpf_map_lookup_elem(&inodemap, &inode);
    if (!cgroup_id_ptr)
        return 0; // e.g. task isn't being traced

    u64 nsockptr = (u64)(void *)nsock;

    // link the new "sock" to the old inode, so it can be linked to a task later

    bpf_map_update_elem(&sockmap, &nsockptr, &inode, BPF_ANY);

    return 0;
}

// implementation ogriginally borrowd from tracee
static __always_inline __u64 get_packet_cgroup(struct __sk_buff *ctx, void *cgrpctxmap)
{
    bpf_printk("get_packet_cgroup");
    __u64 cgroup_id = 0;
    switch (ctx->family)
    {
    case PF_INET:
        bpf_printk("ipv4");
        break;
    case PF_INET6:
        bpf_printk("ipv6");
        break;
    default:
        return cgroup_id;
    }

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return cgroup_id;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return cgroup_id;

    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    void *dest;

    u32 size = 0;
    u32 family = ctx->family;

    switch (family)
    {
    case PF_INET:
        dest = &nethdrs->iphdrs.iphdr;
        size = bpf_core_type_size(struct iphdr);
        break;
    case PF_INET6:
        dest = &nethdrs->iphdrs.ipv6hdr;
        size = bpf_core_type_size(struct ipv6hdr);
        break;
    default:
        return cgroup_id;
    }

    // load layer 3 headers (for cgrpctxmap key/indexer)

    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1))
        return cgroup_id;

    indexer_t indexer = {0};
    indexer.ts = ctx->tstamp;

    u32 ihl = 0;
    __u8 ip_version = 0;
    switch (family)
    {
    case PF_INET:
        if (nethdrs->iphdrs.iphdr.version == 4)
        {
            ip_version = nethdrs->iphdrs.iphdr.version;
        }
        break;

    case PF_INET6:
        ip_version = nethdrs->iphdrs.ipv6hdr.version;
        break;

    default:
        return cgroup_id;
    }

    switch (ip_version)
    {
    case 4:
        ihl = nethdrs->iphdrs.iphdr.ihl;
        if (ihl > 5)
        { // re-read IPv4 header if needed
            size -= bpf_core_type_size(struct iphdr);
            size += ihl * 4;
            bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1);
        }

        switch (nethdrs->iphdrs.iphdr.protocol)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
            break;
        default:
            return cgroup_id;
        }

        // add IPv4 header items to indexer
        indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
        indexer.src.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
        indexer.dst.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
        break;

    case 6:
        switch (nethdrs->iphdrs.ipv6hdr.nexthdr)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMPV6:
            break;
        default:
            return cgroup_id;
        }

        // add IPv6 header items to indexer
        __builtin_memcpy(&indexer.src.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
        __builtin_memcpy(&indexer.dst.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
        break;

    default:
        return cgroup_id;
    }

    __u64 *cgroup_id_ptr = bpf_map_lookup_elem(cgrpctxmap, &indexer);
    if (!cgroup_id_ptr)
    {
        // 1. kthreads receiving ICMP and ICMPv6 (e.g dest unreach)
        // 2. tasks not being traced
        // 3. unknown (yet) sockets (need egress packet to link task and inode)
        // ...
    }
    else
    {
        cgroup_id = *cgroup_id_ptr;
        bpf_map_delete_elem(cgrpctxmap, &indexer); // cleanup
    }

    return cgroup_id;
}
