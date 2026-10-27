/* Keep Darwin's versioned C layouts at the SDK boundary. No subprocesses. */
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

struct rustnet_socket {
    int32_t family;
    int32_t protocol;
    int32_t state;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t local_address[16];
    uint8_t remote_address[16];
    uint64_t identity;
};

int rustnet_socket_info(int pid, int fd, struct rustnet_socket *out) {
    struct socket_fdinfo info;
    memset(&info, 0, sizeof(info));
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    if (size != sizeof(info)) return -(errno ? errno : EIO);
    struct socket_info *socket = &info.psi;
    if (socket->soi_family != AF_INET && socket->soi_family != AF_INET6) return 0;
    if (socket->soi_protocol != IPPROTO_TCP && socket->soi_protocol != IPPROTO_UDP) return 0;
    if (socket->soi_kind != SOCKINFO_TCP && socket->soi_kind != SOCKINFO_IN) return 0;
    const struct in_sockinfo *ip = socket->soi_kind == SOCKINFO_TCP
        ? &socket->soi_proto.pri_tcp.tcpsi_ini : &socket->soi_proto.pri_in;
    memset(out, 0, sizeof(*out));
    out->family = socket->soi_family;
    out->protocol = socket->soi_protocol;
    out->state = socket->soi_kind == SOCKINFO_TCP ? socket->soi_proto.pri_tcp.tcpsi_state : 0;
    out->local_port = ntohs((uint16_t)ip->insi_lport);
    out->remote_port = ntohs((uint16_t)ip->insi_fport);
    out->identity = socket->soi_so;
    if (out->family == AF_INET) {
        memcpy(out->local_address, &ip->insi_laddr.ina_46.i46a_addr4, 4);
        memcpy(out->remote_address, &ip->insi_faddr.ina_46.i46a_addr4, 4);
    } else {
        memcpy(out->local_address, &ip->insi_laddr.ina_6, 16);
        memcpy(out->remote_address, &ip->insi_faddr.ina_6, 16);
    }
    return 1;
}
