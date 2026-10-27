#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

struct rustnet_bpf_record { int64_t seconds; int64_t microseconds; uint32_t offset; uint32_t captured; uint32_t original; uint32_t next; };
int rustnet_bpf_dimensions(int fd, uint32_t *length, uint32_t *linktype) {
    if (ioctl(fd, BIOCGBLEN, length) < 0 || ioctl(fd, BIOCGDLT, linktype) < 0) return -errno;
    return 0;
}
int rustnet_bpf_record(const uint8_t *buffer, uint32_t length, uint32_t offset, struct rustnet_bpf_record *out) {
    if (offset >= length) return 0;
    if (length-offset < sizeof(struct bpf_hdr)) return -EINVAL;
    struct bpf_hdr header; memcpy(&header, buffer+offset, sizeof(header));
    if (header.bh_hdrlen < sizeof(header) || header.bh_hdrlen > length-offset || header.bh_caplen > length-offset-header.bh_hdrlen) return -EINVAL;
    out->seconds=header.bh_tstamp.tv_sec; out->microseconds=header.bh_tstamp.tv_usec;
    out->offset=offset+header.bh_hdrlen; out->captured=header.bh_caplen; out->original=header.bh_datalen;
    uint64_t next=(uint64_t)offset+BPF_WORDALIGN((uint64_t)header.bh_hdrlen+header.bh_caplen);
    out->next=next>length?length:(uint32_t)next;
    return 1;
}
int rustnet_bpf_stats(int fd, uint32_t *received, uint32_t *dropped) {
    struct bpf_stat stats;
    if (ioctl(fd, BIOCGSTATS, &stats)<0) return -errno;
    *received=stats.bs_recv; *dropped=stats.bs_drop; return 0;
}
