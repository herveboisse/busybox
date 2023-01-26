/* vi: set sw=4 ts=4: */
/*
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 *
 * Copyright (C) 2004-2007 Rémi Denis-Courmont
 *
 * Busybox port: Hervé Boisse <admin@netgeek.ovh>
 */
//config:config NDISC6
//config:	bool "ndisc6 (xx kb)"
//config:	default y
//config:	depends on FEATURE_IPV6
//config:	help
//config:	ICMPv6 neighbour discovery command line tool.
//config:
//config:config FEATURE_NDISC6_LONG_OPTIONS
//config:	bool "Enable long options"
//config:	default y
//config:	depends on NDISC6 && LONG_OPTS

//applet:IF_NDISC6(APPLET(ndisc6, BB_DIR_USR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_NDISC6) += ndisc6.o

//usage:#define ndisc6_trivial_usage
//usage:       "[-1mnqv] [-r TRIES] [-s SOURCE] [-w WAIT] IPV6_ADDRESS INTERFACE"
//usage:#define ndisc6_full_usage "\n\n"
//usage:       "Looks up an on-link IPv6 node link-layer address (Neighbor Discovery)\n"
//usage:     "\n	-1		Display first response and exit"
//usage:     "\n	-m		Wait and display all responses"
//usage:     "\n	-n		Do not resolve host names"
//usage:     "\n	-q		Only print the link-layer address (mainly for scripts)"
//usage:     "\n	-v		Verbose display (this is the default)"
//usage:     "\n	-r TRIES	Maximum number of attempts (default: 3)"
//usage:     "\n	-s SOURCE	Specify source IPv6 address"
//usage:     "\n	-w WAIT		How long to wait for a response [ms] (default: 1000)"
//usage:     "\n	IPV6_ADDRESS	Target IPv6 address"
//usage:     "\n	INTERFACE	Interface"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libbb.h"

#ifndef IPV6_RECVHOPLIMIT
/* Using obsolete RFC 2292 instead of RFC 3542 */
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif

/* BSD-like systems define ND_RA_FLAG_HA instead of ND_RA_FLAG_HOME_AGENT */
#ifndef ND_RA_FLAG_HOME_AGENT
#ifdef ND_RA_FLAG_HA
#define ND_RA_FLAG_HOME_AGENT ND_RA_FLAG_HA
#endif
#endif

#define NDISC6_OPTS			"^1mnqr:+s:vw:+\0=2vv"
enum {
	OPT_SINGLE		= 1 << 0,
	OPT_MULTIPLE	= 1 << 1,
	OPT_NUMERIC		= 1 << 2,
	OPT_QUIET		= 1 << 3,
	OPT_RETRY		= 1 << 4,
	OPT_SOURCE		= 1 << 5,
	OPT_VERBOSE		= 1 << 6,
	OPT_WAIT		= 1 << 7,
};

#define NDISC6_DEFAULT_FLAGS	(NDISC_VERBOSE1 | NDISC_SINGLE)
enum ndisc_flags {
	NDISC_VERBOSE1	= 0x1,
	NDISC_VERBOSE2	= 0x2,
	NDISC_VERBOSE3	= 0x3,
	NDISC_VERBOSE	= 0x3,
	NDISC_NUMERIC	= 0x4,
	NDISC_SINGLE	= 0x8,
};

struct solicit_packet {
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[ETHER_ADDR_LEN];
};

static void getipv6byname(const char *name, const char *ifname, bool numeric,
			struct sockaddr_in6 *addr)
{
	struct addrinfo hints, *res = NULL;
	int val;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	if (numeric)
		hints.ai_flags |= AI_NUMERICHOST;

	val = getaddrinfo(name, NULL, &hints, &res);
	if (val)
		bb_error_msg_and_die("%s: %s", name, gai_strerror(val));

	*addr = *(struct sockaddr_in6 *)res->ai_addr;
	freeaddrinfo(res);

	val = if_nametoindex(ifname);
	if (val == 0)
		bb_simple_perror_msg_and_die(ifname);
	addr->sin6_scope_id = val;
}

static void printmacaddress(const uint8_t *ptr, size_t len)
{
	while (len > 1) {
		printf("%02X:", *ptr);
		ptr++;
		len--;
	}

	printf("%02X\n", *ptr);
}

static int getmacaddress(const char *ifname, uint8_t *addr)
{
#ifdef SIOCGIFHWADDR
	struct ifreq req;
	int fd, ret;

	fd = xsocket(PF_INET6, SOCK_DGRAM, 0);

	memset(&req, 0, sizeof(req));
	strncpy_IFNAMSIZ(req.ifr_name, ifname);
	ret = ioctl(fd, SIOCGIFHWADDR, &req);
	close(fd);
	if (ret)
		return -1;

	memcpy(addr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	return 0;
#else /* No SIOCGIFHWADDR, which seems Linux specific. */
	struct ifaddrs *ifa = NULL, *ifp;

	getifaddrs(&ifa);

	for (ifp = ifa; ifp; ifp = ifp->ifa_next) {
		if (ifp->ifa_addr->sa_family == AF_LINK && strcmp(ifp->ifa_name, ifname) == 0) {
			const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)ifp->ifa_addr;

			memcpy(addr, sdl->sdl_data + sdl->sdl_nlen, ETHER_ADDR_LEN);
			freeifaddrs(ifa);

			return 0;
		}
	}

	freeifaddrs(ifa);

	return -1;
#endif
}

static ssize_t buildsol(struct solicit_packet *ns, struct sockaddr_in6 *tgt,
					const char *ifname)
{
	static const uint8_t solicited_node_addr[] = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff
	};

	/* builds ICMPv6 Neighbor Solicitation packet */
	ns->hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->hdr.nd_ns_code = 0;
	ns->hdr.nd_ns_cksum = 0; /* computed by the kernel */
	ns->hdr.nd_ns_reserved = 0;
	ns->hdr.nd_ns_target = tgt->sin6_addr;

	/* determines actual multicast destination address */
	memcpy(tgt->sin6_addr.s6_addr, solicited_node_addr, sizeof(solicited_node_addr));

	/* gets our own interface's link-layer address (MAC) */
	if (getmacaddress(ifname, ns->hw_addr))
		return sizeof(ns->hdr);

	ns->opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	ns->opt.nd_opt_len = 1; /* 8 bytes */

	return sizeof(*ns);
}

static int parseadv(const uint8_t *buf, size_t len, const struct sockaddr_in6 *tgt,
				bool verbose)
{
	const struct nd_neighbor_advert *na = (const struct nd_neighbor_advert *)buf;
	const uint8_t *ptr;

	/* checks if the packet is a Neighbor Advertisement, and
	 * if the target IPv6 address is the right one
	 */
	if (len < sizeof(struct nd_neighbor_advert) ||
			na->nd_na_type != ND_NEIGHBOR_ADVERT ||
			na->nd_na_code != 0 ||
			!IN6_ARE_ADDR_EQUAL(&na->nd_na_target, &tgt->sin6_addr))
		return -1;

	len -= sizeof(struct nd_neighbor_advert);

	/* looks for Target Link-layer address option */
	ptr = buf + sizeof(struct nd_neighbor_advert);

	while (len >= 8) {
		uint16_t optlen;

		optlen = (uint16_t)ptr[1] << 3;
		if (optlen == 0)
			break; /* invalid length */

		if (len < optlen) /* length > remaining bytes */
			break;
		len -= optlen;


		/* skips unrecognized option */
		if (ptr[0] != ND_OPT_TARGET_LINKADDR) {
			ptr += optlen;
			continue;
		}

		/* Found! displays link-layer address */
		ptr += 2;
		optlen -= 2;
		if (verbose)
			puts("Target link-layer address: ");

		printmacaddress(ptr, optlen);
		return 0;
	}

	return -1;
}

static ssize_t recvfromLL(int fd, void *buf, size_t len, int flags,
					struct sockaddr_in6 *addr)
{
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len
	};
	struct msghdr hdr = {
		.msg_name = addr,
		.msg_namelen = sizeof(*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf)
	};
	struct cmsghdr *cmsg;
	ssize_t val;

	val = recvmsg(fd, &hdr, flags);
	if (val < 0)
		return val;

	/* ensures the hop limit is 255 */
	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_HOPLIMIT &&
				*(int *)CMSG_DATA(cmsg) != 255) {
			/* pretend to be a spurious wake-up */
			errno = EAGAIN;
			return -1;
		}
	}

	return val;
}

static ssize_t recvadv(int fd, const struct sockaddr_in6 *tgt, unsigned int wait_ms,
					unsigned int flags)
{
	unsigned int responses = 0;
	const bool verbose = !!(flags & NDISC_VERBOSE);
	struct pollfd fds;
	long long end, now;
	ssize_t val;
	// TODO: use interface MTU as buffer size
	union {
		uint8_t b[1460];
		uint64_t align;
	} buf;
	struct sockaddr_in6 addr;

	/* computes deadline time */
	end = monotonic_ms() + wait_ms;

	fds.fd = fd;
	fds.events = POLLIN;

	/* receive loop */
	for (;;) {
		/* waits for reply until deadline */

		now = monotonic_ms();
		val = MAX(0, end - now);

		val = poll(&fds, 1, val);
		if (val < 0) {
			bb_simple_perror_msg("poll");
			break;
		} else if (val == 0) {
			return responses;
		}

		/* receives an ICMPv6 packet */
		val = recvfromLL(fd, &buf, sizeof(buf), MSG_DONTWAIT, &addr);
		if (val < 0) {
			if (errno != EAGAIN)
				bb_simple_perror_msg("Receiving ICMPv6 packet");
			continue;
		}

		/* ensures the response came through the right interface */
		if (addr.sin6_scope_id && addr.sin6_scope_id != tgt->sin6_scope_id)
			continue;

		if (parseadv(buf.b, val, tgt, verbose) == 0) {
			if (verbose) {
				char str[INET6_ADDRSTRLEN];
				inet_ntop(PF_INET6, &addr.sin6_addr, str, sizeof(str));
				printf(" from %s\n", str);
			}

			if (responses < INT_MAX)
				responses++;

			if (flags & NDISC_SINGLE)
				return 1 /* = responses */;
		}
	}

	return -1; /* error */
}

static int ndisc(const char *name, const char *ifname, unsigned int flags,
			unsigned int retry, unsigned int wait_ms, const char *source)
{
	int err = -1, fd;
	const bool verbose = !!(flags & NDISC_VERBOSE);
	const bool numeric = !!(flags & NDISC_NUMERIC);
	struct sockaddr_in6 tgt, dst;
	struct icmp6_filter f;
	struct solicit_packet packet;
	ssize_t plen, responses;

	fd = xsocket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	close_on_exec_on(fd);

	ICMP6_FILTER_SETBLOCKALL(&f);
	ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &f);
	setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof(f));

	setsockopt_SOL_SOCKET_1(fd, SO_DONTROUTE);

	setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
	setsockopt_int(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255);
	setsockopt_1(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT);

	if (source != NULL) {
		getipv6byname(source, ifname, numeric, &tgt);
		xbind(fd, (struct sockaddr *)&tgt, sizeof(tgt));
	}

	getipv6byname(name, ifname, numeric, &tgt);
	if (verbose) {
		char str[INET6_ADDRSTRLEN];
		inet_ntop(PF_INET6, &tgt.sin6_addr, str, sizeof(str));
		printf("Soliciting %s (%s) on %s...\n", name, str, ifname);
	}

	dst = tgt;
	plen = buildsol(&packet, &dst, ifname);

	while (retry > 0) {
		/* sends a Solitication */
		if (sendto(fd, &packet, plen, 0, (struct sockaddr *)&dst,
				sizeof(dst)) != plen)
			bb_simple_perror_msg_and_die("Sending ICMPv6 packet");
		retry--;

		/* receives an Advertisement */
		responses = recvadv(fd, &tgt, wait_ms, flags);
		if (responses > 0) {
			err = 0;
			break;
		} else if (responses == 0) {
			if (verbose)
				puts("Timed out.");
		} else {
			break;
		}
	}

	if (retry <= 0 && responses == 0) {
		err = -2;
		if (verbose)
			puts("No response.");
	}

	close(fd);

	return err;
}

#if ENABLE_FEATURE_NDISC6_LONG_OPTIONS
static const char ndisc6_longopts[] ALIGN1 =
	"single\0"		No_argument			"1"
	"multiple\0"	No_argument			"m"
	"numeric\0"		No_argument			"n"
	"quiet\0"		No_argument			"q"
	"verbose\0"		No_argument			"v"
	"retry\0"		Required_argument	"r"
	"source\0"		Required_argument	"s"
	"wait\0"		Required_argument	"w"
	;
#endif

int ndisc6_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int ndisc6_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned int opt;
	unsigned int retry = 3, wait_ms = 1000;
	const char *hostname, *ifname, *source = NULL;
	unsigned int flags = NDISC6_DEFAULT_FLAGS;
	int verbose_level = 0;

#if ENABLE_FEATURE_NDISC6_LONG_OPTIONS
	opt = getopt32long(argv, NDISC6_OPTS, ndisc6_longopts,
#else
	opt = getopt32(argv, NDISC6_OPTS,
#endif
		&retry, &source, &wait_ms, &verbose_level
	);

	argv += optind;
	hostname = argv[0];
	ifname = argv[1];

	if (opt & OPT_SINGLE)
		flags |= NDISC_SINGLE;
	if (opt & OPT_MULTIPLE)
		flags &= ~NDISC_SINGLE;
	if (opt & OPT_NUMERIC)
		flags |= NDISC_NUMERIC;
	if (opt & OPT_QUIET)
		flags &= ~NDISC_VERBOSE;
	for (; verbose_level > 0; verbose_level--) {
		/* NOTE: assume NDISC_VERBOSE occupies low-order bits */
		if ((flags & NDISC_VERBOSE) < NDISC_VERBOSE)
			flags++;
	}

	return -ndisc(hostname, ifname, flags, retry, wait_ms, source);
}
