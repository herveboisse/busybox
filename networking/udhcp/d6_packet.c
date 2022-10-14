/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2011 Denys Vlasenko.
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include "common.h"
#include "d6_common.h"
#include "dhcpc.h"
#include "dhcpd.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>

#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 2
void FAST_FUNC d6_dump_packet(struct d6_packet *packet)
{
	if (dhcp_verbose < 2)
		return;

	bb_info_msg(
		" xid %x"
		, packet->d6_xid32
	);
	//*bin2hex(buf, (void *) packet->chaddr, sizeof(packet->chaddr)) = '\0';
	//bb_error_msg(" chaddr %s", buf);
}
#endif

int FAST_FUNC d6_recv_kernel_packet(struct in6_addr *peer_ipv6,
		struct d6_packet *packet, int fd)
{
	int bytes;
	struct sockaddr_in6 sa;
	socklen_t slen;

	memset(packet, 0, sizeof(*packet));
	memset(&sa, 0, sizeof(sa));
	slen = sizeof(sa);
	bytes = recvfrom(fd, packet, sizeof(*packet), 0, (struct sockaddr *)&sa, &slen);
	if (bytes < 0) {
		log1s("packet read error, ignoring");
		return bytes; /* returns -1 */
	}
	if (peer_ipv6)
		*peer_ipv6 = sa.sin6_addr;

	if (bytes < offsetof(struct d6_packet, d6_options)) {
		bb_simple_info_msg("packet with bad magic, ignoring");
		return -2;
	}
	log2("received %s", "a packet");
	/* log2 because more informative msg for valid packets is printed later at log1 level */
	d6_dump_packet(packet);

	return bytes;
}

/* Let the kernel do all the work for packet generation */
int FAST_FUNC d6_send_kernel_packet_from_client_data_ifindex(
		struct d6_packet *d6_pkt, unsigned d6_pkt_size,
		const struct in6_addr *dst_ipv6, int dest_port)
{
	struct sockaddr_in6 sa;
	int result = -1;
	const char *msg;

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(dest_port);
	sa.sin6_addr = *dst_ipv6; /* struct copy */
	sa.sin6_scope_id = client_data.ifindex;

	d6_dump_packet(d6_pkt);
	result = sendto(client_data.sockfd, d6_pkt, d6_pkt_size,
			/*flags:*/ 0,
			(struct sockaddr *)&sa, sizeof(sa)
	);
	msg = "sendto";
	if (result < 0)
		bb_perror_msg(msg, "UDP");
	return result;
}
