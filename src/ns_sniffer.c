/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Rp
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * ns_sniffer.c
 *
 *  Created on			: 03-Nov-2015
 *  Author				: rp
 *  Date					: 12:50:24 am
 */

#include <sys/socket.h>						/* socket, AF_PACKET, SOCK_RAW */
#include <errno.h>								/* errno */
#include <linux/if_packet.h>				/* sockaddr_ll */
#include <net/if.h>								/* ifr */
#include <netinet/if_ether.h>			/* ETH_P_ALL */
#include <arpa/inet.h>						/* htons */
#include <unistd.h>							/* close */
#include <string.h>								/* strncpy */
#include <sys/ioctl.h>						/* SIOCGIFINDEX, SIOCGIFHWADDR */

#include "ns_arp.h"
#include "ns_config.h"
#include "ns_packet_processor.h"
#include "ns_sniffer.h"
#include "ns_utils.h"

#if 0
PRIVATE ns_error_t bind_to_interface(
	IN int sock_fd)
{
	int interface_idx = 0;
	struct ifreq interface_request;
	struct sockaddr_ll sock_addr;

	strncpy(interface_request.ifr_name, DEFAULT_NETWORK_INTERFACE, IFNAMSIZ);
	if (ioctl(sock_fd, SIOCGIFINDEX, &interface_request) == -1) {
		ERR("Unable to get the interface index!");
		return ns_interface_error;
	}
	interface_idx = interface_request.ifr_ifindex;
	DBG("Index: %d", interface_idx);

	sock_addr.sll_family = AF_PACKET;
	sock_addr.sll_protocol = htons(NS_ETH_TYPE_ARP);
	sock_addr.sll_ifindex = interface_idx;

	if (bind(sock_fd, (struct sockaddr*) &sock_addr, sizeof(sock_addr)) < 0) {
		ERR("Unable to bind!");
		return ns_bind_failed;
	}

	return ns_success;
}
#endif

PUBLIC ns_error_t sniffer(void)
{
	ns_error_t response = ns_success;

	int raw_sock = -1;
	int data_size = 0;

	unsigned char* buf = NULL;
	//unsigned char dest_mac[NS_ETH_ADDR_LEN];
	unsigned char local_mac[NS_ETH_ADDR_LEN];

	socklen_t saddr_size;
	struct sockaddr saddr;

	DBG("opening raw socket...");
	raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_sock < 0) {
		ERR("Socket Error!");
		return ns_socket_failed;
	}

#if 0
	DBG("binding the raw socket to %s...", DEFAULT_NETWORK_INTERFACE);
	response = bind_to_interface(raw_sock);
	if (ns_success != response) {
		ERR("Bind Failed!");
		return response;
	}
#endif

	response = get_MAC_from_device_name(DEFAULT_NETWORK_INTERFACE, local_mac);
	if (ns_success != response) {
		ERR("Unable to retreive MAC for device: %s", DEFAULT_NETWORK_INTERFACE);
		close(raw_sock);
		return response;
	}

	buf = (unsigned char*) malloc(DEFAULT_BUF_SIZE);
	if (NULL == buf) {
		ERR("No mem!");
		close(raw_sock);
		return ns_malloc_failed;
	}

	DBG("listening for Ethernet packets...");
	while (1) {
		saddr_size = sizeof(saddr);

		if ((data_size = recvfrom(raw_sock, buf, DEFAULT_BUF_SIZE, 0, &saddr,
			(socklen_t *) &saddr_size)) < 0) {
			ERR("No data!");
			free(buf);
			close(raw_sock);
			return ns_recvfrom_received_no_data;
		}

		process_packet(buf, data_size);

	}

	ERR("done\n");
	return ns_success;
}
