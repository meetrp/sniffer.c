/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Rp
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
 *  Created on		: 03-Nov-2015
 *  Author		: rp
 *  Date			: 12:50:24 am
 */

#include <sys/socket.h>			/* socket, AF_PACKET, SOCK_RAW */
#include <linux/if_packet.h>		/* sockaddr_ll */
#include <net/if.h>				/* ifr */
#include <netinet/if_ether.h>	/* ETH_P_ALL */
#include <arpa/inet.h>			/* htons */
#include <unistd.h>			/* close */
#include <string.h>				/* strncpy */
#include <sys/ioctl.h>			/* SIOCGIFINDEX, SIOCGIFHWADDR */

#include "ns_sniffer.h"			/* includes standard header */

#include "ns_packet_processor.h"
#include "ns_config.h"
#include "ns_arp.h"			/* ARP spoofing requirement */

static ns_error_t send_arp_response(unsigned char *buf, unsigned char *dest_mac)
{
	struct sockaddr_ll sock_addr;
	int interface_idx = 0;
	struct ifreq interface_request;

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0) {
		ERR("Unable to open raw socket!");
		return ns_socket_failed;
	}

	strncpy(interface_request.ifr_name, DEFAULT_NETWORK_INTERFACE,
	        IFNAMSIZ);
	if (ioctl(sock_raw, SIOCGIFINDEX, &interface_request) == -1) {
		ERR("Unable to get the interface index!");
		return ns_interface_error;
	}
	interface_idx = interface_request.ifr_ifindex;
	DBG("Index: %d", interface_idx);

	sock_addr.sll_family = PF_PACKET;
	sock_addr.sll_protocol = htons(NS_ETH_TYPE_ARP);
	sock_addr.sll_ifindex = interface_idx;
	sock_addr.sll_hatype = NS_ARP_ETHERNET_TYPE;
	sock_addr.sll_pkttype = 0; //PACKET_OTHERHOST;
	sock_addr.sll_halen = 0;

	/* ethernet address */
	sock_addr.sll_addr[0] = dest_mac[0];
	sock_addr.sll_addr[1] = dest_mac[1];
	sock_addr.sll_addr[2] = dest_mac[2];
	sock_addr.sll_addr[3] = dest_mac[3];
	sock_addr.sll_addr[4] = dest_mac[4];
	sock_addr.sll_addr[5] = dest_mac[5];
	sock_addr.sll_addr[6] = 0x00;
	sock_addr.sll_addr[7] = 0x00;

	if (sendto(sock_raw, buf, DEFAULT_BUF_SIZE, 0,
	        (struct sockaddr*) &sock_addr, sizeof(sock_addr))) {
		ERR("Send to failed!");
		return ns_sendto_failed;
	}

	return ns_success;
}

ns_error_t sniffer()
{
	int raw_sock = -1;

	unsigned char *buf = NULL;
	unsigned char dest_mac[NS_ETH_ADDR_LEN];
	unsigned char local_mac[NS_ETH_ADDR_LEN];
	struct sockaddr saddr;
	socklen_t saddr_size;

	int data_size = 0;

	DBG("About to open raw socket!");
	raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_sock < 0) {
		ERR("Socket Error!");
		return ns_socket_failed;
	}

	DBG("Mallocing");
	buf = (unsigned char*) malloc(DEFAULT_BUF_SIZE);
	if (NULL == buf) {
		ERR("No mem!");
		close(raw_sock);
		return ns_malloc_failed;
	}

	while (1) {
		saddr_size = sizeof(saddr);

		if ((data_size = recvfrom(raw_sock, buf, DEFAULT_BUF_SIZE, 0,
		        &saddr, (socklen_t *) &saddr_size)) < 0) {
			ERR("No data!");
			free(buf);
			close(raw_sock);
			return ns_recvfrom_received_no_data;
		}

		process_packet(buf, data_size);

		if (ns_success
		        != get_MAC_from_device_name(DEFAULT_NETWORK_INTERFACE,
		                local_mac)) {
			ERR("Unable to retreive MAC for device: %s",
			        DEFAULT_NETWORK_INTERFACE);
			continue;
		}

		if (ns_success
		        != prepare_arp_spoof_response_buf_if_blacklisted(
		                local_mac, buf, (unsigned char*) dest_mac)) {
			continue;
		}

		if (ns_success != send_arp_response(buf, dest_mac)) {
			continue;
		}
	}

	ERR("done\n");
	return ns_success;
}
