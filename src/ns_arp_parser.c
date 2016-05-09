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
 * ns_arp_parser.c
 *
 *  Created on			: 03-Nov-2015
 *  Author				: rp
 *  Date					: 12:57:22 am
 */

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ns_log.h"
#include "ns_arp.h"
#include "ns_utils.h"
#include "ns_config.h"

PRIVATE void convert_arp_type(IN uint16_t opcode, OUT char *arp_type)
{
	switch (opcode) {
		case NS_ARP_REQUEST:
		snprintf((char *) arp_type, NS_ARP_TYPE_STR_LEN, "Reqst");
		break;
		case NS_ARP_REPLY:
		snprintf((char *) arp_type, NS_ARP_TYPE_STR_LEN, "Reply");
		break;
	}
}

PRIVATE void dump_ipv4_eth_arp_packet(IN ns_arp_IPv4_eth_packet_t *arp_IPv4)
{
	char arp_type[NS_ARP_TYPE_STR_LEN];
	char src_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char src_ip[NS_ETH_IPv4_PRINTABLE_IPv4_SIZE];
	char dest_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char dest_ip[NS_ETH_IPv4_PRINTABLE_IPv4_SIZE];

	convert_arp_type(ntohs(arp_IPv4->ns_arp_hdr.ns_arp_opcode), arp_type);
	human_readable_MAC(arp_IPv4->ns_arp_sender_hw_addr, src_mac);
	human_readable_MAC(arp_IPv4->ns_arp_target_hw_addr, dest_mac);
	human_readable_IPv4(arp_IPv4->ns_arp_sender_proto_addr, src_ip);
	human_readable_IPv4(arp_IPv4->ns_arp_target_proto_addr, dest_ip);

	DBG("[%4s] (%5s) %s --> %s", "ARP", arp_type, src_ip, dest_ip);
}

PUBLIC ns_error_t parse_arp_packet(IN unsigned char *packet)
{
	ns_arp_IPv4_eth_packet_t *arp_IPv4 = NULL;
	ns_arp_packet_hdr_t *arp_hdr = (ns_arp_packet_hdr_t *) packet;

	if (ntohs(arp_hdr->ns_arp_hw_type) != NS_ARP_ETHERNET_TYPE) {
		ERR("Not ethernet!!");
		return ns_not_ethernet_arp_packet;
	}

	if (ntohs(arp_hdr->ns_arp_proto_type) != NS_ETH_TYPE_IPv4) {
		ERR("Not IPv4!");
		return ns_not_ipv4_arp_packet;
	}

	arp_IPv4 = (ns_arp_IPv4_eth_packet_t *) packet;
	dump_ipv4_eth_arp_packet(arp_IPv4);

	return ns_success;
}
