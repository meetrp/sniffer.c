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
 *  Created on		: 06-Nov-2015
 *  Author		: rp
 *  Date			: 12:57:22 am
 */

#include <string.h>
#include <netinet/in.h>
//#include <sys/socket.h>
#include <arpa/inet.h>

#include "ns_log.h"
#include "ns_arp.h"
#include "ns_utils.h"
#include "ns_config.h"

static unsigned char blacklist[][NS_ETH_IPv4_PRINTABLE_MAC_SIZE] =
{
        "08:00:27:6E:C9:AA"
};

static void convert_arp_type(const uint16_t opcode, char *arp_type)
{
	switch (opcode) {
		case NS_ARP_REQUEST:
			snprintf((char *) arp_type, NS_ARP_TYPE_STR_LEN,
			        "Reqst");
			break;
		case NS_ARP_REPLY:
			snprintf((char *) arp_type, NS_ARP_TYPE_STR_LEN,
			        "Reply");
			break;
	}
}

static void convert_arp_payload_to_human_readable(
        const ns_arp_IPv4_eth_packet_t *arp_IPv4_payload,
        ns_arp_IPv4_eth_payload_t *arp_IPv4_human_readable)
{
	human_readable_MAC(arp_IPv4_payload->ns_arp_sender_hw_addr,
	        arp_IPv4_human_readable->ns_arp_sender_hw_addr);
	human_readable_IPv4(arp_IPv4_payload->ns_arp_sender_proto_addr,
	        arp_IPv4_human_readable->ns_arp_sender_proto_addr);

	human_readable_MAC(arp_IPv4_payload->ns_arp_target_hw_addr,
	        arp_IPv4_human_readable->ns_arp_target_hw_addr);
	human_readable_IPv4(arp_IPv4_payload->ns_arp_target_proto_addr,
	        arp_IPv4_human_readable->ns_arp_target_proto_addr);
}

static void dump_ipv4_eth_arp_packet(const ns_arp_IPv4_eth_packet_t *arp_IPv4)
{
	char arp_type[NS_ARP_TYPE_STR_LEN];
	ns_arp_IPv4_eth_payload_t arp_IPv4_human_readable;

	convert_arp_type(ntohs(arp_IPv4->ns_arp_hdr.ns_arp_opcode), arp_type);
	convert_arp_payload_to_human_readable(arp_IPv4,
	        &arp_IPv4_human_readable);
	DBG("ARP: %s [%s (%s)] --> [%s (%s)]", arp_type,
	        arp_IPv4_human_readable.ns_arp_sender_hw_addr,
	        arp_IPv4_human_readable.ns_arp_sender_proto_addr,
	        arp_IPv4_human_readable.ns_arp_target_hw_addr,
	        arp_IPv4_human_readable.ns_arp_target_proto_addr);
}

static void modify_packet_to_ARP_reply(const unsigned char* local_mac,
        ns_arp_IPv4_eth_packet_t* arp_IPv4)
{
	unsigned char temp_ip[NS_IPv4_ADDR_LEN];

	DBG("--------------------------------------------------");
	dump_ipv4_eth_arp_packet(arp_IPv4);

	/* swap the entries except for sender mac */
	memcpy(arp_IPv4->ns_arp_target_hw_addr, arp_IPv4->ns_arp_sender_hw_addr,
	        NS_ETH_ADDR_LEN);
	memcpy(arp_IPv4->ns_arp_sender_hw_addr, local_mac, NS_ETH_ADDR_LEN);

	memcpy(temp_ip, arp_IPv4->ns_arp_sender_proto_addr, NS_IPv4_ADDR_LEN);
	memcpy(arp_IPv4->ns_arp_sender_proto_addr,
	        arp_IPv4->ns_arp_target_proto_addr, NS_IPv4_ADDR_LEN);
	memcpy(arp_IPv4->ns_arp_target_proto_addr, temp_ip, NS_IPv4_ADDR_LEN);

	arp_IPv4->ns_arp_hdr.ns_arp_opcode = ntohs(NS_ARP_REPLY);

	DBG("--------------------------------------------------");
	dump_ipv4_eth_arp_packet(arp_IPv4);
	DBG("--------------------------------------------------");
}

ns_error_t spoof_arp_response_if_blacklisted(const unsigned char* local_mac,
        unsigned char* buf)
{
	ns_arp_IPv4_eth_payload_t arp_IPv4_human_readable;
	ns_arp_IPv4_eth_packet_t* arp_IPv4 = (ns_arp_IPv4_eth_packet_t *) buf;
	ns_error_t response = ns_success;
	struct in_addr in_addr;

	if (ntohs(arp_IPv4->ns_arp_hdr.ns_arp_opcode) != NS_ARP_REQUEST) {
		return ns_not_ipv4_arp_request_packet;
	}

	get_ip_addr_from_name(DEFAULT_NETWORK_INTERFACE, &in_addr);
	DBG("%s", inet_ntoa(in_addr));

	convert_arp_payload_to_human_readable(arp_IPv4,
	        &arp_IPv4_human_readable);

	DBG("is found?");
	response = is_found((const unsigned char**) blacklist,
	        arp_IPv4_human_readable.ns_arp_target_hw_addr);
	if (ns_success != response) {
		ERR("Not found in blacklist: %d!", response);
		return response;
	}

	DBG("about to modify");
	modify_packet_to_ARP_reply(local_mac, arp_IPv4);

	return response;
}

ns_error_t parse_arp_packet(const unsigned char *packet)
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
