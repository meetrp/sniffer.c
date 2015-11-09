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
 * ns_ethernet_parser.c
 *
 *  Created on			: 06-Nov-2015
 *  Author			: rp
 *  Date				: 1:07:00 am
 */

#include <netinet/in.h>
#include <string.h>

#include "ns_ethernet.h"
#include "ns_log.h"
#include "ns_utils.h"
#include "ns_arp.h"
#include "ns_config.h"

static void convert_eth_type(const uint16_t type, char *eth_type)
{
	switch (type) {
		case NS_ETH_TYPE_IPv4:
			snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN,
			        "IPv4");
			break;
		case NS_ETH_TYPE_IPv6:
			snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN,
			        "IPv6");
			break;
		case NS_ETH_TYPE_ARP:
			snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN, "ARP");
			break;
	}
}

void dump_eth_packet(ns_ethernet_frame_hdr_t *eth_hdr)
{
	char dest_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char src_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char eth_type[NS_ETH_TYPE_STR_LEN];

	convert_eth_type(ntohs(eth_hdr->ns_eth_type), eth_type);
	human_readable_MAC(eth_hdr->ns_eth_src, src_mac);
	human_readable_MAC(eth_hdr->ns_eth_dest, dest_mac);
	DBG("ETH: %s\t[%s] --> [%s]", eth_type, src_mac, dest_mac);
}

ns_error_t parse_ethernet_packet(const unsigned char *buf, const int buf_size,
        unsigned char** payload_offset, uint16_t* payload_type)
{
	ns_ethernet_frame_hdr_t *eth_hdr = NULL;

	if (NULL == buf) {
		ERR("buf is NULL!");
		return ns_eth_empty_packet;
	}

	eth_hdr = (ns_ethernet_frame_hdr_t *) buf;
	if (ntohs(eth_hdr->ns_eth_type) == NS_ETH_TYPE_ARP) {
		dump_eth_packet(eth_hdr);
	}

	/*
	 * Not working!!
	 if ((buf_size < NS_ETH_MIN_LEN) || (buf_size > NS_ETH_MAX_LEN)) {
	 printf("Bad size! - %d\n", buf_size);
	 return ns_eth_bad_packet_size;
	 }
	 */

	/* output data */
	*payload_type = ntohs(eth_hdr->ns_eth_type);
	*payload_offset = (unsigned char *) (buf + NS_ETH_HDR_LEN);
	return ns_success;
}

static void modify_packet_to_reply(const unsigned char* local_mac,
        unsigned char *buf, unsigned char *dest_mac)
{
	ns_ethernet_frame_hdr_t *eth_hdr = (ns_ethernet_frame_hdr_t *) buf;

	DBG("--------------------------------------------------");
	dump_eth_packet(eth_hdr);

	memcpy(eth_hdr->ns_eth_dest, eth_hdr->ns_eth_src, NS_ETH_ADDR_LEN);
	memcpy(eth_hdr->ns_eth_src, local_mac, NS_ETH_ADDR_LEN);

	memcpy(dest_mac, eth_hdr->ns_eth_dest, NS_ETH_ADDR_LEN);

	DBG("--------------------------------------------------");
	dump_eth_packet(eth_hdr);
	DBG("--------------------------------------------------");
}

ns_error_t prepare_arp_spoof_response_buf_if_blacklisted(
        const unsigned char* local_mac, unsigned char *buf,
        unsigned char* dest_mac)
{
	ns_error_t response = ns_success;

	ns_ethernet_frame_hdr_t *eth_hdr = (ns_ethernet_frame_hdr_t *) buf;
	if (ntohs(eth_hdr->ns_eth_type) != NS_ETH_TYPE_ARP) {
		return ns_not_ethernet_arp_packet;
	}

	response = spoof_arp_response_if_blacklisted(local_mac,
	        (unsigned char *) (buf + NS_ETH_HDR_LEN));
	if ((response != ns_success)
	        && (response != ns_not_ipv4_arp_request_packet)) {
		ERR("Unable to spoof the ARP response packet: %d", response);
		return response;
	}

	if (response == ns_not_ipv4_arp_request_packet)
	        return ns_not_ipv4_arp_request_packet;

	modify_packet_to_reply(local_mac, buf, dest_mac);

	return ns_success;
}
