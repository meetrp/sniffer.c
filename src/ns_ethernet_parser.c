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
 *  Created on			: 03-Nov-2015
 *  Author				: rp
 *  Date					: 1:07:00 am
 */

#include <netinet/in.h>
#include <string.h>

#include "ns_ethernet.h"
#include "ns_log.h"
#include "ns_utils.h"
#include "ns_arp.h"
#include "ns_config.h"

PRIVATE void convert_eth_type(IN uint16_t type, OUT char *eth_type)
{
	switch (type) {
		case NS_ETH_TYPE_IPv4:
		snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN, "IPv4");
		break;
		case NS_ETH_TYPE_IPv6:
		snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN, "IPv6");
		break;
		case NS_ETH_TYPE_ARP:
		snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN, "ARP");
		break;
		default:
		snprintf((char *) eth_type, NS_ETH_TYPE_STR_LEN, "0x%x", type);
		break;
	}
}

PRIVATE void dump_eth_packet(IN ns_ethernet_frame_hdr_t *eth_hdr)
{
	char dest_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char src_mac[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
	char eth_type[NS_ETH_TYPE_STR_LEN];

	convert_eth_type(ntohs(eth_hdr->ns_eth_type), eth_type);
	human_readable_MAC(eth_hdr->ns_eth_src, src_mac);
	human_readable_MAC(eth_hdr->ns_eth_dest, dest_mac);

	//DBG("[%4s] <%4s> [%s] --> [%s]", "ETH", eth_type, src_mac, dest_mac);
}

PUBLIC ns_error_t parse_ethernet_packet(IN unsigned char *buf,
	IN int buf_size, OUT unsigned char** payload_offset, OUT uint16_t* payload_type)
{
	ns_ethernet_frame_hdr_t *eth_hdr = NULL;

	if (NULL == buf) {
		ERR("buf is NULL!");
		return ns_eth_empty_packet;
	}

	eth_hdr = (ns_ethernet_frame_hdr_t *) buf;
	dump_eth_packet(eth_hdr);

#if NOT_WORKING
	if ((buf_size < NS_ETH_MIN_LEN) || (buf_size > NS_ETH_MAX_LEN)) {
		printf("Bad size! - %d\n", buf_size);
		return ns_eth_bad_packet_size;
	}
#endif

	/* output data */
	*payload_type = ntohs(eth_hdr->ns_eth_type);
	*payload_offset = (unsigned char *) (buf + NS_ETH_HDR_LEN);
	return ns_success;
}
