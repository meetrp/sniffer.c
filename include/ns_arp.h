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
 * ns_arp.h
 *
 *  Created on		: 06-Nov-2015
 *  Author		: rp
 *  Date			: 8:46:46 pm
 */

#ifndef NS_ARP_H_
#define NS_ARP_H_

#include <stdint.h>			/* uint16_t and likes */
#include <stddef.h>		/* NULL */

#include "ns_utils.h"
#include "ns_ethernet.h"	/* NS_ETH_.* */
#include "ns_error.h"		/* error states */

/************************************************************
 * ARP FRAME FORMAT
 *
 * 		6			6			2	    (var)		4		Bytes/Octets
 * 	-----------------------------------------------------------------
 * 	| destination	| source 		| ether	| payload	| CRC	|
 * 	| mac addr	| mac addr	| type	|		|		|
 * 	-----------------------------------------------------------------
 ************************************************************/

/*
 * Magic Constants as per the RFC
 */
#define NS_ARP_ETHERNET_TYPE		1		/* Ethernet 10/100Mbps */

/* ARP protocol opcodes. */
#define	NS_ARP_REQUEST				1		/* ARP request. */
#define	NS_ARP_REPLY				2		/* ARP reply. */

typedef struct _ns_arp_packet_hdr {
		uint16_t ns_arp_hw_type;
		uint16_t ns_arp_proto_type;
		uint8_t ns_arp_hw_addr_len;
		uint8_t ns_arp_proto_addr_len;
		uint16_t ns_arp_opcode;
} ns_arp_packet_hdr_t;

/* ToDo: Move to IPv4 based file */
#define NS_IPv4_ADDR_LEN					4
#define NS_ARP_TYPE_STR_LEN					8

/* IPv4 over Ethernet ARP payload */
typedef struct _ns_arp_IPv4_eth_payload {
		char ns_arp_sender_hw_addr[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
		char ns_arp_sender_proto_addr[NS_ETH_IPv4_PRINTABLE_IPv4_SIZE];
		char ns_arp_target_hw_addr[NS_ETH_IPv4_PRINTABLE_MAC_SIZE];
		char ns_arp_target_proto_addr[NS_ETH_IPv4_PRINTABLE_IPv4_SIZE];
} ns_arp_IPv4_eth_payload_t;

/* IPv4 over Ethernet ARP packet */
typedef struct _ns_arp_IPv4_eth_packet {
		ns_arp_packet_hdr_t ns_arp_hdr;

		/* addresses */
		unsigned char ns_arp_sender_hw_addr[NS_ETH_ADDR_LEN];
		unsigned char ns_arp_sender_proto_addr[NS_IPv4_ADDR_LEN];
		unsigned char ns_arp_target_hw_addr[NS_ETH_ADDR_LEN];
		unsigned char ns_arp_target_proto_addr[NS_IPv4_ADDR_LEN];
} ns_arp_IPv4_eth_packet_t;

ns_error_t parse_arp_packet(const unsigned char *);
ns_error_t spoof_arp_response_if_blacklisted(const unsigned char*,
        unsigned char*);

#endif /* NS_ARP_H_ */
