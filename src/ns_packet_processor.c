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
 * ns_packet_processor.c
 *
 *  Created on		: 03-Nov-2015
 *  Author		: rp
 *  Date			: 1:29:38 am
 */

#include <stddef.h>			/* NULL */

#include "ns_log.h"
#include "ns_error.h"
#include "ns_ethernet.h"		/* ethernet packet related fns */
#include "ns_arp.h"			/* ARP packet related fns */

void process_packet(const unsigned char *buf, const int buf_size)
{
	unsigned char *eth_payload = NULL;
	uint16_t eth_payload_type;

	if (ns_success
	        != parse_ethernet_packet(buf, buf_size, &eth_payload,
	                &eth_payload_type)) {
		ERR("Error while parsing ethernet packet!\n");
		return;
	}

	//printf("about to check ARP: 0x%X\n", eth_payload_type);
	if ((eth_payload_type == NS_ETH_TYPE_ARP)
	        && (ns_success != parse_arp_packet(eth_payload))) {
		ERR("Error while parsing ARP packet!\n");
		return;
	}
}
