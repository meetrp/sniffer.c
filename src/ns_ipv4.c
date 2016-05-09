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
 *ns_ipv4.h
 *
 *  Created on			: 05-May-2016
 *  Author				: rp
 *  Date					: 3:26:29 pm
 */

#include <stdint.h>						/* uint16_t and likes */
#include <string.h>						/* memset */
#include <ctype.h>						/* isprint */
#include <stdlib.h>						/* free */

#include "ns_log.h"
#include "ns_error.h"
#include "ns_ipv4.h"
#include "ns_utils.h"

PRIVATE void convert_ipv4_type(IN uint8_t opcode, OUT char *ipv4_type)
{
	switch (opcode) {
		case NS_IPv4_ICMP_PROTO:
		snprintf((char*) ipv4_type, NS_IPv4_TYPE_STR_LEN, "ICMP");
		break;
		case NS_IPv4_IGMP_PROTO:
		snprintf((char*) ipv4_type, NS_IPv4_TYPE_STR_LEN, "IGMP");
		break;
		case NS_IPv4_TCP_PROTO:
		snprintf((char*) ipv4_type, NS_IPv4_TYPE_STR_LEN, "TCP");
		break;
		case NS_IPv4_UDP_PROTO:
		snprintf((char*) ipv4_type, NS_IPv4_TYPE_STR_LEN, "UDP");
		break;
		default:
		snprintf((char*) ipv4_type, NS_IPv4_TYPE_STR_LEN, "%d ??", opcode);
		break;
	}
}

PRIVATE char* dump_ipv4_packet_data(IN unsigned char* data, IN unsigned int len)
{
	char *disp_str = NULL;
	char* _tmp = NULL;
	int i = 0;

	for (i = 0; i < len; i++) {
		if (isprint(data[i])) {
			if (_tmp) {
				asprintf(&disp_str, "%s%c", _tmp, data[i]);
			}
			else {
				asprintf(&disp_str, "%c", data[i]);
			}
		}
		else {
			if (_tmp) {
				asprintf(&disp_str, "%s.", _tmp);
			}
			else {
				asprintf(&disp_str, ".");
			}
		}

		free(_tmp);
		_tmp = disp_str;
	}

	return disp_str;
}

PRIVATE char* dump_ipv4_packet_hdr(IN ns_IPv4_packet_t* hdr)
{
	char ipv4_type[NS_IPv4_TYPE_STR_LEN];
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	char *disp_str = NULL;

	convert_ipv4_type(hdr->ns_ipv4_proto, ipv4_type);
	human_readable_IPV4_from_number(hdr->ns_ipv4_src, src_ip);
	human_readable_IPV4_from_number(hdr->ns_ipv4_dest, dest_ip);
	asprintf(&disp_str, "[%4s] (%5s) %s --> %s", "IPv4", ipv4_type, src_ip,
		dest_ip);

	return disp_str;
}

PUBLIC ns_error_t parse_ipv4_packet(IN unsigned char *packet)
{
	ns_IPv4_packet_t *ip_hdr = (ns_IPv4_packet_t*) packet;
	unsigned char* data = ((void*) packet
		+ (ip_hdr->ns_ipv4_hdr_len * sizeof(uint32_t)));
	char* parsed_hdr = NULL;
	char* parsed_data = NULL;
	char *disp_str = NULL;

	parsed_hdr = dump_ipv4_packet_hdr(ip_hdr);
	parsed_data = dump_ipv4_packet_data(data,
		ntohs(ip_hdr->ns_ipv4_len)
		- (ip_hdr->ns_ipv4_hdr_len & sizeof(uint32_t)));

	asprintf(&disp_str, "%s %s", parsed_hdr, parsed_data);
	free(parsed_hdr);
	free(parsed_data);
	DBG(disp_str);

	return ns_success;
}
