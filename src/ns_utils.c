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
 * ns_utils.c
 *
 *  Created on			: 03-Nov-2015
 *  Author				: rp
 *  Date					: 7:50:15 pm
 */

#include <string.h>					/* bzero */
#include <netdb.h>
#include <sys/ioctl.h>			/* SIOCGIFHWADDR */
#include <net/if.h>					/* ifr */
#include <unistd.h>				/* close */

#include "ns_utils.h"
#include "ns_ethernet.h"
#include "ns_log.h"

PUBLIC void human_readable_MAC(IN unsigned char* orig_mac, OUT char* mac)
{
	bzero(mac, NS_ETH_IPv4_PRINTABLE_MAC_SIZE);
	snprintf(mac, NS_ETH_IPv4_PRINTABLE_MAC_SIZE,
		"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", orig_mac[0], orig_mac[1], orig_mac[2],
		orig_mac[3], orig_mac[4], orig_mac[5]);
}

PUBLIC void human_readable_IPv4(IN unsigned char* orig_ip, OUT char* ip)
{
	bzero(ip, NS_ETH_IPv4_PRINTABLE_IPv4_SIZE);
	snprintf(ip, NS_ETH_IPv4_PRINTABLE_IPv4_SIZE, "%d.%d.%d.%d", orig_ip[0],
		orig_ip[1], orig_ip[2], orig_ip[3]);
}

PUBLIC char* human_readable_IPV4_from_number(IN uint32_t ip, char* ip_str)
{
	struct in_addr addr;
	addr.s_addr = ip;

	inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
	return ip_str;
}

PUBLIC ns_error_t get_ip_addr_from_name(IN char* device_name,
	OUT struct in_addr* in_addr)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	/* output */
	*in_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

	return ns_success;
}

PUBLIC ns_error_t get_MAC_from_device_name(IN char* device_name, OUT unsigned char *mac)
{
	struct ifreq interface_request;
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sock < 0) {
		ERR("Socket open failed!");
		return ns_socket_failed;
	}

	strcpy(interface_request.ifr_name, device_name);
	if (0 == ioctl(sock, SIOCGIFHWADDR, &interface_request)) {
		int i;
		for (i = 0; i < NS_ETH_ADDR_LEN; ++i)
		mac[i] = (unsigned char) interface_request.ifr_addr.sa_data[i];
		return ns_success;
	}

	return ns_ioctl_failed;
}
