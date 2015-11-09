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
 *  Created on		: 06-Nov-2015
 *  Author		: rp
 *  Date			: 7:50:15 pm
 */

#include <string.h>
#include <netdb.h>
#include <sys/ioctl.h>			/* SIOCGIFHWADDR */
#include <net/if.h>				/* ifr */
#include <unistd.h>			/* close */

#include "ns_utils.h"
#include "ns_ethernet.h"
#include "ns_log.h"

void human_readable_MAC(const unsigned char* orig_mac, char* mac)
{
	bzero(mac, NS_ETH_IPv4_PRINTABLE_MAC_SIZE);
	snprintf(mac, NS_ETH_IPv4_PRINTABLE_MAC_SIZE,
	        "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", orig_mac[0], orig_mac[1],
	        orig_mac[2], orig_mac[3], orig_mac[4], orig_mac[5]);
}

void human_readable_IPv4(const unsigned char* orig_ip, char* ip)
{
	bzero(ip, NS_ETH_IPv4_PRINTABLE_IPv4_SIZE);
	snprintf(ip, NS_ETH_IPv4_PRINTABLE_IPv4_SIZE, "%d.%d.%d.%d", orig_ip[0],
	        orig_ip[1], orig_ip[2], orig_ip[3]);
}

ns_error_t get_ip_addr_from_name(const char* device_name,
        struct in_addr* in_addr)
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

ns_error_t get_MAC_from_device_name(const char* device_name, unsigned char *mac)
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

ns_error_t is_found(const unsigned char **list, char *mac)
{
	/* TODO: implement string search in an array */
	return ns_success;
}
