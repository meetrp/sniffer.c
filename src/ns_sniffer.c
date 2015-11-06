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
#include <netinet/if_ether.h>	/* ETH_P_ALL */
#include <arpa/inet.h>			/* htons */
#include <unistd.h>			/* close */

#include "ns_sniffer.h"			/* includes standard header */

#include "ns_packet_processor.h"
#include "ns_config.h"

ns_error_t sniffer()
{
	int raw_sock = -1;

	unsigned char *buf;
	struct sockaddr saddr;
	socklen_t saddr_size;

	int data_size;

	raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_sock < 0) {
		ERR("Socket Error!");
		return ns_socket_failed;
	}

	buf = (unsigned char*) malloc(DEFAULT_BUF_SIZE);
	if (NULL == buf) {
		ERR("No mem!");
		close(raw_sock);
		return ns_malloc_failed;
	}

	while (1) {
		saddr_size = sizeof(saddr);
		if ((data_size = recvfrom(raw_sock, buf, DEFAULT_BUF_SIZE, 0,
		        &saddr, &saddr_size)) < 0) {
			ERR("No data!");
			free(buf);
			close(raw_sock);
			return ns_recvfrom_received_no_data;
		}

		process_packet(buf, data_size);
	}

	return ns_success;
}
