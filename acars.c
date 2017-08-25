/*
 *  dumpvdl2 - a VDL Mode 2 message decoder and protocol analyzer
 *
 *  Copyright (c) 2017 Tomasz Lemiech <szpajder@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "dumpvdl2.h"
#include "acars.h"

#define ETX 0x83
#define ETB 0x97
#define DEL 0x7f

/*
 * ACARS message decoder
 * Based on acarsdec by Thierry Leconte
 */
acars_msg_t *parse_acars(uint8_t *buf, uint32_t len, uint32_t *msg_type) {
	static acars_msg_t *msg = NULL;
	int i;

	if(len < MIN_ACARS_LEN) {
		debug_print("too short: %u < %u\n", len, MIN_ACARS_LEN);
		return NULL;
	}

	if(buf[len-1] != DEL) {
		debug_print("%02x: no DEL byte at end\n", buf[len-1]);
		return NULL;
	}
	if(buf[len-4] != ETX && buf[len-4] != ETB) {
		debug_print("%02x: no ETX/ETB byte at end\n", buf[len-4]);
		return NULL;
	}
	len -= 4;
	if(msg == NULL)
		msg = XCALLOC(1, sizeof(acars_msg_t));
	else
		memset(msg, 0, sizeof(acars_msg_t));

	// safe default
	*msg_type |= MSGFLT_ACARS_NODATA;
	for(i = 0; i < len; i++)
		buf[i] &= 0x7f;

	uint32_t k = 0;
	msg->mode = buf[k++];

	for (i = 0; i < 7; i++, k++) {
		msg->reg[i] = buf[k];
	}
	msg->reg[7] = '\0';

	/* ACK/NAK */
	msg->ack = buf[k++];
	if (msg->ack == 0x15)
		msg->ack = '!';

	msg->label[0] = buf[k++];
	msg->label[1] = buf[k++];
	if (msg->label[1] == 0x7f)
		msg->label[1] = 'd';
	msg->label[2] = '\0';

	msg->bid = buf[k++];
	if (msg->bid == 0)
		msg->bid = ' ';

	/* txt start  */
	msg->bs = buf[k++] & 0x7f;
	msg->be = buf[len] & 0x7f;

	msg->txt[0] = '\0';

	if(k >= len) {		// empty txt
		return msg;
	}

	if (msg->bs != 0x03) {
		/* Message txt */
		len -= k;
		if(len > ACARSMSG_BUFSIZE) {
			debug_print("message truncated to buffer size (%u > %u)", len, ACARSMSG_BUFSIZE);
			len = ACARSMSG_BUFSIZE - 1;		// leave space for terminating '\0'
		}
		if(len > 0) {
			memcpy(msg->txt, buf + k, len);
			*msg_type |= MSGFLT_ACARS_DATA;
			*msg_type &= ~MSGFLT_ACARS_NODATA;
		}
		msg->txt[len] = '\0';
	}
	/* txt end */
	return msg;
}

void output_acars_pp(const acars_msg_t *msg) {
	char pkt[ACARSMSG_BUFSIZE+32];
	char txt[ACARSMSG_BUFSIZE];

	strcpy(txt, msg->txt);
	for(char *ptr = txt; *ptr != 0; ptr++)
		if (*ptr == '\n' || *ptr == '\r')
			*ptr = ' ';

	sprintf(pkt, "AC%1c %7s %1c %2s %1c %4s %6s %s",
		msg->mode, msg->reg, msg->ack, msg->label, msg->bid, "", "", txt);

	if(write(pp_sockfd, pkt, strlen(pkt)) < 0)
		debug_print("write(pp_sockfd) error: %s", strerror(errno));
}

#define STATION_ID_LENGTH 8

typedef struct _acars_udp_message_header_t acars_udp_message_header_t;
struct _acars_udp_message_header_t {
    char station_id[STATION_ID_LENGTH];
    unsigned int fc;
    unsigned int timestamp;
};

typedef struct _acars_udp_message_t acars_udp_message_t;
struct _acars_udp_message_t {
    acars_udp_message_header_t header;
    char payload[ACARSMSG_BUFSIZE + 16];
};

void output_acars_nc(const acars_msg_t *msg, uint32_t freq) {
	acars_udp_message_t pkt;
	size_t txt_len = 0;
	size_t pkt_len;

	memset(&pkt, 0, sizeof(pkt));

	strncpy(&pkt.header.station_id[0], station_id, STATION_ID_LENGTH);
	pkt.header.timestamp = htonl(time(NULL));
	pkt.header.fc = htonl(freq);

	pkt.payload[0] = msg->mode;
	memcpy(&pkt.payload[1], msg->reg, 7);
	pkt.payload[8] = msg->ack == '!' ? 0x15 : msg->ack;
	pkt.payload[9] = msg->label[0];
	pkt.payload[10] = msg->label[1];
	if (msg->label[1] == 'd')
		pkt.payload[10] = 0x7f;
	pkt.payload[11] = msg->bid;
	pkt.payload[12] = msg->bs;
	if (msg->bs == 0x02) {
		txt_len = strlen(msg->txt);
		strcpy(&pkt.payload[13], msg->txt);
		pkt.payload[13 + txt_len] = msg->be;
		pkt_len = sizeof(pkt.header) + 13 + txt_len + 1;
	} else {
		pkt_len = sizeof(pkt.header) + 13;
	}

	if(write(nc_sockfd, &pkt, pkt_len) < 0)
		debug_print("write(pp_sockfd) error: %s", strerror(errno));
}

void output_acars(const acars_msg_t *msg, uint32_t freq) {
	fprintf(outf, "ACARS:\n");
	if(msg->mode < 0x5d)
		fprintf(outf, "Reg: %s\n", msg->reg);
	fprintf(outf, "Mode: %1c Label: %s Blk id: %c Ack: %c\n",
		msg->mode, msg->label, msg->bid, msg->ack);
	fprintf(outf, "Message:\n%s\n", msg->txt);
	if(pp_sockfd > 0)
		output_acars_pp(msg);
	if(nc_sockfd > 0)
		output_acars_nc(msg, freq);
}
