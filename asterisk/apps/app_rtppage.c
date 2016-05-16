/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2007-2008, Andreas 'MacBrody' Brodmann
 *
 * Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
 *
 * Information on how multicast paging works with Linksys
 * phones was used from FreeSWITCH's mod_esf with permission
 * from Brian West.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*

RTPPage - An asterisk module by Netconf

What is it for
app_rtppage is an asterisk app that provides the functionality to rtp stream voice data from an asterisk server
 to ip phones without any prior signalling. This can be used with phones by Snom and Linksys as well as devices by Barix.

License
app_rtppage is released under the GNU General Public License.

Where to start?
Download app_rtppage.c (date: 2008-08-10) from this site, copy it into ${ASTERISK_SOURCE}/apps and compile asterisk as usual.

Usage in extensions.conf
Use either one:

exten => s,1,RTPPage(basic|224.168.168.168:1234|ulaw|ef)
exten => s,1,RTPPage(linksys|224.168.168.168:34567&224.168.168.168:6061|ulaw|ef)

http://www.netconf.ch/asterisk/

*/

/*! \file
 *
 * \brief Application to stream a channel's input to a specified uni-/multicast address
 *
 * \author Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
 *
 * \ingroup applications
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 40722 $")

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/lock.h"
#include "asterisk/app.h"
#include "asterisk/config.h"
#include "asterisk/acl.h"

#define RTP_PT_ULAW    0
#define RTP_PT_GSM     3
#define RTP_PT_ALAW    8
#define RTP_PT_G729   18

#define MAX_RTPBUF_LEN 2048

/*! \brief Multicast Group Receiver Type object */
enum grouptype {
	MGT_BASIC = 1,    /*!< simple multicast enabled client/receiver like Snom, Barix */
	MGT_LINKSYS = 2,  /*!< Linksys ipphones; they need a start/stop packet */
};

/*! \brief Multicast Group object */
struct mcast_dest {
	int socket;                           /*!< socket used for streaming to this group (each group has got its own socket */
	struct sockaddr_in rtp_address;       /*!< address/port pair where the traffic is sent to */
	struct sockaddr_in control_address;   /*!< address/port for Linksys phones to send the start/stop packet to */
};

/*! \brief RTP header object */
struct rtp_header {
	uint16_t flags;
	uint16_t seqno;
	uint32_t timestamp;
	uint32_t ssrc;
	char data[0];                          /*!< start of data */
};

/*! \brief Control Packet object as used for Linksys phones for start/stop packets */
struct control_packet {
	uint32_t unique_id;                    /*!< unique id per command start or stop - not the same for both commands */
	uint32_t command;                      /*!< the command: 6=start, 7=stop */
	uint32_t ip;                           /*!< multicast address in network byte order */
	uint32_t port;                         /*!< udp port to send the data to */
};

static char *app = "RTPPage";
static char *synopsis = "Reads the channel's input and streams RTP data to a specified unicast/multicast address/port";
static char *descrip = "  RTPPage(pagetype,ip:port[,codec][,tos_value][,ttl]): Sends the channel's input to the\n"
"specified destinations.\n"
"The optional codec may be one of the following:\n"
"   ulaw - default\n"
"   alaw\n"
"   gsm\n"
"   g729\n"
"as long as asterisk does not have to translate or respective translators are\n"
"installed with your asterisk installation. If none or any other codec is\n"
"specified the application will fall back to ulaw.\n\n"
"the tos_value parameter is meant to be specified exactly as in sip.conf (e.g. ef)\n";

/*! \brief Read input from channel and send it to the specified group(s) as rtp traffic */
static int rtppage_exec(struct ast_channel *chan, void *data)
{
	int res = 0;
	struct ast_module_user *u =  NULL;
	struct ast_frame *f = NULL;
	char *parse = NULL;
	char *cur = NULL, *cur2 = NULL;
	char *ip = NULL, *port = NULL;
	int ms = -1;
	struct rtp_header *rtpheader = NULL;
	struct mcast_dest destination;
	struct control_packet cpk;
	uint8_t rtp_pt = RTP_PT_ULAW;
	int chan_format = AST_FORMAT_ULAW;
	uint16_t rtpflags = 0;
	int ttl = -1;
	int pagetype = MGT_BASIC;
	unsigned int tos = -1;

	/* initialize destination structure */
	memset(&destination, 0, sizeof(struct mcast_dest));
	destination.socket = -1;

	/* you can specify three arguments:
	 * 1) destination (ip:port)
	 * 2) pagetype (basic, linksys)
	 * 3) optional: codec
	 *    this codec will be used for streaming
	 * 4) optional: tos value
	 * 5) optional: ttl value
	 */
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(pagetype);
		AST_APP_ARG(destination);
		AST_APP_ARG(codec);
		AST_APP_ARG(tos);
		AST_APP_ARG(ttl);
	);

	/* make sure there is at least one parameter */
	if (ast_strlen_zero(data)) {
		ast_log(LOG_ERROR, "%s requires argument (pagetype,destination[,codec][,tos][,ttl])\n", app);
		return -1;
	}

	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);

	/* pagetype is a mandatory parameter */
	if (args.pagetype) {
		if (!strcasecmp(args.pagetype, "basic")) {
			pagetype = MGT_BASIC;
		} else if (!strcasecmp(args.pagetype, "linksys")) {
			pagetype = MGT_LINKSYS;
		} else {
			ast_log(LOG_ERROR, "%s is an invalid / not yet implemented pagetype!\n", args.pagetype);
			return -1;
		}
	} else {
		ast_log(LOG_ERROR, "%s requires argument (pagetype,destination[,codec][,tos][,ttl])\n", app);
		return -1;
	}

	/* fill the destination structure */
	if (args.destination) {
		cur = strsep(&args.destination, "&");
		cur2 = strsep(&args.destination, "&");
		ip = strsep(&cur, ":");
		port = strsep(&cur, ":");
		if (ip == NULL || port == NULL) {
			ast_log(LOG_ERROR, "Missing ip or port in call to RTPPage\n");
			return -1;
		}
		destination.rtp_address.sin_family = AF_INET;
		destination.rtp_address.sin_port = htons(atoi(port));
		if (inet_pton(AF_INET, ip, &destination.rtp_address.sin_addr) <= 0) {
			ast_log(LOG_ERROR, "Invalid ip address in call to RTPPage(%s)!\n", ip);
			return -1;
		}

		if (pagetype == MGT_LINKSYS) {
			if (cur2 == NULL) {
				ast_log(LOG_ERROR, "Missing control_address in call to RTPPage with Pagetype=Linksys!\n");
				return -1;
			}
			ip = strsep(&cur2, ":");
			port = strsep(&cur2, ":");
			if (ip == NULL || port == NULL) {
				ast_log(LOG_ERROR, "Missing ip or port in control_address in '%s:%s'!\n", ip, port);
				return -1;
			}
			destination.control_address.sin_family = AF_INET;
			destination.control_address.sin_port = htons(atoi(port));
			if (inet_pton(AF_INET, ip, &destination.control_address.sin_addr) <= 0) {
				ast_log(LOG_ERROR, "Invalid ip for control_address in call to RTPPage(%s)!\n", ip);
				return -1;
			}
		}
	} else {
		ast_log(LOG_ERROR, "%s needs arguments (pagetype,destination[,codec][,tos][,ttl])!\n", app);
		return -1;
	}

	/* setup tos if set by user */
	if (args.tos) {
		ast_str2tos(args.tos, &tos);
	}

	/* setup ttl if set by user */
	if (args.ttl) {
		ttl = atoi(args.ttl);
	}

	/* init our own comm socket */
	destination.socket = socket(AF_INET, SOCK_DGRAM, 0);

	/* set ttl if set by user */
	if (ttl > 0) {
		if (setsockopt(destination.socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
			ast_log(LOG_WARNING, "Failed to set TTL in call to RTPPage()\n");
		}
	}

	/* set tos if set by user */
	if (tos > 0) {
		if (setsockopt(destination.socket, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
			ast_log(LOG_WARNING, "Failed to set TOS field in call to RTPPage()\n");
		}
	}

	/* setup variables for the desired codec */
	if (args.codec) {
		if (!strcasecmp(args.codec, "ulaw")) {
			rtp_pt = RTP_PT_ULAW;
			chan_format = AST_FORMAT_ULAW;
		} else if (!strcasecmp(args.codec, "alaw")) {
			rtp_pt = RTP_PT_ALAW;
			chan_format = AST_FORMAT_ALAW;
		} else if (!strcasecmp(args.codec, "gsm")) {
			rtp_pt = RTP_PT_GSM;
			chan_format = AST_FORMAT_GSM;
		} else if (!strcasecmp(args.codec, "g729")) {
			rtp_pt = RTP_PT_G729;
			chan_format = AST_FORMAT_G729A;
		} else {
			ast_log(LOG_ERROR, "Specified not implemented/supported codec %s!\n", args.codec);
			return -1;
		}
	}

	u = ast_module_user_add(chan);

	/* Check if the channel is answered, if not
	 * do answer it */
	if (chan->_state != AST_STATE_UP) {
		res = ast_answer(chan);
		if (res) {
			ast_log(LOG_ERROR, "Could not answer channel '%s'\n", chan->name);
			goto end;
		}
	}

	/* allocate memory for the rtp send buffer */
	if ((rtpheader = (struct rtp_header *)ast_calloc(1, MAX_RTPBUF_LEN)) == NULL) {
		ast_log(LOG_ERROR, "Failed to allocate memory for the rtpheader and payload, give up\n");
		goto end;
	}

	/* initialize rtp buffer header
	 * with rtp version and
	 * payload type
	 */
	rtpflags = (0x02 << 14); /* rtp v2 */
	rtpflags = (rtpflags & 0xFF80) | rtp_pt;  
	rtpheader->flags = htons(rtpflags);
	rtpheader->ssrc =  htonl((u_long)time(NULL));

	/* init the stream if it is supposed to be for Linksys phones */
	if (pagetype == MGT_LINKSYS) {
		cpk.unique_id = htonl((u_long)time(NULL));
		cpk.command = htonl(6);    /* multicast start command */
		memcpy(&cpk.ip, &destination.rtp_address.sin_addr, sizeof(cpk.ip));
		cpk.port = htonl(ntohs(destination.rtp_address.sin_port));
		/* sending the following packet twice was a recommendation of Brian West who did the FreeSWITCH implementation of the multicast paging */
		sendto(destination.socket, &cpk, sizeof(cpk), 0, (struct sockaddr *)&destination.control_address, sizeof(destination.control_address));
		sendto(destination.socket, &cpk, sizeof(cpk), 0, (struct sockaddr *)&destination.control_address, sizeof(destination.control_address));
	}

	/* Set read format as configured - this codec will be used for streaming */
	res = ast_set_read_format(chan, chan_format);
	if (res < 0) {
		ast_log(LOG_WARNING, "Unable to set channel read mode, giving up\n");
		res = -1;
		goto end;
	}

	/* Play a beep to let the caller know he can start talking */
	res = ast_streamfile(chan, "beep", chan->language);
	if (!res) {
		res = ast_waitstream(chan, "");
	} else {
		ast_log(LOG_WARNING, "ast_streamfile failed on %s\n", chan->name);
	}
	ast_stopstream(chan);

	/* main loop: 
	 * read frames from the input channel and, if they are voice frames,
	 * send them to all requested multi-/unicast listeners.
	 */
	for (;;) {
		ms = ast_waitfor(chan, 1000);
		if (ms < 0) {
			ast_log(LOG_DEBUG, "Hangup detected\n");
			goto end;
		}
		f = ast_read(chan);
		if (!f)
			break;

		/* if the speaker pressed '#', then quit */
		if ((f->frametype == AST_FRAME_DTMF) && (f->subclass == '#')) {
			res = 0;
			ast_log(LOG_DEBUG, "Received DTMF key: #\n");
			ast_frfree(f);
			goto end;
		}

		if (f->frametype == AST_FRAME_VOICE) {
			/* update the rtp header */
			rtpheader->seqno = htons(f->seqno);
			rtpheader->timestamp = htonl(f->ts * 8);
			if (f->datalen+12 > MAX_RTPBUF_LEN) {
				ast_log(LOG_ERROR, "Received oversized voice packet from channel!\n");
				ast_frfree(f);
				goto end;
			} else {
				memcpy(&rtpheader->data[0], f->data, f->datalen);
			}

			sendto(destination.socket, rtpheader, f->datalen+12, 0, (struct sockaddr *)&destination.rtp_address, sizeof(destination.rtp_address));
		}
		ast_frfree(f);
		f = NULL;
	}

end:

	/* send a multicast stop command in case it was a Linksys type page */
	if (pagetype == MGT_LINKSYS) {
		cpk.unique_id = htonl((u_long)time(NULL));
		cpk.command = htonl(7); /* multicast stop command */
		memcpy(&cpk.ip, &destination.rtp_address.sin_addr, sizeof(cpk.ip));
		cpk.port = htonl(ntohs(destination.rtp_address.sin_port));
		/* sending the following packet twice was a recommendation of Brian West who did the FreeSWITCH implementation of the multicast paging */
		sendto(destination.socket, &cpk, 8, 0, (struct sockaddr *)&destination.control_address, sizeof(destination.control_address));
		sendto(destination.socket, &cpk, 8, 0, (struct sockaddr *)&destination.control_address, sizeof(destination.control_address));
	}

	/* free the rtp data buffer */
	if (rtpheader != NULL) {
		free(rtpheader);
	}

	ast_module_user_remove(u);

	return res;
}

static int unload_module(void)
{
	int res;
	res = ast_unregister_application(app);
	ast_module_user_hangup_all();
	return res;	
}

static int load_module(void)
{
	return ast_register_application(app, rtppage_exec, synopsis, descrip);
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "RTP Multicast Paging");

