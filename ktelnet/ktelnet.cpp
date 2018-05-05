// ktelnet.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <winsock2.h>

#include <stdio.h>
#include <stdlib.h>

#define ICMP_ECHO		8	/* Echo Request			*/

typedef unsigned char   __u8 ;
typedef unsigned short  __sum16;
typedef unsigned short  __be16;
typedef unsigned short  __u16;
typedef unsigned int    __be32;
typedef unsigned int    __u32;

struct iphdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__u16	tot_len;
	__u16	id;
	__u16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__u16	check;
	__u32	saddr;
	__u32	daddr;
	/*The options start here. */
};

struct icmphdr {
  __u8		type;
  __u8		code;
  __u16		checksum;
  union {
	struct {
		__u16	id;
		__u16	sequence;
	} echo;
	__u32	gateway;
	struct {
		__u16	__unused;
		__u16	mtu;
	} frag;
  } un;
};

struct sockaddr whereto;

static int in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

int pinger(SOCKET s, char *buff, int size)
{
	static int  ntransmitted = 0;
	struct icmphdr *icp;
	int i;

	icp = (struct icmphdr *)buff;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.id = 0x400;			/* ID */
	icp->un.echo.sequence = (ntransmitted++);

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((u_short *)icp, size);

	i = sendto(s, (char *)buff, size, 0, &whereto, sizeof(struct sockaddr));

	if (i < 0 || i != size)
    {
        perror("ping: sendto ");
		printf("ping: wrote %d bytes, ret=%d\n", size, i);
		return -1;
	}

	return 0;
}

char *pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	register struct icmphdr *icp;
	struct iphdr *ip;
	long triptime = 0;
	int hlen;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	hlen = ip->ihl << 2;

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);

	buf += hlen + sizeof(struct icmphdr);

	return buf;
}

void usage(void)
{
	printf("Usage: \n");
	printf("\tktelnet [IP address]\n");

	exit(1);
}

#define ICMP_PAYLOAD_SIZE 1200
#define ICMP_HEAD_SIZE 8

int main(int argc, char *argv[])
{
	struct sockaddr_in *to;
    struct sockaddr_in from;
    int fromlen, cc;
	fd_set fdmask;
    struct timeval timeout;

	char outpack[1600];
	char inpack[1600];
	int  datalen = 1200 -8;

	char *payload;
	char cmd[32];
	int c, ret, i;

	WSADATA wsd;

	SOCKET s;	

	/* must provide ip address */
	if (argc < 2)
		usage();

	/* init windows socket libarary */
	if (WSAStartup(MAKEWORD(2,2), &wsd)!=0)
		printf("fail\n");

    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("ping: socket fail");
        return -1;
    }

    to = (struct sockaddr_in *)&whereto;
    to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(argv[1]);

	/* send the first icmp message for prompt */
	/* Basic ktelnet data struction */ /* ygx */
	/*
	*     ktelnet head struction placed in icmp payload
	*
	*     0                    15                     31
	*     ++++++++++++++++++++++++++++++++++++++++++++++
	*     +   mark              +        length        +
	*     ++++++++++++++++++++++++++++++++++++++++++++++
	*     +                  command                   +
	*     +                                            +
	*     ++++++++++++++++++++++++++++++++++++++++++++++
	*     mark is "zt" in request.
	*     mark is "tz" in response.
	*/
	payload    = outpack + sizeof(struct icmphdr);
	payload[0] = 'z';
	payload[1] = 't';
	*((short *)(payload+2)) = htons(1); /* 1 is length */
	payload[4] = '\n';                  /* command */

	ret = pinger(s, outpack, ICMP_PAYLOAD_SIZE + ICMP_HEAD_SIZE);
	if (ret == -1){
		perror("main: pinger fail\n");
		exit(1);
	}

	for (;;)
	{
		timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
		FD_ZERO(&fdmask);
		FD_SET(s, &fdmask);

        if (select(s + 1, &fdmask, NULL, NULL, &timeout) < 1){
			continue;
        }

		memset(inpack, 0, sizeof(inpack));
        fromlen = sizeof(from);
        if ((cc = recvfrom(s, (char *)inpack, sizeof(inpack), 0, (struct sockaddr *)&from, &fromlen)) < 0)
        {
    		printf("b %s\n", strerror(errno));
			exit(0);
        }

		/* get payload and check */
		payload = pr_pack(inpack, cc, &from);
		if (payload[0] != 't' || payload[1] != 'z')
			continue;

		printf("%s", payload+4); /* print response */

		i = 0;
		memset(cmd, 0, sizeof(cmd));
		c=getchar();
		cmd[i++] = c;
		while ( c != '\n' && (i < (sizeof(cmd)-1)))
		{
			c = getchar();
			cmd[i++] = c;
		}

		/* clean input buffer */
		if (i >= (sizeof(cmd)-1))
		{
			while((c=getchar())!= '\n');
		}
		
		/* exit is a location command */
		if (strcmp(cmd, "exit\n") == 0)
			exit(0);

		/* send command by icmp */
		memset(outpack, 0, sizeof(outpack));
		payload = outpack + sizeof(struct icmphdr);
		payload[0] = 'z';
		payload[1] = 't';
		*((short *)(payload+2)) = htons(strlen(cmd));
		strcpy(&payload[4], cmd);

		ret = pinger(s, outpack, ICMP_PAYLOAD_SIZE + ICMP_HEAD_SIZE);
		if (ret == -1)
		{
			perror("main: pinger fail\n");
			exit(1);
		}
	}

	return 0;
}

