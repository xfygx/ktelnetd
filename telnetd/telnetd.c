/*
 * Copyright (c) 1983, 1986 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983, 1986 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
 static char sccsid[] = "@(#)telnetd.c   5.31 (Berkeley) 2/23/89";
#endif /* not lint */

/*
 * Telnet server.
 */
#include "sys_defs.h"
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/types.h>

#include <netinet/in.h>

#include <arpa/telnet.h>

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <termios.h>
#include <netdb.h>
#ifdef linux
#include <sys/varargs.h>
#endif
#include <syslog.h>
#include <ctype.h>

#include <unistd.h>

#ifdef linux
/*include nothing by tby :p */
#else
#include <stdlib.h>
#endif


#ifdef STREAM_PTY
#include <sys/stropts.h>
#include "../lib/tiocpkt.h"
extern	char	*ptsname();
#define PTY_PKT_READ	pty_pkt_read
#else
#define PTY_PKT_READ	read
#endif

#ifndef O_RDWR
#include <sys/fcntl.h>
#endif

#ifndef FIONBIO
#include <sys/filio.h>
#endif

#ifndef FIONBIO
#include <sys/ioctl.h>
#endif

#if !defined(STREAM_PTY) && !defined(TIOCPKT)
#include <sys/pty.h>
#endif

#include <string.h>
#define index		strchr
#define rindex		strrchr
#define bcopy(s,d,l)	memcpy(d,s,l)

#ifdef __STDC__
#define puts		xputs		/* prototype conflict */
#else
# ifdef __linux
#define puts		xputs		/* prototype conflict */
# endif
#endif

/* Ultrix syslog(3) has no facility stuff. */
#ifndef LOG_DAEMON
#define LOG_DAEMON	0
#define LOG_ODELAY	0
#endif

#ifdef ultrix
#define setsid()	setpgrp(0,0)
#endif

#ifndef _PATH_LOGIN
#define _PATH_LOGIN "/bin/login"
/*
#define _PATH_LOGIN "/bin/bash"
*/
#endif

#define	OPT_NO			0		/* won't do this option */
#define	OPT_YES			1		/* will do this option */
#define	OPT_YES_BUT_ALWAYS_LOOK	2
#define	OPT_NO_BUT_ALWAYS_LOOK	3
char	hisopts[256];
char	myopts[256];

char	doopt[] = { IAC, DO, '%', 'c', 0 };
char	dont[] = { IAC, DONT, '%', 'c', 0 };
char	will[] = { IAC, WILL, '%', 'c', 0 };
char	wont[] = { IAC, WONT, '%', 'c', 0 };

/*
 * I/O data buffers, pointers, and counters.
 */

char shen_buf[80];

char	ptyibuf[BUFSIZ], *ptyip = ptyibuf;

char	ptyobuf[BUFSIZ], *pfrontp = ptyobuf, *pbackp = ptyobuf;

char	netibuf[BUFSIZ], *netip = netibuf;
#define	NIACCUM(c)	{   *netip++ = c; \
			    ncc++; \
			}

char	netobuf[BUFSIZ], *nfrontp = netobuf, *nbackp = netobuf;
char	*neturg = 0;		/* one past last bye of urgent data */
	/* the remote system seems to NOT be an old 4.2 */
int	not42 = 1;

#ifdef SUNOS5
#define	BANNER	"UNIX(r) System V Release 4.0"
#endif

#ifdef LINUX
#define	BANNER	"Linux UNIX"
#endif

#ifdef ultrix
#define	BANNER  "ULTRIX V4.2A (Rev. 47)"
#endif

#ifdef HPUX	/* uname -s hostname uname -r uname -v uname -m (tty) */
#define	BANNER  "HP-UX"
#endif

#ifndef BANNER
#define	BANNER	"4.3 BSD UNIX"
#endif



		/* buffer for sub-options */
char	subbuffer[100], *subpointer= subbuffer, *subend= subbuffer;
#define	SB_CLEAR()	subpointer = subbuffer;
#define	SB_TERM()	{ subend = subpointer; SB_CLEAR(); }
#define	SB_ACCUM(c)	if (subpointer < (subbuffer+sizeof subbuffer)) { \
				*subpointer++ = (c); \
			}
#define	SB_GET()	((*subpointer++)&0xff)
#define	SB_EOF()	(subpointer >= subend)

int	pcc, ncc;

int	pty, net;
#ifdef STREAM_PTY
int	pts;
#endif
int	inter;
#ifndef SYSV_ENV
extern	char **environ;
#endif
extern	int errno;
char	*line;
int	SYNCHing = 0;		/* we are in TELNET SYNCH mode */

/*
 * The following are some clocks used to decide how to interpret
 * the relationship between various variables.
 */

struct {
    int
	system,			/* what the current time is */
	echotoggle,		/* last time user entered echo character */
	modenegotiated,		/* last time operating mode negotiated */
	didnetreceive,		/* last time we read data from network */
	ttypeopt,		/* ttype will/won't received */
	ttypesubopt,		/* ttype subopt is received */
	getterminal,		/* time started to get terminal information */
	gotDM;			/* when did we last see a data mark */
} clocks;

#define	settimer(x)	(clocks.x = ++clocks.system)
#define	sequenceIs(x,y)	(clocks.x < clocks.y)

#ifndef DEBUG
#  define DEBUG
#endif
#ifndef STANDALONE
#  define STANDALONE
#endif

 /*
  * rfc931() speaks a common subset of the RFC 931, AUTH, TAP, IDENT and RFC
  * 1413 protocols. It queries an RFC 931 etc. compatible daemon on a remote
  * host to look up the owner of a connection. The information should not be
  * used for authentication purposes. This routine intercepts alarm signals.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#include <setjmp.h>

#define STRN_CPY(d,s,l)	{ strncpy((d),(s),(l)); (d)[(l)-1] = 0; }
#define STRING_LENGTH    60
#define RFC931_TIMEOUT	 1
#define	RFC931_PORT	113		/* Semi-well-known port */
#define	ANY_PORT	0		/* Any old port will do */

static jmp_buf timebuf;

/* fsocket - open stdio stream on top of socket */

static FILE *fsocket(domain, type, protocol)
int     domain;
int     type;
int     protocol;
{
    int     s;
    FILE   *fp;

    if ((s = socket(domain, type, protocol)) < 0) {
	perror("telnetd: socket in rfc931");
	return (0);
    } else {
	if ((fp = fdopen(s, "r+")) == 0) {
	    perror("telnetd:fdopen");
	    close(s);
	}
	return (fp);
    }
}

/* timeout - handle timeouts */

static void timeout(sig)
int     sig;
{
    longjmp(timebuf, sig);
}

void    rfc931(rmt_sin, our_sin, dest)
struct sockaddr_in *rmt_sin;
struct sockaddr_in *our_sin;
char   *dest;
{
    unsigned rmt_port;
    unsigned our_port;
    struct sockaddr_in rmt_query_sin;
    struct sockaddr_in our_query_sin;
    char    user[256];			/* XXX */
    char    buffer[512];		/* XXX */
    char   *cp;
    FILE   *fp;
    char   *result = "unknown";

    /*
     * Use one unbuffered stdio stream for writing to and for reading from
     * the RFC931 etc. server. This is done because of a bug in the SunOS
     * 4.1.x stdio library. The bug may live in other stdio implementations,
     * too. When we use a single, buffered, bidirectional stdio stream ("r+"
     * or "w+" mode) we read our own output. Such behaviour would make sense
     * with resources that support random-access operations, but not with
     * sockets.
     */
    if ((fp = fsocket(AF_INET, SOCK_STREAM, 0)) != 0) {
	setbuf(fp, (char *) 0);

	/*
	 * Set up a timer so we won't get stuck while waiting for the server.
	 */

	if (setjmp(timebuf) == 0) {
	    signal(SIGALRM, timeout);
	    alarm(RFC931_TIMEOUT);

	    /*
	     * Bind the local and remote ends of the query socket to the same
	     * IP addresses as the connection under investigation. We go
	     * through all this trouble because the local or remote system
	     * might have more than one network address. The RFC931 etc.
	     * client sends only port numbers; the server takes the IP
	     * addresses from the query socket.
	     */

	    our_query_sin = *our_sin;
	    our_query_sin.sin_port = htons(ANY_PORT);
	    rmt_query_sin = *rmt_sin;
	    rmt_query_sin.sin_port = htons(RFC931_PORT);

	    if (bind(fileno(fp), (struct sockaddr *) & our_query_sin,
		     sizeof(our_query_sin)) >= 0 &&
		connect(fileno(fp), (struct sockaddr *) & rmt_query_sin,
			sizeof(rmt_query_sin)) >= 0) {

		/*
		 * Send query to server. Neglect the risk that a 13-byte
		 * write would have to be fragmented by the local system and
		 * cause trouble with buggy System V stdio libraries.
		 */

		fprintf(fp, "%u,%u\r\n",
			ntohs(rmt_sin->sin_port),
			ntohs(our_sin->sin_port));
		fflush(fp);

		/*
		 * Read response from server. Use fgets()/sscanf() so we can
		 * work around System V stdio libraries that incorrectly
		 * assume EOF when a read from a socket returns less than
		 * requested.
		 */

		if (fgets(buffer, sizeof(buffer), fp) != 0
		    && ferror(fp) == 0 && feof(fp) == 0
		    && sscanf(buffer, "%u , %u : USERID :%*[^:]:%255s",
			      &rmt_port, &our_port, user) == 3
		    && ntohs(rmt_sin->sin_port) == rmt_port
		    && ntohs(our_sin->sin_port) == our_port) {

		    /*
		     * Strip trailing carriage return. It is part of the
		     * protocol, not part of the data.
		     */

		    if (cp = strchr(user, '\r'))
			*cp = 0;
		    result = user;
		}
	    }
	    alarm(0);
	}
	fclose(fp);
    }
    STRN_CPY(dest, result, STRING_LENGTH);
}

#ifdef STANDALONE

static char  *Loadstring;

static int reapchild()
{
        int state,pid;
	signal(SIGCHLD,reapchild);
        while ((pid=waitpid(-1,&state,WNOHANG|WUNTRACED))>0);
}

int dokill()
{
   kill(0,SIGKILL);
}

int standaloneinit(port)
int port ;
{
       int ndescriptors;
       FILE *pf;
       char pidfile[24];
       ndescriptors = getdtablesize();
       if (fork())
		exit(0);
       {  int s;
	  for (s = 0; s < ndescriptors; s++)
	      (void) close(s);
       }
       sprintf(pidfile,"/etc/bbsd-%d.pid",port);
       pf=fopen(pidfile,"w");
       if (pf != NULL) {
	       fprintf(pf,"%d",getpid());
			       fclose(pf);
       }
       (void) open("/", O_RDONLY);
       (void) dup2(0, 1);
       (void) dup2(0, 2);
       {
	 int tt = open("/dev/tty", O_RDWR);
	   if (tt > 0) {
             ioctl(tt, TIOCNOTTY, (char *)0);
	     (void) close(tt);
           }
        }
}

int standalonesetup(fd)
int fd;
{
	int on =1;
	if (setsockopt(fd,SOL_SOCKET, SO_REUSEADDR,(char *)&on,sizeof(on)) < 0)
		syslog(LOG_ERR, "setsockopt (SO_REUSEADDR): %m");
	on = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&on, sizeof (on))<0)
		syslog(LOG_ERR, "setsockopt (SO_LINGER): %m");
}

relisten( sin , port)
struct sockaddr_in *sin;
int port;
{
	    int s;
	    bzero(sin,sizeof(*sin));
	    sin->sin_port = port;
	    sin->sin_family = AF_INET;
	    s = socket(AF_INET, SOCK_STREAM, 0);
	    if (s < 0) {
		    perror("telnetd: socket");;
	            syslog(LOG_INFO, "BBS relisten can't open socket to %d",sin->sin_port);
		    exit(1);
	    }
	    standalonesetup(s);
	    if (bind(s, sin, sizeof *sin) < 0) {
	        syslog(LOG_INFO, "BBS relisten can't bind to %d",sin->sin_port);
		perror("bind");
		exit(1);
	    }
	    if (listen(s, 10) < 0) {
	        syslog(LOG_INFO, "BBS relisten can't listen to %d",sin->sin_port);
		perror("listen");
		exit(1);
	    }
	    return s;
}

getloadlimit(argc,argv,loadlimit)
int argc;
char **argv;
int loadlimit[];
{
    char *P[4], *p;
    int i;

    for (i=0;i<4;i++) P[i]=NULL;
    for (p=argv[0],i=0;*p && i < 4;i++) {
	    for (P[i]=p;*p && *p != '-'; p++);
	    if (*p=='\0') break;
	    for (*p++='\0';*p && *p == '-'; p++);
    }
    for (i=1;i<4;++i)
      if (P[i] != NULL)
        loadlimit[i-1]=atol(P[i]);
    if (argc > 3) {
       for (i = 3; i < argc; i++)
	      loadlimit[i - 3] = atoi(argv[i]);
    } 
}

#endif 
/* stand alone server */

main(argc, argv)
	char *argv[];
{
	struct sockaddr_in from;
	int on = 1, fromlen;

        openlog("telnetd", LOG_PID , LOG_LOCAL0);
#if	defined(STANDALONE)
	{
	    int s, ns, foo;
	    struct servent *sp;
	    static struct sockaddr_in sin = { AF_INET };
	    int port;
	    int loadlimit[3]={0,0,0};

	    getloadlimit(argc, argv, loadlimit);

	    sp = getservbyname("telnet", "tcp");
	    if (sp == 0) {
		    fprintf(stderr, "telnetd: tcp/telnet: unknown service\n");
		    exit(1);
	    }
	    port = sp->s_port;
	    if (argc > 1) {
		    port = atoi(argv[1]);
		    port = htons((u_short)port);
	    }
            standaloneinit(port);
	    s = relisten(&sin,port);

            signal(SIGHUP, SIG_IGN);
	    signal(SIGCHLD,reapchild);
            signal(SIGINT,dokill);
            signal(SIGTERM,dokill);
            chdir("/");


            for (;;) {
		static int shutdownforload=0;
		int pid, count;

#ifndef __linux
		if ((Loadstring=(char*)bbscheckload(loadlimit))==NULL) {
		    shutdownforload = 1;
	  	    close(s);
/*	 	    sleep(3);*/
		} else if (shutdownforload == 1) {
		    shutdownforload = 0;
	 	    syslog(LOG_INFO, "%s listen load too high in port %d", argv[0],port);
	 	    s = relisten(&sin,port);
	        }
#endif

                do {
                   int foo;
                   foo = sizeof sin;
                   ns = accept(s, &sin, &foo);
                   errno = 0;
                 } while ( ns < 0 && errno == EINTR );
                 if (ns < 0 && errno != EINTR){
                     perror("accept");
                     continue;
                 }
		 pid = fork();
	         if (pid<0) {
	            perror("fork");
	            exit(1);
	         }
                 if (pid==0) {
#ifndef __linux
			getkvmloadclose();
#endif
                        dup2(ns, 0);
                        dup2(ns, 1);
                        dup2(ns, 2);
                        close(s);
			openlog(argv[0], LOG_PID | LOG_ODELAY, LOG_DAEMON);
			fromlen = sizeof (from);
			if (getpeername(0, &from, &fromlen) < 0) {
				fprintf(stderr, "%s: ", argv[0]);
				perror("getpeername");
				_exit(1);
			}
			if (setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on)) < 0) {
				syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
			}
#ifdef __linux
			setpgrp();
#else
			setpgrp(0,0);
#endif
			if( argc > 2 ) doit(0,&from,argv[2]);
			else doit(0, &from,NULL);
			close(ns);	
                 }
		 else {
			close(ns);
		 }
	    }
        }
#else
	openlog("telnetd", LOG_PID | LOG_ODELAY, LOG_DAEMON);
	fromlen = sizeof (from);
	if (getpeername(0, (struct sockaddr *) &from, &fromlen) < 0) {
		fprintf(stderr, "%s: ", argv[0]);
		perror("getpeername");
		_exit(1);
	}
	if (setsockopt(0,SOL_SOCKET,SO_KEEPALIVE,(char *) &on,sizeof(on)) < 0) {
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	}
	if( argc > 2 ) doit(0,&from,argv[2]);
	else doit(0, &from,NULL);
#endif
}

char	*terminaltype = 0;
void	cleanup();

/*
 * ttloop
 *
 *	A small subroutine to flush the network output buffer, get some data
 * from the network, and pass it through the telnet state machine.  We
 * also flush the pty input buffer (by dropping its data) if it becomes
 * too full.
 */

void
ttloop()
{
    if (nfrontp-nbackp) {
	netflush();
    }
    ncc = read(net, netibuf, sizeof netibuf);
    if (ncc < 0) {
	syslog(LOG_INFO, "ttloop:  read: %m\n");
	exit(1);
    } else if (ncc == 0) {
	syslog(LOG_INFO, "ttloop:  peer died: %m\n");
	exit(1);
    }
    netip = netibuf;
    telrcv();			/* state machine */
    if (ncc > 0) {
	pfrontp = pbackp = ptyobuf;
	telrcv();
    }
}

/*
 * getterminaltype
 *
 *	Ask the other end to send along its terminal type.
 * Output is the variable terminaltype filled in.
 */

void
getterminaltype()
{
    static char sbuf[] = { IAC, DO, TELOPT_TTYPE };

    settimer(getterminal);
    bcopy(sbuf, nfrontp, sizeof sbuf);
    nfrontp += sizeof sbuf;
    hisopts[TELOPT_TTYPE] = OPT_YES_BUT_ALWAYS_LOOK;
    while (sequenceIs(ttypeopt, getterminal)) {
	ttloop();
    }
    if (hisopts[TELOPT_TTYPE] == OPT_YES) {
	static char sbbuf[] = { IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE };

	bcopy(sbbuf, nfrontp, sizeof sbbuf);
	nfrontp += sizeof sbbuf;
	while (sequenceIs(ttypesubopt, getterminal)) {
	    ttloop();
	}
    }
}

/*
 * Get a pty, scan input lines.
 */
doit(f,who,user)
	int f;
	struct sockaddr_in *who;
	char *user;
{
	char *host, *inet_ntoa(), *realhost;
	int i, p, t;
        time_t now;
#ifdef PTY512
	char *ttychar = "klmnopqrstuvwxyzKLMNOPQRSTUVWXYZ";
	int ttyno = 512;
	int ttyrow = 32;
#else
	char *ttychar = "pqrstuvwxyzPQRST";
	int ttyno = 256;
	int ttyrow = 16;
#endif

#ifdef ultrix
	struct termios b;
#endif
	struct hostent *hp;
#ifdef STREAM_PTY
	if ((p = open("/dev/ptmx", O_RDWR)) < 0)
		fatal(f, "All network ports in use");
	if (grantpt(p) < 0 || unlockpt(p) < 0)
		fatal(f, "Cannot initialize pty slave");
	dup2(f, 0);
	if ((line = ptsname(p)) == 0 || (t = open(line, O_RDWR)) < 0)
		fatal(f, "Cannot find  pty slave");
	if (ioctl(t, I_PUSH, "ptem") < 0 || ioctl(t, I_PUSH, "ldterm") < 0 
	|| ioctl(t, I_PUSH, "ttcompat") < 0 || ioctl(p, I_PUSH, "pckt") < 0)
		fatal(f, "Cannot push streams modules onto pty");
#else /* STREAM_PTY */


/*  Using the simple hashing algrithm to increase the seaching pty speed */
/* 						changed By Sun */
/* Begin ..............		*/


time(&now);


now %= ttyno;
for (i = now ; i < now + ttyno ; ++i) {
        line = "/dev/ptyXX";
        line[strlen("/dev/pty")] = "pqrstuvwxyzPQRST"[i %  ttyrow];
        line[strlen("/dev/ptyp")] = "0123456789abcdef"[(i%ttyno)/ttyrow];
        if ((p = open(line, O_RDWR)) == -1)
               continue;
		else 	goto gotpty;
}
/* End 		.....			Sun */

/*
	int c;

	for (c = 'p'; c <= 'z'; c++) {
		struct stat stb;
		static char ptyname[] = "/dev/ptyXX";
		line = ptyname;
		line[strlen("/dev/pty")] = c;
		line[strlen("/dev/ptyp")] = '0';
		if (stat(line, &stb) < 0)
			break;
		for (i = 0; i < 16; i++) {
			line[sizeof("/dev/ptyp") - 1] = "0123456789abcdef"[i];
			close(open(line, O_RDWR | O_NOCTTY));
			p = open(line, O_RDWR | O_NOCTTY);
			if (p > 0)
				goto gotpty;
		}
	}
*/
	fatal(f, "All network ports in use");
	/*NOTREACHED*/
gotpty:
	dup2(f, 0);
	line[strlen("/dev/")] = 't';
	t = open(line, O_RDWR | O_NOCTTY);
	if (t < 0)
		fatalperror(f, line);
	if (fchmod(t, 0))
		fatalperror(f, line);
#ifdef ultrix
	tcgetattr(t, &b);
	b.c_iflag |= ICRNL;
	b.c_oflag |= ONLCR;
	tcsetattr(t, TCSANOW, &b);
#endif /* ultrix */
#endif /* STREAM_PTY */
	hp = gethostbyaddr((char *) &who->sin_addr, sizeof (struct in_addr),
		who->sin_family);
	if (hp)
		host = hp->h_name;
	else
		host = inet_ntoa(who->sin_addr);
	net = f;
	pty = p;
#ifdef STREAM_PTY
	pts = t;
#endif

	/*
	 * get terminal type.
	 */
	getterminaltype();

	if ((i = fork()) < 0)
		fatalperror(f, "fork");
	if (i)
		telnet(f, p);
	/* Acquire a controlling terminal */
	setsid();

#ifdef DEBUG
	{
        int len;
        char *ptr;
	static char remoteusername[80];
        struct sockaddr_in our;
        len = sizeof our;
        if(getsockname(0,&our,&len) < 0)
                perror("telnetd:getsockname");
        strcpy(shen_buf,"REMOTEUSERNAME=");
	strcpy(remoteusername,"REMOTEUSERNAME=");
        ptr = &shen_buf[strlen("REMOTEUSERNAME=")];
	ptr = &remoteusername[strlen("REMOTEUSERNAME=")];   
        rfc931(who, &our,ptr );
        syslog(LOG_INFO,"connect from %s@%s",ptr, host);
        environ[0] = 0;
        putenv(shen_buf);
        environ[0]='\0'; /* 後面的 environ[0]='\0' 刪除 */
        putenv(remoteusername);
        strcpy(shen_buf,"REMOTEHOSTNAME=");
        ptr = &shen_buf[strlen("REMOTEHOSTNAME=")];
        /* Shuo */
        strcpy(ptr,host);

	}
#endif

#if defined(TIOCSCTTY) && !defined(BROKEN_TIOCSCTTY)
	ioctl(t, TIOCSCTTY, (caddr_t) 0);
#else /* TIOCSCTTY */
	i = t;
	if ((t = open(line, O_RDWR)) < 0)
		_exit(1);
	close(i);
#endif /* TIOCSCTTY */
	close(f);
	close(p);
	dup2(t, 0);
	dup2(t, 1);
	dup2(t, 2);
	close(t);
	/*
	 * -h : pass on name of host.
	 *		WARNING:  -h is accepted by login if and only if
	 *			getuid() == 0.
	 * -p : don't clobber the environment (so terminal type stays set).
	 */
#ifdef SYSV_UTMP
	/* SYSV login insists on an utmp(x) entry */
	{
		char *MAKE_UTMP_ID(), *utmp_id = MAKE_UTMP_ID(line, "tn");
		UTMP_INIT(line + sizeof("/dev/") - 1, ".telnet", utmp_id);
	}
#endif
#ifdef SYSV_ENV
	execl(_PATH_LOGIN, "login", "-h", host,
					terminaltype, (char *) 0);
#else
/*	environ[0] = 0;*/
	if (terminaltype)
		putenv(terminaltype);
	putenv(shen_buf);
	if ( user ) {
	      /*  setuid(user);*/
		execl(_PATH_LOGIN,"login", "-p", "-h", host, user,0);
	} else
		execl(_PATH_LOGIN,"login", "-h", host, 
					terminaltype ? "-p" : 0, 0);
	
#endif
	syslog(LOG_ERR, "%s: %m", _PATH_LOGIN);
	fatalperror(2, _PATH_LOGIN);
	/*NOTREACHED*/
}

fatal(f, msg)
	int f;
	char *msg;
{
	char buf[BUFSIZ];

	(void) sprintf(buf, "telnetd: %s.\r\n", msg);
	(void) write(f, buf, strlen(buf));
	exit(1);
}

fatalperror(f, msg)
	int f;
	char *msg;
{
	char buf[BUFSIZ];
	extern char *sys_errlist[];

	(void) sprintf(buf, "%s: %s\r\n", msg, sys_errlist[errno]);
	fatal(f, buf);
}


/*
 * Check a descriptor to see if out of band data exists on it.
 */


stilloob(s)
int	s;		/* socket number */
{
    static struct timeval timeout = { 0 };
    fd_set	excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(s, &excepts);
	value = select(s+1, (fd_set *)0, (fd_set *)0, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	fatalperror(pty, "select");
    }
    if (FD_ISSET(s, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

/*
 * Main loop.  Select from pty and network, and
 * hand data to telnet receiver finite state machine.
 */
char tbyhostname[MAXHOSTNAMELEN];
telnet(f, p)
{
	int on = 1;
        int issueget;
        char	*buf;
        char	*show_os_list();
        char	real_os[100];
        char    hostname[MAXHOSTNAMELEN];
  
#define	TABBUFSIZ	512
	char	defent[TABBUFSIZ];
	char	defstrs[TABBUFSIZ];
#undef	TABBUFSIZ
	char *HE;
	char *HN;
	char *IM;

	ioctl(f, FIONBIO, &on);
	ioctl(p, FIONBIO, &on);
#ifndef STREAM_PTY
	ioctl(p, TIOCPKT, &on);
#endif
#if	defined(SO_OOBINLINE)
	setsockopt(net, SOL_SOCKET, SO_OOBINLINE, (char *) &on, sizeof on);
#endif	/* defined(SO_OOBINLINE) */
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	/*
	 * Ignoring SIGTTOU keeps the kernel from blocking us
	 * in ttioctl() in /sys/tty.c.
	 */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGCHLD, cleanup);
	setsid();

	/*
	 * Request to do remote echo and to suppress go ahead.
	 */
	if (!myopts[TELOPT_ECHO]) {
	    dooption(TELOPT_ECHO);
	}
	if (!myopts[TELOPT_SGA]) {
	    dooption(TELOPT_SGA);
	}
	/*
	 * Is the client side a 4.2 (NOT 4.3) system?  We need to know this
	 * because 4.2 clients are unable to deal with TCP urgent data.
	 *
	 * To find out, we send out a "DO ECHO".  If the remote system
	 * answers "WILL ECHO" it is probably a 4.2 client, and we note
	 * that fact ("WILL ECHO" ==> that the client will echo what
	 * WE, the server, sends it; it does NOT mean that the client will
	 * echo the terminal input).
	 */
	(void) sprintf(nfrontp, doopt, TELOPT_ECHO);
	nfrontp += sizeof doopt-2;
	hisopts[TELOPT_ECHO] = OPT_YES_BUT_ALWAYS_LOOK;

	/*
	 * Show banner that getty never gave.
	 *
	 * We put the banner in the pty input buffer.  This way, it
	 * gets carriage return null processing, etc., just like all
	 * other pty --> client data.
	 */

  
	gethostname(hostname, sizeof (hostname));
	strcpy(tbyhostname,hostname);
  
#if 0
	if (getent(defent, "default") == 1) {
		char *getstr();
		char *p=defstrs;~

		HE = getstr("he", &p);
		HN = getstr("hn", &p);
		IM = getstr("im", &p);
		if (HN && *HN)
			strcpy(hostname, HN);
		edithost(HE, hostname);
		if (IM && *IM)
			putf(IM, ptyibuf+1);
	} else {
#endif
        
         strcpy(real_os, show_os_list());
#define MYBANNER real_os
         sprintf(ptyibuf+1, MYBANNER );
         
#if 0
	}
#endif
        if(fopen("/etc/issue","r")!=NULL)
        system("/bin/cat /etc/issue");

#ifdef SUNOS5      
        system("/usr/ucb/uptime");
#else
        system("/usr/bin/uptime");
#endif

	ptyip = ptyibuf+1;		/* Prime the pump */
	pcc = strlen(ptyip);		/* ditto */

	/* Clear ptybuf[0] - where the packet information is received */
	ptyibuf[0] = 0;

	/*
	 * Call telrcv() once to pick up anything received during
	 * terminal type negotiation.
	 */
	telrcv();

	for (;;) {
		fd_set ibits, obits, xbits;
		register int c;

		if (ncc < 0 && pcc < 0)
			break;

		FD_ZERO(&ibits);
		FD_ZERO(&obits);
		FD_ZERO(&xbits);
		/*
		 * Never look for input if there's still
		 * stuff in the corresponding output buffer
		 */
		if (nfrontp - nbackp || pcc > 0) {
			FD_SET(f, &obits);
			FD_SET(p, &xbits);
		} else {
			FD_SET(p, &ibits);
		}
		if (pfrontp - pbackp || ncc > 0) {
			FD_SET(p, &obits);
		} else {
			FD_SET(f, &ibits);
		}
		if (!SYNCHing) {
			FD_SET(f, &xbits);
		}
		if ((c = select(16, &ibits, &obits, &xbits,
						(struct timeval *)0)) < 1) {
			if (c == -1) {
				if (errno == EINTR) {
					continue;
				}
			}
/*			sleep(5);*/
			continue;
		}

		/*
		 * Any urgent data?
		 */
		if (FD_ISSET(net, &xbits)) {
		    SYNCHing = 1;
		}

		/*
		 * Something to read from the network...
		 */
		if (FD_ISSET(net, &ibits)) {
#if	!defined(SO_OOBINLINE)
			/*
			 * In 4.2 (and 4.3 beta) systems, the
			 * OOB indication and data handling in the kernel
			 * is such that if two separate TCP Urgent requests
			 * come in, one byte of TCP data will be overlaid.
			 * This is fatal for Telnet, but we try to live
			 * with it.
			 *
			 * In addition, in 4.2 (and...), a special protocol
			 * is needed to pick up the TCP Urgent data in
			 * the correct sequence.
			 *
			 * What we do is:  if we think we are in urgent
			 * mode, we look to see if we are "at the mark".
			 * If we are, we do an OOB receive.  If we run
			 * this twice, we will do the OOB receive twice,
			 * but the second will fail, since the second
			 * time we were "at the mark", but there wasn't
			 * any data there (the kernel doesn't reset
			 * "at the mark" until we do a normal read).
			 * Once we've read the OOB data, we go ahead
			 * and do normal reads.
			 *
			 * There is also another problem, which is that
			 * since the OOB byte we read doesn't put us
			 * out of OOB state, and since that byte is most
			 * likely the TELNET DM (data mark), we would
			 * stay in the TELNET SYNCH (SYNCHing) state.
			 * So, clocks to the rescue.  If we've "just"
			 * received a DM, then we test for the
			 * presence of OOB data when the receive OOB
			 * fails (and AFTER we did the normal mode read
			 * to clear "at the mark").
			 */
		    if (SYNCHing) {
			int atmark;

			ioctl(net, SIOCATMARK, (char *)&atmark);
			if (atmark) {
			    ncc = recv(net, netibuf, sizeof (netibuf), MSG_OOB);
			    if ((ncc == -1) && (errno == EINVAL)) {
				ncc = read(net, netibuf, sizeof (netibuf));
				if (sequenceIs(didnetreceive, gotDM)) {
				    SYNCHing = stilloob(net);
				}
			    }
			} else {
			    ncc = read(net, netibuf, sizeof (netibuf));
			}
		    } else {
			ncc = read(net, netibuf, sizeof (netibuf));
		    }
		    settimer(didnetreceive);
#else	/* !defined(SO_OOBINLINE)) */
		    ncc = read(net, netibuf, sizeof (netibuf));
#endif	/* !defined(SO_OOBINLINE)) */
		    if (ncc < 0 && errno == EWOULDBLOCK)
			ncc = 0;
		    else {
			if (ncc <= 0) {
			    break;
			}
			netip = netibuf;
		    }
		}

		/*
		 * Something to read from the pty...
		 */
		if (FD_ISSET(p, &xbits)) {
			if (PTY_PKT_READ(p, ptyibuf, 1) != 1) {
				break;
			}
		}
		if (FD_ISSET(p, &ibits)) {
			pcc = PTY_PKT_READ(p, ptyibuf, BUFSIZ);
			if (pcc < 0 && errno == EWOULDBLOCK)
				pcc = 0;
			else {
				if (pcc <= 0)
					break;
				/* Skip past "packet" */
				pcc--;
				ptyip = ptyibuf+1;
			}
		}
		if (ptyibuf[0] & TIOCPKT_FLUSHWRITE) {
			netclear();	/* clear buffer back */
			*nfrontp++ = IAC;
			*nfrontp++ = DM;
			neturg = nfrontp-1;  /* off by one XXX */
			ptyibuf[0] = 0;
		}

		while (pcc > 0) {
			if ((&netobuf[BUFSIZ] - nfrontp) < 2)
				break;
			c = *ptyip++ & 0377, pcc--;
			if (c == IAC)
				*nfrontp++ = c;
			*nfrontp++ = c;
			/* Don't do CR-NUL if we are in binary mode */
			if ((c == '\r') && (myopts[TELOPT_BINARY] == OPT_NO)) {
				if (pcc > 0 && ((*ptyip & 0377) == '\n')) {
					*nfrontp++ = *ptyip++ & 0377;
					pcc--;
				} else
					*nfrontp++ = '\0';
			}
		}
		if (FD_ISSET(f, &obits) && (nfrontp - nbackp) > 0)
			netflush();
		if (ncc > 0)
			telrcv();
		if (FD_ISSET(p, &obits) && (pfrontp - pbackp) > 0)
			ptyflush();
	}
	cleanup();
}
	
/*
 * State for recv fsm
 */
#define	TS_DATA		0	/* base state */
#define	TS_IAC		1	/* look for double IAC's */
#define	TS_CR		2	/* CR-LF ->'s CR */
#define	TS_SB		3	/* throw away begin's... */
#define	TS_SE		4	/* ...end's (suboption negotiation) */
#define	TS_WILL		5	/* will option negotiation */
#define	TS_WONT		6	/* wont " */
#define	TS_DO		7	/* do " */
#define	TS_DONT		8	/* dont " */

telrcv()
{
	register int c;
	static int state = TS_DATA;
#ifdef STREAM_PTY
	int pty = pts;	/* XXX apply ioctl()s at slave end */
#endif

	while (ncc > 0) {
		if ((&ptyobuf[BUFSIZ] - pfrontp) < 2)
			return;
		c = *netip++ & 0377, ncc--;
		switch (state) {

		case TS_CR:
			state = TS_DATA;
			/* Strip off \n or \0 after a \r */
			if ((c == 0) || (c == '\n')) {
				break;
			}
			/* FALL THROUGH */

		case TS_DATA:
			if (c == IAC) {
				state = TS_IAC;
				break;
			}
			if (inter > 0)
				break;
			/*
			 * We now map \r\n ==> \r for pragmatic reasons.
			 * Many client implementations send \r\n when
			 * the user hits the CarriageReturn key.
			 *
			 * We USED to map \r\n ==> \n, since \r\n says
			 * that we want to be in column 1 of the next
			 * printable line, and \n is the standard
			 * unix way of saying that (\r is only good
			 * if CRMOD is set, which it normally is).
			 */
			if ((c == '\r') && (hisopts[TELOPT_BINARY] == OPT_NO)) {
				state = TS_CR;
			}
			*pfrontp++ = c;
			break;

		case TS_IAC:
			switch (c) {

			/*
			 * Send the process on the pty side an
			 * interrupt.  Do this with a NULL or
			 * interrupt char; depending on the tty mode.
			 */
			case IP:
				interrupt();
				break;

			case BREAK:
				sendbrk();
				break;

			/*
			 * Are You There?
			 */
			case AYT:
				strcpy(nfrontp, "\r\n[Yes]\r\n");
				nfrontp += 9;
				break;

			/*
			 * Abort Output
			 */
			case AO: {
					ptyflush();	/* half-hearted */
					tcflush(pty, TCOFLUSH);
					netclear();	/* clear buffer back */
					*nfrontp++ = IAC;
					*nfrontp++ = DM;
					neturg = nfrontp-1; /* off by one XXX */
					break;
				}

			/*
			 * Erase Character and
			 * Erase Line
			 */
			case EC:
			case EL: {
					struct termios b;
					char ch;

					ptyflush();	/* half-hearted */
					tcgetattr(pty, &b);
					ch = (c == EC) ?
						b.c_cc[VERASE] : b.c_cc[VKILL];
					if (ch != '\377') {
						*pfrontp++ = ch;
					}
					break;
				}

			/*
			 * Check for urgent data...
			 */
			case DM:
				SYNCHing = stilloob(net);
				settimer(gotDM);
				break;


			/*
			 * Begin option subnegotiation...
			 */
			case SB:
				state = TS_SB;
				continue;

			case WILL:
				state = TS_WILL;
				continue;

			case WONT:
				state = TS_WONT;
				continue;

			case DO:
				state = TS_DO;
				continue;

			case DONT:
				state = TS_DONT;
				continue;

			case IAC:
				*pfrontp++ = c;
				break;
			}
			state = TS_DATA;
			break;

		case TS_SB:
			if (c == IAC) {
				state = TS_SE;
			} else {
				SB_ACCUM(c);
			}
			break;

		case TS_SE:
			if (c != SE) {
				if (c != IAC) {
					SB_ACCUM(IAC);
				}
				SB_ACCUM(c);
				state = TS_SB;
			} else {
				SB_TERM();
				suboption();	/* handle sub-option */
				state = TS_DATA;
			}
			break;

		case TS_WILL:
			if (hisopts[c] != OPT_YES)
				willoption(c);
			state = TS_DATA;
			continue;

		case TS_WONT:
			if (hisopts[c] != OPT_NO)
				wontoption(c);
			state = TS_DATA;
			continue;

		case TS_DO:
			if (myopts[c] != OPT_YES)
				dooption(c);
			state = TS_DATA;
			continue;

		case TS_DONT:
			if (myopts[c] != OPT_NO) {
				dontoption(c);
			}
			state = TS_DATA;
			continue;

		default:
			syslog(LOG_ERR, "telnetd: panic state=%d\n", state);
			printf("telnetd: panic state=%d\n", state);
			exit(1);
		}
	}
}

willoption(option)
	int option;
{
	char *fmt;

	switch (option) {

	case TELOPT_BINARY:
		telopt_binary(1);
		fmt = doopt;
		break;

	case TELOPT_ECHO:
		not42 = 0;		/* looks like a 4.2 system */
		/*
		 * Now, in a 4.2 system, to break them out of ECHOing
		 * (to the terminal) mode, we need to send a "WILL ECHO".
		 * Kludge upon kludge!
		 */
		if (myopts[TELOPT_ECHO] == OPT_YES) {
		    dooption(TELOPT_ECHO);
		}
		fmt = dont;
		break;

	case TELOPT_TTYPE:
		settimer(ttypeopt);
		if (hisopts[TELOPT_TTYPE] == OPT_YES_BUT_ALWAYS_LOOK) {
		    hisopts[TELOPT_TTYPE] = OPT_YES;
		    return;
		}
		fmt = doopt;
		break;

	case TELOPT_SGA:
		fmt = doopt;
		break;

	case TELOPT_TM:
		fmt = dont;
		break;

	default:
		fmt = dont;
		break;
	}
	if (fmt == doopt) {
		hisopts[option] = OPT_YES;
	} else {
		hisopts[option] = OPT_NO;
	}
	(void) sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (dont) - 2;
}

wontoption(option)
	int option;
{
	char *fmt;

	switch (option) {
	case TELOPT_ECHO:
		not42 = 1;		/* doesn't seem to be a 4.2 system */
		break;

	case TELOPT_BINARY:
		telopt_binary(0);
		break;

	case TELOPT_TTYPE:
	    settimer(ttypeopt);
	    break;
	}

	fmt = dont;
	hisopts[option] = OPT_NO;
	(void) sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (doopt) - 2;
}

dooption(option)
	int option;
{
	char *fmt;

	switch (option) {

	case TELOPT_TM:
		fmt = wont;
		break;

	case TELOPT_ECHO:
		telopt_echo(1);
		fmt = will;
		break;

	case TELOPT_BINARY:
		telopt_binary(1);
		fmt = will;
		break;

	case TELOPT_SGA:
		fmt = will;
		break;

	default:
		fmt = wont;
		break;
	}
	if (fmt == will) {
	    myopts[option] = OPT_YES;
	} else {
	    myopts[option] = OPT_NO;
	}
	(void) sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (doopt) - 2;
}


dontoption(option)
int option;
{
    char *fmt;

    switch (option) {
    case TELOPT_ECHO:		/* we should stop echoing */
	telopt_echo(0);
	fmt = wont;
	break;

    default:
	fmt = wont;
	break;
    }

    if (fmt = wont) {
	myopts[option] = OPT_NO;
    } else {
	myopts[option] = OPT_YES;
    }
    (void) sprintf(nfrontp, fmt, option);
    nfrontp += sizeof (wont) - 2;
}

/*
 * suboption()
 *
 *	Look at the sub-option buffer, and try to be helpful to the other
 * side.
 *
 *	Currently we recognize:
 *
 *	Terminal type is
 */

suboption()
{
    switch (SB_GET()) {
    case TELOPT_TTYPE: {		/* Yaaaay! */
	static char terminalname[5+41] = "TERM=";

	settimer(ttypesubopt);

	if (SB_GET() != TELQUAL_IS) {
	    return;		/* ??? XXX but, this is the most robust */
	}

	terminaltype = terminalname+strlen(terminalname);

	while ((terminaltype < (terminalname + sizeof terminalname-1)) &&
								    !SB_EOF()) {
	    register int c;

	    c = SB_GET();
	    if (isupper(c)) {
		c = tolower(c);
	    }
	    *terminaltype++ = c;    /* accumulate name */
	}
	*terminaltype = 0;
	terminaltype = terminalname;
	break;
    }

    default:
	;
    }
}

#if 0

mode(on, off)
	int on, off;
{
	struct sgttyb b;
#ifdef STREAM_PTY
	int pty = pts;	/* XXX apply ioctl()s at slave end */
#endif

	ptyflush();
	ioctl(pty, TIOCGETP, &b);
	b.sg_flags |= on;
	b.sg_flags &= ~off;
	ioctl(pty, TIOCSETP, &b);
}

#else

telopt_echo(on)
	int	on;
{
#ifdef STREAM_PTY
	int	pty = pts;
#endif
	struct termios b;

	ptyflush();
	tcgetattr(pty, &b);
	if (on) {
		b.c_lflag |= ECHO;
	} else {
		b.c_lflag &= ~ECHO;
	}
	tcsetattr(pty, TCSANOW, &b);
}

telopt_binary(on)
	int	on;
{
#ifdef STREAM_PTY
	int	pty = pts;
#endif
	struct termios b;

	ptyflush();
	tcgetattr(pty, &b);
	if (on) {
		b.c_oflag &= ~OPOST;
	} else {
		b.c_oflag |= OPOST;
	}
	tcsetattr(pty, TCSANOW, &b);
}

#endif

/*
 * Send interrupt to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write intr char.
 */
interrupt()
{
	struct termios b;
#ifdef STREAM_PTY
	int pty = pts;	/* XXX apply ioctl()s at slave end */
#endif

	ptyflush();	/* half-hearted */
	tcgetattr(pty, &b);
	if ((b.c_lflag & ICANON) == 0) {
		*pfrontp++ = '\0';
		return;
	}
	if (b.c_cc[VINTR] != 0377)
		*pfrontp++ = b.c_cc[VINTR];
}

/*
 * Send quit to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write quit char.
 */
sendbrk()
{
	struct termios b;
#ifdef STREAM_PTY
	int pty = pts;	/* XXX apply ioctl()s at slave end */
#endif

	ptyflush();	/* half-hearted */
	tcgetattr(pty, &b);
	if ((b.c_lflag & ICANON) == 0) {
		*pfrontp++ = '\0';
		return;
	}
	if (b.c_cc[VQUIT] != 0377)
		*pfrontp++ = b.c_cc[VQUIT];
}

ptyflush()
{
	int n;

	if ((n = pfrontp - pbackp) > 0)
		n = write(pty, pbackp, n);
	if (n < 0)
		return;
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */

char *
nextitem(current)
char	*current;
{
    if ((*current&0xff) != IAC) {
	return current+1;
    }
    switch (*(current+1)&0xff) {
    case DO:
    case DONT:
    case WILL:
    case WONT:
	return current+3;
    case SB:		/* loop forever looking for the SE */
	{
	    register char *look = current+2;

	    for (;;) {
		if ((*look++&0xff) == IAC) {
		    if ((*look++&0xff) == SE) {
			return look;
		    }
		}
	    }
	}
    default:
	return current+2;
    }
}


/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */

netclear()
{
    register char *thisitem, *next;
    char *good;
#define	wewant(p)	((nfrontp > p) && ((*p&0xff) == IAC) && \
				((*(p+1)&0xff) != EC) && ((*(p+1)&0xff) != EL))

    thisitem = netobuf;

    while ((next = nextitem(thisitem)) <= nbackp) {
	thisitem = next;
    }

    /* Now, thisitem is first before/at boundary. */

    good = netobuf;	/* where the good bytes go */

    while (nfrontp > thisitem) {
	if (wewant(thisitem)) {
	    int length;

	    next = thisitem;
	    do {
		next = nextitem(next);
	    } while (wewant(next) && (nfrontp > next));
	    length = next-thisitem;
	    bcopy(thisitem, good, length);
	    good += length;
	    thisitem = next;
	} else {
	    thisitem = nextitem(thisitem);
	}
    }

    nbackp = netobuf;
    nfrontp = good;		/* next byte to be sent */
    neturg = 0;
}

/*
 *  netflush
 *		Send as much data as possible to the network,
 *	handling requests for urgent data.
 */


netflush()
{
    int n;

    if ((n = nfrontp - nbackp) > 0) {
	/*
	 * if no urgent data, or if the other side appears to be an
	 * old 4.2 client (and thus unable to survive TCP urgent data),
	 * write the entire buffer in non-OOB mode.
	 */
	if ((neturg == 0) || (not42 == 0)) {
	    n = write(net, nbackp, n);	/* normal write */
	} else {
	    n = neturg - nbackp;
	    /*
	     * In 4.2 (and 4.3) systems, there is some question about
	     * what byte in a sendOOB operation is the "OOB" data.
	     * To make ourselves compatible, we only send ONE byte
	     * out of band, the one WE THINK should be OOB (though
	     * we really have more the TCP philosophy of urgent data
	     * rather than the Unix philosophy of OOB data).
	     */
	    if (n > 1) {
		n = send(net, nbackp, n-1, 0);	/* send URGENT all by itself */
	    } else {
		n = send(net, nbackp, n, MSG_OOB);	/* URGENT data */
	    }
	}
    }
    if (n < 0) {
	if (errno == EWOULDBLOCK)
	    return;
	/* should blow this guy away... */
	return;
    }
    nbackp += n;
    if (nbackp >= neturg) {
	neturg = 0;
    }
    if (nbackp == nfrontp) {
	nbackp = nfrontp = netobuf;
    }
}

void	cleanup()
{
	char *p;

	p = line + sizeof("/dev/") - 1;
#ifdef SYSV_UTMP
	UTMP_LOGOUT(p);
	(void)chown(line, 0, 0);
	(void)chmod(line, 0644);
#else /* SYSV_UTMP */
	if (logout(p))
		logwtmp(p, "", "");
	(void)chmod(line, 0666);
	(void)chown(line, 0, 0);
	*p = 'p';
	(void)chmod(line, 0666);
	(void)chown(line, 0, 0);
#endif /* SYSV_UTMP */
	shutdown(net, 2);
	exit(1);
}

char	editedhost[32];

edithost(pat, host)
	register char *pat;
	register char *host;
{
	register char *res = editedhost;

	if (!pat)
		pat = "";
	while (*pat) {
		switch (*pat) {

		case '#':
			if (*host)
				host++;
			break;

		case '@':
			if (*host)
				*res++ = *host++;
			break;

		default:
			*res++ = *pat;
			break;

		}
		if (res == &editedhost[sizeof editedhost - 1]) {
			*res = '\0';
			return;
		}
		pat++;
	}
	if (*host)
		strncpy(res, host, sizeof editedhost - (res - editedhost) - 1);
	else
		*res = '\0';
	editedhost[sizeof editedhost - 1] = '\0';
}

static char *putlocation;

puts(s)
register char *s;
{

	while (*s)
		putchr(*s++);
}

putchr(cc)
{
	*putlocation++ = cc;
}

putf(cp, where)
register char *cp;
char *where;
{
	char *slash;
	extern char *rindex();

	putlocation = where;

	while (*cp) {
		if (*cp != '%') {
			putchr(*cp++);
			continue;
		}
		switch (*++cp) {

		case 't':
			slash = rindex(line, '/');
			if (slash == (char *) 0)
				puts(line);
			else
				puts(&slash[1]);
			break;

		case 'h':
			puts(editedhost);
			break;

		case 'd':
#if 0
			get_date(datebuffer);
			puts(datebuffer);
#else
			puts("hi there");
#endif
			break;

		case '%':
			putchr('%');
			break;
		}
		cp++;
	}
}

char *
show_os_list()
{


  static      char  buf[100][201];
  FILE        *fp;
  int         i,j=0;
  int	      osget,buflen;
  char        dirbuf[40];
  char	      totalbuf[100];
              
    if( (fp=fopen("/usr/local/etc/OS.list","r"))!=NULL){
     for (i=0; i<100; i++) {
      if (fgets(buf[i],200,fp) == (char *) NULL) {
         buf[i][0]='\0';
         break;
         }
       j++;
       }
      fclose(fp);
     }
   else {
   sprintf(totalbuf,"\r\n\r%s (%s) %s\r\n\r\r",BANNER,tbyhostname,line+5);
   return totalbuf;
   }
    
   osget=time(NULL)%j; 
   buflen=strlen(buf[osget]);
   buf[osget][buflen-1]='\0';
   buf[osget+1][0]='\0';
  
   sprintf(totalbuf,"\r\n\r%s(%s) %s\r\n\r\r",buf[osget],tbyhostname,line+5);
   return totalbuf;
}   
