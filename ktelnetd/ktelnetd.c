/*
 * Copyright (c) 2009, 2009 Regents of Robert.young.
 * All rights reserved.
 *
*/

#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/wanrouter.h>
#include <linux/if_bridge.h>
#include <linux/if_frad.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/kmod.h>
#include <linux/audit.h>
#include <linux/wireless.h>
#include <linux/nsproxy.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <net/compat.h>

#include <net/sock.h>
#include <linux/netfilter.h>

#include <linux/init.h>    /* For module_init and module_clea */
#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */

/* For socket etc */
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/smp_lock.h>
#include <linux/slab.h> /* for kmalloc */
#include <linux/kthread.h>

#define KTELNETD_WELCOME "Welcome to kernel space\r\nBuilded by Rober.Young\r\n\r\n"
#define KTELNETD_PROMTE  "[root@kernel]#"
#define KTELNETD_STRING  "KTELNETD: "

#define KTELNETD_PORT 12323     /* KTELNET port */
#define SNDBUF 32 
#define RCVBUF 32

#define IAC 255

#define	CMD_SB		250	/* ...end's (suboption negotiation) */
#define	CMD_WILL	251	/* will option negotiation */
#define	CMD_WONT	252	/* wont " */
#define	CMD_DO		253	/* do " */
#define	CMD_DONT	254	/* dont " */

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

#define	IP          244
#define	BREAK       243
#define	AYT         246
#define	AO          245
#define	EC          247
#define	EL          248
#define	DM          242

char data_stack[RCVBUF];
int  sp = 0; /* stack pointer */

struct socket* sock;
struct socket* nsock;

typedef struct {
	int echo;
}TL_SESSION;

TL_SESSION session;

size_t SendBuffer(struct socket *sock, const char *Buffer, size_t Length);

int ds_push(char c)
{
	if (sp < RCVBUF){
		data_stack[sp] = c;
		sp++;
		data_stack[sp] = 0;
	}
	else
		return -1;
	
	return sp;
}

int ds_pop(char *p)
{
	if (sp > 0){
		*p = data_stack[sp-1];
		sp--;
		data_stack[sp] = 0;
	}
	else
		return -1;

	return sp;
}

char *ds_all(void)
{
	sp = 0;
	return data_stack;
}

int sh_exe(char *cmd, char **psndbuf)
{
	int ret;
	
	printk(KERN_INFO KTELNETD_STRING "command %s not found\n", cmd);

	ret = sprintf(*psndbuf, "command %s not found\r\n", cmd);
	*psndbuf += ret;
	ret = sprintf(*psndbuf, "%s", KTELNETD_PROMTE);
	*psndbuf += ret;
	
	return 0;
}

#if 0
int send_sync_buf (struct socket *sock, const char *buf, 
                   const size_t length, unsigned long flags)
{
    struct msghdr msg;
    struct iovec iov;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name     = 0;
    msg.msg_namelen  = 0;
    msg.msg_iov      = &iov;
    msg.msg_iovlen   = 1;
    msg.msg_control  = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags    = flags;

    oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
    msg.msg_iov->iov_len = left;
    msg.msg_iov->iov_base = (char *) buf + written;

    len = sock_sendmsg(sock, &msg, left);
    if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && 
         (len == -EAGAIN)))
        goto repeat_send;
    if (len > 0) {
        written += len;
        left -= len;
        if (left)
            goto repeat_send;
    }
    set_fs(oldmm);
    return written ? written : len;
}

int send_reply(struct socket *sock, char *str, int len)
{   
    return send_sync_buf(sock, str, len, MSG_DONTWAIT);
}

int ktelnetd_recv(struct socket *sock, char *str)
{       mm_segment_t oldmm;
        struct msghdr msg;
        struct iovec iov;
        int len;
        int max_size = SNDBUF;

        msg.msg_name     = 0;
        msg.msg_namelen  = 0;
        msg.msg_iov      = &iov;
        msg.msg_iovlen   = 1;
        msg.msg_control  = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags    = 0;
        
        msg.msg_iov->iov_base = str;
        msg.msg_iov->iov_len  = max_size;
        
        oldmm = get_fs(); set_fs(KERNEL_DS);

read_again:
        len = sock_recvmsg(sock, &msg, max_size, 0); /*MSG_DONTWAIT); */
        if (len == -EAGAIN || len == -ERESTARTSYS) {
            goto read_again;
        }
        set_fs(oldmm);
        return len;
}

#endif 



#define TELOPT_ECHO 1

int wont_option(unsigned char option, char *p)
{
	int ret = 0;

	switch (option) {
		
	default:
		p[0] = IAC;
		p[1] = CMD_DONT;
		p[2] = option;

		ret += 3;
		break;

	}

	return ret;
}

int will_option(unsigned char option, char *p)
{
	int ret = 0;

	switch (option) {
		
	default:
		p[0] = IAC;
		p[1] = CMD_DO;
		p[2] = option;

		ret += 3;
		break;

	}

	return ret;
}
int dont_option(unsigned char option, char *p)
{
	int ret = 0;
	
	switch (option) {

	case TELOPT_ECHO:
		p[0] = IAC;
		p[1] = CMD_WONT;
		p[2] = TELOPT_ECHO;

		ret += 3;
		break;

	default:
		p[0] = IAC;
		p[1] = CMD_WONT;
		p[2] = option;

		ret += 3;
		break;
	}

	return ret;
}

int do_option(unsigned char option, char *p)
{
	int ret = 0;
	
	switch (option) {

	case TELOPT_ECHO:
		p[0] = IAC;
		p[1] = CMD_WILL;
		p[2] = TELOPT_ECHO;

		ret += 3;
		break;

	default:
		p[0] = IAC;
		p[1] = CMD_WONT;
		p[2] = option;

		ret += 3;
		break;
	}

	return ret;
}

int process_request(char *req, int len, char *resp, int size)
{
	int i = 0;
	int ret = 0;
	char *p;
	unsigned char c;
	static int state = TS_DATA;

	p = resp;
	
	while (i < len){
		
		c = req[i];
		
		switch (state){
			
		case TS_CR:
			state = TS_DATA;
			/* Strip off \n or \0 after a \r */
			if ((c == 0) || (c == '\n')) {
				sh_exe(ds_all(), &p);
				printk(KERN_INFO KTELNETD_STRING "%s %d\n", resp, (p-resp));
				SendBuffer(nsock, resp, (p-resp));
				break;
			}
			/* FALL THROUGH */

		case TS_DATA:
			if (c == IAC) {
				state = TS_IAC;
				break;
			}
			if (c == '\r'){
				state = TS_CR;
				break;
			}
			
			ds_push(c);
			
			break;

		case TS_IAC:
			switch (c) {

			/*
			 * Send the process on the pty side an
			 * interrupt.  Do this with a NULL or
			 * interrupt char; depending on the tty mode.
			 */
			case IP:
				break;

			case BREAK:
				break;

			/*
			 * Are You There?
			 */
			case AYT:
				break;

			/*
			 * Abort Output
			 */
			case AO:
				break;

			/*
			 * Erase Character and
			 * Erase Line
			 */
			case EC:
			case EL: 
				break;

			/*
			 * Check for urgent data...
			 */
			case DM:
				break;

			/*
			 * Begin option subnegotiation...
			 */
			case CMD_SB:
				state = TS_SB;
				break;

			case CMD_WILL:
				state = TS_WILL;
				break;

			case CMD_WONT:
				state = TS_WONT;
				break;

			case CMD_DO:
				state = TS_DO;
				break;

			case CMD_DONT:
				state = TS_DONT;
				break;

			case IAC:
				ds_push(IAC);
				break;
			}
			
			state = TS_DATA;
			break;

		case TS_SB:
			if (c == IAC) {
				state = TS_SE;
			}
			break;

		case TS_SE:
			break;

		case TS_WILL:
			ret = will_option(c, p); p += ret;
			state = TS_DATA;
			break;

		case TS_WONT:
			ret = wont_option(c, p); p += ret;
			state = TS_DATA;
			break;

		case TS_DO:
			ret = do_option(c, p); p += ret;
			state = TS_DATA;
			
			break;

		case TS_DONT:
			ret = dont_option(c, p);  p += ret;
			state = TS_DATA;
			break;

		default:
			printk("telnetd: panic state=%d\n", state);
		}
		
		i++;
	}

	return (p - resp);
}


#if 0
int send_sync_buf (struct socket *sock, const char *buf, 
                   const size_t length, unsigned long flags)
{
    struct msghdr msg;
    struct iovec iov;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name     = 0;
    msg.msg_namelen  = 0;
    msg.msg_iov      = &iov;
    msg.msg_iovlen   = 1;
    msg.msg_control  = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags    = flags;

    oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
    msg.msg_iov->iov_len = left;
    msg.msg_iov->iov_base = (char *) buf + written;

    len = sock_sendmsg(sock, &msg, left);
    if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && 
         (len == -EAGAIN)))
        goto repeat_send;
    if (len > 0) {
        written += len;
        left -= len;
        if (left)
            goto repeat_send;
    }
    set_fs(oldmm);
    return written ? written : len;
}

int send_reply(struct socket *sock, char *str, int len)
{   
    return send_sync_buf(sock, str, len, MSG_DONTWAIT);
}

int ktelnetd_recv(struct socket *sock, char *str)
{       mm_segment_t oldmm;
        struct msghdr msg;
        struct iovec iov;
        int len;
        int max_size = SNDBUF;

        msg.msg_name     = 0;
        msg.msg_namelen  = 0;
        msg.msg_iov      = &iov;
        msg.msg_iovlen   = 1;
        msg.msg_control  = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags    = 0;
        
        msg.msg_iov->iov_base = str;
        msg.msg_iov->iov_len  = max_size;
        
        oldmm = get_fs(); set_fs(KERNEL_DS);

read_again:
        len = sock_recvmsg(sock, &msg, max_size, 0); /*MSG_DONTWAIT); */
        if (len == -EAGAIN || len == -ERESTARTSYS) {
            goto read_again;
        }
        set_fs(oldmm);
        return len;
}

int reply_response(struct socket *sock, char *buf, int len)
{
	return send_reply(sock, buf, len);
}

int ktelnetd(void *thdata)
{
    struct sockaddr_in  daddr;
    struct socket *data = NULL;
    struct socket *new_sock = NULL;

	char rcv_buf[SNDBUF];
	char snd_buf[SNDBUF];
	
    int r = -1;
    
    char *a;
    char address[128];
    int len = 0;
 
    r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &data);
    if (r < 0) {
        printk(KERN_ERR KTELNETD_STRING "error %d creating data socket.\n", r);
        goto err;
    }
    memset(&daddr,0, sizeof(daddr));
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(KTELNETD_PORT);
    daddr.sin_addr.s_addr= htonl(INADDR_ANY);
    r = data->ops->bind(data, (struct sockaddr *)&daddr, sizeof (daddr));
    if(r < 0) {
        printk(KERN_ERR KTELNETD_STRING "error %d binding data socket.\n", r);
        goto err2;
    }
    
    r = data->ops->listen(data, 1);
    if(r < 0) {
        printk(KERN_ERR KTELNETD_STRING "error %d listening in data socket.\n", r);
        goto err2;
    }
   
    a = (char *)&daddr.sin_addr;

    new_sock = sock_alloc();
    if (!new_sock)
        goto err2;
    new_sock->type = data->type;
    new_sock->ops = data->ops;

    r = data->ops->accept(data, new_sock, 0);
    if (r < 0) {
        printk("Error accepting connection on data socket\n");
        goto err3;
    }

    new_sock->ops->getname(new_sock, (struct sockaddr *)address, &len, 2);
    a = (char *)&(((struct sockaddr_in *)address)->sin_addr.s_addr);
    printk("Connection from %d.%d.%d.%d\n", a[0], a[1], a[2], a[3]);

 	while (len=ktelnetd_recv(new_sock, rcv_buf)){
		r = process_request(rcv_buf, len, snd_buf, SNDBUF);
		strcat(snd_buf, KTELNETD_PROMTE);
		r += strlen(KTELNETD_PROMTE);
		reply_response(new_sock, snd_buf, r);
	}
	
    sock_release(new_sock);
    sock_release(data);
    return 0;

err3:
    sock_release(new_sock);
err2:
    sock_release(data);
err:
    return -1;
}

#endif 



/*
Sendbuffer sends "Length" bytes from "Buffer" through the socket "sock".
*/

size_t SendBuffer(struct socket *sock, const char *Buffer, size_t Length)
{
	struct msghdr msg;
	mm_segment_t oldfs; // mm_segment_t is just a long
	struct iovec iov; // structure containing a base addr. and length
	int len2;

	//printk("Entering SendBuffer\n");


	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1; //point to be noted
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg.msg_flags = MSG_NOSIGNAL;//0/*MSG_DONTWAIT*/;

	iov.iov_base = (char*) Buffer; // as we know that iovec is
	iov.iov_len = (__kernel_size_t) Length; // nothing but a base addr and length



	// #define get_fs() (current_thread_info()->addr_limit)
	// similar for set_fs;
	/*
	Therefore this line sets the "fs" to KERNEL_DS and saves its old value
	*/
	oldfs = get_fs(); set_fs(KERNEL_DS);

	/* Actual Sending of the Message */
	len2 = sock_sendmsg(sock,&msg,(size_t)(Length));

	/* retrieve the old value of fs (whatever it is)*/
	set_fs(oldfs);


	return len2;
}


/*
Recieves data from the socket "sock" and puts it in the 'Buffer'.
Returns the length of data recieved

The Calling function must do a:
Buffer = (char*) get_free_page(GFP_KERNEL);
or a kmalloc to allocate kernel's memory
(or it can use the kernel's stack space [very small] )

*/


size_t RecvBuffer(struct socket *sock, const char *Buffer, size_t Length)
{
	struct msghdr msg;
	struct iovec iov;

	int len;
	mm_segment_t oldfs;

	/* Set the msghdr structure*/
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	/* Set the iovec structure*/
	iov.iov_base = (void *) &Buffer[0];
	iov.iov_len = (size_t)Length;

	/* Recieve the message */
	oldfs = get_fs(); set_fs(KERNEL_DS);
	len = sock_recvmsg(sock,&msg,Length,0/*MSG_DONTWAIT*/); // let it wait if there is no message
	set_fs(oldfs);

	// if ((len!=-EAGAIN)&&(len!=0))
	// printk("RecvBuffer Recieved %i bytes \n",len);

	return len;
}



/*
Sets up a server-side socket

1. Create a new socket
2. Bind the address to the socket
3. Start listening on the socket
*/

struct socket* set_up_server_socket(int port_no) 
{
	struct socket *sock;
	struct sockaddr_in sin;

	int error;

	/* First create a socket */
	error = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP,&sock) ;
	if (error<0){
		printk(KERN_INFO KTELNETD_STRING "Error during creation of socket; terminating\n");
		return 0;
	}

	/* Now bind the socket */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port_no);

	error = sock->ops->bind(sock,(struct sockaddr*)&sin,sizeof(sin));
	if (error<0){
		printk(KERN_INFO KTELNETD_STRING "Error binding socket \n");
		return 0;
	}



	/* Now, start listening on the socket */
	error=sock->ops->listen(sock,32);
	if (error!=0){
		printk(KERN_INFO KTELNETD_STRING "Error listening on socket \n");
		return 0;
	}
	
	/* Now start accepting */
	// Accepting is performed by the function server_accept_connection

	return sock;
}


/*

Accepts a new connection (server calls this function)

1. Create a new socket
2. Call socket->ops->accept
3. return the newly created socket

*/

struct socket* server_accept_connection(struct socket *sock) 
{
	struct socket * newsock;
	int error;

	/* Before accept: Clone the socket */

	error = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP,&newsock);
	if (error<0){
		printk(KERN_INFO KTELNETD_STRING "Error during creation of the other socket; terminating\n");
	}

	newsock->type = sock->type;
	newsock->ops=sock->ops;

	/* Do the actual accept */

	error = newsock->ops->accept(sock,newsock,0);


	if (error<0) {
		printk(KERN_INFO KTELNETD_STRING "Error accepting socket\n") ;
		return 0;
	}
	
	return newsock;
}

struct socket * set_up_client_socket(unsigned int IP_addr, int port_no)
{
	struct socket * clientsock;
	struct sockaddr_in sin;
	int error, i;

	/* First create a socket */
	error = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP,&clientsock);
	if (error<0) {
	printk(KERN_INFO KTELNETD_STRING "Error during creation of socket; terminating\n");
	return 0;
	}

	/* Now bind and connect the socket */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IP_addr);
	sin.sin_port = htons(port_no);

	for(i=0;i<10;i++) {
		error = clientsock->ops->connect(clientsock,(struct sockaddr*)&sin,sizeof(sin),0);
		if (error<0) {
			printk(KERN_INFO KTELNETD_STRING "Error connecting client socket to server: %i, retrying .. %d \n",error, i);
			if(i==10-1) {
				printk(KERN_INFO KTELNETD_STRING "Giving Up!\n"); 
				return 0;
			}
		}
	else 
		break; //connected
	}

	return clientsock;
}


int ktelnetd(void *thdata)
{
	char rcvbuf[1024];
	char sndbuf[1024];
	int len, r;
	
	printk(KERN_INFO KTELNETD_STRING "set_up_server_socket start\n");
	sock = set_up_server_socket(KTELNETD_PORT);
	if (sock == NULL){
		printk(KERN_INFO KTELNETD_STRING "set_up_server_socket fail\n");
		return 0;
	}

	printk(KERN_INFO KTELNETD_STRING "server_accept_connection start\n");
	nsock = server_accept_connection(sock);

	strcpy(sndbuf, KTELNETD_WELCOME);
	r = strlen(KTELNETD_WELCOME);
	strcat(sndbuf, KTELNETD_PROMTE);
	r += strlen(KTELNETD_PROMTE);
	SendBuffer(nsock, sndbuf, r);

	while (len=RecvBuffer(nsock, rcvbuf, sizeof(rcvbuf))){
		r = process_request(rcvbuf, len, sndbuf, sizeof(sndbuf));
	}
	
	return 0;	
}

static int ktelnetd_init(void)
{
    printk(KERN_INFO KTELNETD_STRING "Starting ktelnetd server module\n");

    memset(data_stack, 0, sizeof(data_stack));

	printk(KERN_INFO KTELNETD_STRING "kthread_run\n");
    kthread_run(ktelnetd, NULL, "ktelnetd/%d", 1);

    return 0;
}

static void ktelnetd_exit(void)
{
    printk(KERN_INFO KTELNETD_STRING "Cleaning up ktelnetd module, bye !\n");
    sock_release(nsock);
    sock_release(sock);
	
} 

module_init(ktelnetd_init);
module_exit(ktelnetd_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert Young");
