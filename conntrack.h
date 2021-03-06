/**
 * conntrack.h
 *
 * Handles receiving conntrack updates for the Untnagle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

/*--------------------------------------------------------------------------*/
struct conntrack_info
{
	u_int8_t	msg_type;
	u_int32_t	orig_saddr,repl_saddr;
	u_int32_t	orig_daddr,repl_daddr;
	u_int16_t	orig_sport,repl_sport;
	u_int16_t	orig_dport,repl_dport;
	u_int8_t	orig_proto,repl_proto;
};
/*--------------------------------------------------------------------------*/
extern void go_conntrack_callback(struct conntrack_info* info);
extern void go_child_startup(void);
extern void go_child_goodbye(void);
/*--------------------------------------------------------------------------*/
static struct nfct_handle	*nfcth;
static u_int64_t			tracker_error;
static u_int64_t			tracker_unknown;
/*--------------------------------------------------------------------------*/
static int conntrack_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)
{
struct conntrack_info	info;

	switch(type)
	{
		case NFCT_T_NEW:
		case NFCT_T_UPDATE:
		case NFCT_T_DESTROY:
			break;

		case NFCT_T_ERROR:
			tracker_error++;
			return(NFCT_CB_CONTINUE);

		default:
			tracker_unknown++;
			return(NFCT_CB_CONTINUE);
	}

info.msg_type = type;
info.orig_proto = nfct_get_attr_u8(ct,ATTR_ORIG_L4PROTO);
info.repl_proto = nfct_get_attr_u8(ct,ATTR_REPL_L4PROTO);

	if (info.orig_proto != info.repl_proto)
	{
	logmessage(LOG_WARNING,"Protocol mismatch %d != %d in conntrack handler\n",info.orig_proto,info.repl_proto);
	return(NFCT_CB_CONTINUE);
	}

// ignore everything except TCP and UDP
if ((info.orig_proto != IPPROTO_TCP) && (info.orig_proto != IPPROTO_UDP)) return(NFCT_CB_CONTINUE);

// get all of the source and destination addresses
info.orig_saddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
info.orig_daddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);
info.repl_saddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC);
info.repl_daddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST);

// ignore anything on the loopback interface by looking at the least
// significant byte because these values are in network byte order
if ((info.orig_saddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);
if ((info.orig_daddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);
if ((info.repl_saddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);
if ((info.repl_daddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);

// get all of the source and destination ports
info.orig_sport = ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC));
info.orig_dport = ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST));
info.repl_sport = ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC));
info.repl_dport = ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST));

go_conntrack_callback(&info);

return(NFCT_CB_CONTINUE);
}
/*--------------------------------------------------------------------------*/
static int conntrack_startup(void)
{
int		ret;

// Open a netlink conntrack handle. The header file defines
// NFCT_ALL_CT_GROUPS but we really only care about new and
// destroy so we subscribe to just those ignoring update
nfcth = nfct_open(CONNTRACK,NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY);

	if (nfcth == NULL)
	{
	logmessage(LOG_ERR,"Error %d returned from nfct_open()\n",errno);
	g_shutdown = 1;
	return(1);
	}

// register the conntrack callback
ret = nfct_callback_register(nfcth,NFCT_T_ALL,conntrack_callback,NULL);

	if (ret != 0)
	{
	logmessage(LOG_ERR,"Error %d returned from nfct_callback_register()\n",errno);
	g_shutdown = 1;
	return(2);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
static void conntrack_shutdown(void)
{
// unregister the callback handler
nfct_callback_unregister(nfcth);

// close the conntrack netlink handler
nfct_close(nfcth);
}
/*--------------------------------------------------------------------------*/
static int conntrack_thread(void)
{
int		ret;

logmessage(LOG_INFO,"The conntrack thread is starting\n");

// call our conntrack startup function
ret = conntrack_startup();

	if (ret != 0)
	{
	logmessage(LOG_ERR,"Error %d returned from conntrack_startup()\n",ret);
	g_shutdown = 1;
	return(1);
	}

go_child_startup();

	// the nfct_catch function should only return if it receives a signal
	// other than EINTR or if NFCT_CB_STOP is returned from the callback
	while (g_shutdown == 0)
	{
	nfct_catch(nfcth);
	}

// call our conntrack shutdown function
conntrack_shutdown();

logmessage(LOG_INFO,"The conntrack thread has terminated\n");
go_child_goodbye();
return(0);
}
/*--------------------------------------------------------------------------*/
static void conntrack_goodbye(void)
{
int		value;

g_shutdown = 1;
if (nfcth == NULL) return;

value = AF_INET;
nfct_send(nfcth,NFCT_Q_DUMP,&value);
}
/*--------------------------------------------------------------------------*/
