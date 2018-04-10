package example

import "fmt"
import "sync"
import "encoding/hex"

import "github.com/untangle/packetd/support"

/*---------------------------------------------------------------------------*/
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "example")
	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "example")
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
func Plugin_netfilter_handler(ch chan<- int32,buffer []byte, length int) {
	fmt.Println(hex.Dump(buffer))

	// use the channel to return our mark bits
	ch <- 1
}

/*---------------------------------------------------------------------------*/
func Plugin_conntrack_handler(tracker *support.Tracker) {
	fmt.Printf("CONNTRACK OSA:%s RSA:%s ODA:%s RDA:%s OSP:%d RSP:%d ODP:%d RDP:%d OP:%d RP:%d\n",
		support.Int2Ip(tracker.Orig_src_addr),
		support.Int2Ip(tracker.Repl_src_addr),
		support.Int2Ip(tracker.Orig_dst_addr),
		support.Int2Ip(tracker.Repl_dst_addr),
		tracker.Orig_src_port,
		tracker.Repl_src_port,
		tracker.Orig_dst_port,
		tracker.Repl_dst_port,
		tracker.Orig_protocol,
		tracker.Repl_protocol)
}

/*---------------------------------------------------------------------------*/
func Plugin_netlogger_handler(logger *support.Logger) {
	fmt.Printf("NETLOGGER PROTO:%d ICMP:%d SIF:%d DIF:%d SADR:%s DADR:%s SPORT:%d DPORT:%d MARK:%X PREFIX:%s\n",
		logger.Protocol,
		logger.IcmpType,
		logger.SrcIntf,
		logger.DstIntf,
		support.Int2Ip(logger.SrcAddr),
		support.Int2Ip(logger.DstAddr),
		logger.SrcPort,
		logger.DstPort,
		logger.Mark,
		logger.Prefix)
}

/*---------------------------------------------------------------------------*/
