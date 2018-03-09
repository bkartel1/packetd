package example

import "fmt"
import "sync"
import "encoding/hex"

import "github.com/untangle/packetd/support"

func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "example")
	childsync.Add(1)
}

func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "example")
	childsync.Done()
}

func Plugin_netfilter_handler(buffer []byte, length int) {
	fmt.Println(hex.Dump(buffer))
}

func Plugin_conntrack_handler(tracker *support.Tracker) {
	fmt.Printf("OSA:%d RSA:%d ODA:%d RDA:%d OSP:%d RSP:%d ODP:%d RDP:%d OP:%d RP:%d\n",
		tracker.Orig_src_addr,
		tracker.Repl_src_addr,
		tracker.Orig_dst_addr,
		tracker.Repl_dst_addr,
		tracker.Orig_src_port,
		tracker.Repl_src_port,
		tracker.Orig_dst_port,
		tracker.Repl_dst_port,
		tracker.Orig_protocol,
		tracker.Repl_protocol)
}
