package main

//#include "common.h"
//#include "netfilter.h"
//#include "conntrack.h"
//#cgo LDFLAGS: -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack
import "C"

import "os"
import "time"
import "sync"
import "bufio"
import "unsafe"
import "github.com/untangle/packetd/support"
import "github.com/untangle/packetd/example"

/*---------------------------------------------------------------------------*/
var childsync sync.WaitGroup

/*---------------------------------------------------------------------------*/
func main() {
	var counter int
	C.common_startup()

	support.LogMessage("Untangle Packet Daemon Version %s\n", "1.00")

	go C.netfilter_thread()
	go C.conntrack_thread()

	// ********** Call all plugin startup functions here

	go example.Plugin_Startup(&childsync)

	// ********** End of plugin startup functions

	ch := make(chan string)
	go func(ch chan string) {
		reader := bufio.NewReader(os.Stdin)
		for {
			s, err := reader.ReadString('\n')
			if err != nil {
				close(ch)
				return
			}
			ch <- s
		}
		close(ch)
	}(ch)

stdinloop:
	for {
		shutdown := C.get_shutdown_flag()
		if shutdown != 0 {
			break
		}
		select {
		case stdin, ok := <-ch:
			if !ok {
				break stdinloop
			} else {
				support.LogMessage("Console input detected - Application shutting down\n")
				_ = stdin
				break stdinloop
			}
		case <-time.After(1 * time.Second):
			counter++
			support.LogMessage("Waiting for input %d...\n", counter)
		}
	}

	// ********** Call all plugin goodbye functions here

	go example.Plugin_Goodbye(&childsync)

	// ********** End of plugin goodbye functions

	C.netfilter_goodbye()
	C.conntrack_goodbye()
	childsync.Wait()
}

/*---------------------------------------------------------------------------*/
//export go_netfilter_callback
func go_netfilter_callback(data *C.uchar, size C.int) {

	// this version creates a Go copy of the buffer
	//	buffer := C.GoBytes(unsafe.Pointer(data),size)

	// this version creates a Go pointer to the buffer
	buffer := (*[0xFFFF]byte)(unsafe.Pointer(data))[:int(size):int(size)]
	length := int(size)

	// ********** Call all plugin netfilter handler functions here

	go example.Plugin_netfilter_handler(buffer, length)

	// ********** End of plugin netfilter callback functions
}

/*---------------------------------------------------------------------------*/
//export go_conntrack_callback
func go_conntrack_callback(info *C.struct_conntrack_info) {
	var tracker support.Tracker
	tracker.Orig_src_addr = uint(info.orig_saddr)
	tracker.Repl_src_addr = uint(info.repl_saddr)
	tracker.Orig_dst_addr = uint(info.orig_daddr)
	tracker.Repl_dst_addr = uint(info.repl_daddr)
	tracker.Orig_src_port = uint(info.orig_sport)
	tracker.Repl_src_port = uint(info.repl_sport)
	tracker.Orig_dst_port = uint(info.orig_dport)
	tracker.Repl_dst_port = uint(info.repl_dport)
	tracker.Orig_protocol = uint(info.orig_proto)
	tracker.Repl_protocol = uint(info.repl_proto)

	// ********** Call all plugin conntrack handler functions here

	go example.Plugin_conntrack_handler(&tracker)

	// ********** End of plugin netfilter callback functions

}

/*---------------------------------------------------------------------------*/
//export go_child_startup
func go_child_startup() {
	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
//export go_child_goodbye
func go_child_goodbye() {
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
