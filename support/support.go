package support

import "fmt"
import "net"
import "time"

var runtime time.Time = time.Now()

/*---------------------------------------------------------------------------*/
type Tracker struct {
	Orig_src_addr uint32
	Repl_src_addr uint32

	Orig_dst_addr uint32
	Repl_dst_addr uint32

	Orig_src_port uint16
	Repl_src_port uint16

	Orig_dst_port uint16
	Repl_dst_port uint16

	Orig_protocol uint8
	Repl_protocol uint8
}

/*---------------------------------------------------------------------------*/
type Logger struct {
	Protocol 	uint8
	IcmpType	uint16
	SrcIntf		uint8
	DstIntf		uint8
	SrcAddr		uint32
	DstAddr		uint32
	SrcPort		uint16
	DstPort		uint16
	Mark		uint32
	Prefix		string
}

/*---------------------------------------------------------------------------*/
func LogMessage(format string, args ...interface{}) {
	nowtime := time.Now()
	var elapsed = nowtime.Sub(runtime)

	if len(args) == 0 {
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), buffer)
	}
}

/*---------------------------------------------------------------------------*/
func Int2Ip(value uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(value)
	ip[1] = byte(value >>8)
	ip[2] = byte(value >>16)
	ip[3] = byte(value >> 24)
	return(ip)
}

/*---------------------------------------------------------------------------*/
