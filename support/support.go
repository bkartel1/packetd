package support

import "fmt"
import "time"

var runtime time.Time = time.Now()

/*---------------------------------------------------------------------------*/
type Tracker struct {
	Orig_src_addr uint
	Repl_src_addr uint

	Orig_dst_addr uint
	Repl_dst_addr uint

	Orig_src_port uint
	Repl_src_port uint

	Orig_dst_port uint
	Repl_dst_port uint

	Orig_protocol uint
	Repl_protocol uint
}

/*---------------------------------------------------------------------------*/
func LogMessage(format string, args ...interface{}) {
	nowtime := time.Now()
	var elapsed = nowtime.Sub(runtime)

	if len(args) == 0 {
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), format)
	} else {
		buffer := fmt.Sprintf(format, args)
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), buffer)
	}
}

/*---------------------------------------------------------------------------*/
