package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Kind            uint32
	PID             uint32
	SKB             uint64
	Head            uint64
	Data            uint64
	Len             uint32
	DataLen         uint32
	HeadLen         uint32
	DataOffset      uint32
	NetworkHeader   uint16
	TransportHeader uint16
	CsumStart       uint16
	CsumOffset      uint16
	Packet          [64]byte
	Tail            [64]byte
}

type objects struct {
	TraceIPDoFragment *ebpf.Program `ebpf:"trace_ip_do_fragment"`
	TraceCsumEnter    *ebpf.Program `ebpf:"trace_csum_enter"`
	TraceCsumExit     *ebpf.Program `ebpf:"trace_csum_exit"`
	ActiveCsum        *ebpf.Map     `ebpf:"active_csum"`
	Events            *ebpf.Map     `ebpf:"events"`
}

func (o *objects) Close() {
	if o.TraceIPDoFragment != nil {
		o.TraceIPDoFragment.Close()
	}
	if o.TraceCsumEnter != nil {
		o.TraceCsumEnter.Close()
	}
	if o.TraceCsumExit != nil {
		o.TraceCsumExit.Close()
	}
	if o.ActiveCsum != nil {
		o.ActiveCsum.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
}

func main() {
	objPath := flag.String("object", "trace.bpf.o", "compiled BPF object")
	duration := flag.Duration("duration", 30*time.Second, "maximum trace duration")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: remove memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("load BPF spec: %v", err)
	}
	var objs objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	fragmentLink, err := link.KprobeMulti(objs.TraceIPDoFragment,
		link.KprobeMultiOptions{Symbols: []string{"ip_do_fragment"}})
	if err != nil {
		log.Fatalf("attach ip_do_fragment kprobe-multi: %v", err)
	}
	defer fragmentLink.Close()
	csumEnterLink, err := link.KprobeMulti(objs.TraceCsumEnter,
		link.KprobeMultiOptions{Symbols: []string{"skb_checksum_help"}})
	if err != nil {
		log.Fatalf("attach skb_checksum_help kprobe-multi: %v", err)
	}
	defer csumEnterLink.Close()
	csumExitLink, err := link.KretprobeMulti(objs.TraceCsumExit,
		link.KprobeMultiOptions{Symbols: []string{"skb_checksum_help"}})
	if err != nil {
		log.Fatalf("attach skb_checksum_help kretprobe-multi: %v", err)
	}
	defer csumExitLink.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer: %v", err)
	}
	defer reader.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	timer := time.AfterFunc(*duration, func() { reader.Close() })
	defer timer.Stop()
	go func() {
		<-stop
		reader.Close()
	}()

	fmt.Printf("skbtrace: attached object=%s duration=%s\n", *objPath, *duration)
	for {
		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Fatalf("read ring buffer: %v", err)
		}
		var ev event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		fmt.Printf("event=%s pid=%d skb=%#x head=%#x data=%#x len=%d data_len=%d head_len=%d data_off=%d net=%d trans=%d csum_start=%d csum_offset=%d\n",
			kindName(ev.Kind), ev.PID, ev.SKB, ev.Head, ev.Data, ev.Len, ev.DataLen,
			ev.HeadLen, ev.DataOffset, ev.NetworkHeader, ev.TransportHeader,
			ev.CsumStart, ev.CsumOffset)
		fmt.Printf("  packet=%s\n", hex.EncodeToString(ev.Packet[:]))
		fmt.Printf("  tail=%s\n", hex.EncodeToString(ev.Tail[:]))
	}
}

func kindName(kind uint32) string {
	switch kind {
	case 1:
		return "ip_fragment"
	case 2:
		return "csum_enter"
	case 3:
		return "csum_exit"
	default:
		return fmt.Sprintf("unknown_%d", kind)
	}
}
