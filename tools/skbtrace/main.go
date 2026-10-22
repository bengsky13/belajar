package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	Kind             uint32
	TGID             uint32
	TID              uint32
	Pad              uint32
	SKB              uint64
	Head             uint64
	Data             uint64
	Len              uint32
	DataLen          uint32
	HeadLen          uint32
	DataOffset       uint32
	TailOffset       uint32
	EndOffset        uint32
	TaskFragPage     uint64
	TaskFragOffset   uint32
	TaskFragSize     uint32
	TaskFragRefcount int32
	TaskFragPad      uint32
	NetworkHeader    uint16
	TransportHeader  uint16
	CsumStart        uint16
	CsumOffset       uint16
	Page             uint64
	PageRefcount     int32
	PagePad          uint32
	PageOrder        uint32
	PageMigratetype  int32
	PageGFP          uint64
	PCPCount         int32
	PCPHigh          int32
	PCPHighMin       int32
	PCPHighMax       int32
	PCPBatch         int32
	PCPFreeCount     int32
	PCPFlags         uint8
	PCPAllocFactor   uint8
	PCPPad           uint16
	Packet           [64]byte
	Tail             [128]byte
	Shinfo           [96]byte
	SKBObject        [96]byte
	CoalesceAlignPad uint32
	CoalesceFrom     uint64
	CoalesceResult   int32
	CoalescePad      uint32
}

type objects struct {
	TraceNetDevQueue          *ebpf.Program `ebpf:"trace_net_dev_queue"`
	TraceNetDevStartXmit      *ebpf.Program `ebpf:"trace_net_dev_start_xmit"`
	TraceKfreeSKB             *ebpf.Program `ebpf:"trace_kfree_skb"`
	TraceNetifReceiveSKB      *ebpf.Program `ebpf:"trace_netif_receive_skb"`
	TracePutPage              *ebpf.Program `ebpf:"trace_put_page"`
	TraceSKBTryCoalesceEntry  *ebpf.Program `ebpf:"trace_skb_try_coalesce_entry"`
	TraceSKBTryCoalesceReturn *ebpf.Program `ebpf:"trace_skb_try_coalesce_return"`
	TraceMMPagePCPUDrain      *ebpf.Program `ebpf:"trace_mm_page_pcpu_drain"`
	TraceFreeFrozenPageCommit *ebpf.Program `ebpf:"trace_free_frozen_page_commit"`
	TraceMMPageAlloc          *ebpf.Program `ebpf:"trace_mm_page_alloc"`
	Events                    *ebpf.Map     `ebpf:"events"`
	CoalesceCalls             *ebpf.Map     `ebpf:"coalesce_calls"`
}

func (o *objects) Close() {
	if o.TraceNetDevQueue != nil {
		o.TraceNetDevQueue.Close()
	}
	if o.TraceNetDevStartXmit != nil {
		o.TraceNetDevStartXmit.Close()
	}
	if o.TraceKfreeSKB != nil {
		o.TraceKfreeSKB.Close()
	}
	if o.TraceNetifReceiveSKB != nil {
		o.TraceNetifReceiveSKB.Close()
	}
	if o.TracePutPage != nil {
		o.TracePutPage.Close()
	}
	if o.TraceSKBTryCoalesceEntry != nil {
		o.TraceSKBTryCoalesceEntry.Close()
	}
	if o.TraceSKBTryCoalesceReturn != nil {
		o.TraceSKBTryCoalesceReturn.Close()
	}
	if o.TraceMMPagePCPUDrain != nil {
		o.TraceMMPagePCPUDrain.Close()
	}
	if o.TraceFreeFrozenPageCommit != nil {
		o.TraceFreeFrozenPageCommit.Close()
	}
	if o.TraceMMPageAlloc != nil {
		o.TraceMMPageAlloc.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	if o.CoalesceCalls != nil {
		o.CoalesceCalls.Close()
	}
}

func main() {
	objPath := flag.String("object", "trace.bpf.o", "compiled BPF object")
	duration := flag.Duration("duration", 30*time.Second, "maximum trace duration")
	putPage := flag.Bool("put-page", false, "attach the lab-only put_page kprobe")
	coalesce := flag.Bool("coalesce", false, "attach lab-only skb_try_coalesce entry/return probes")
	pcpDrain := flag.Bool("pcp-drain", false, "attach the mm_page_pcpu_drain raw tracepoint")
	pcpCommit := flag.Bool("pcp-commit", false, "attach the free_frozen_page_commit kprobe")
	pageAlloc := flag.Bool("page-alloc", false, "trace order-0 UNMOVABLE mm_page_alloc events")
	noNet := flag.Bool("no-net", false, "do not attach the four high-volume skb raw tracepoints")
	interesting := flag.Bool("interesting", false, "print only jumbo skb events and short events with a live task_frag pointer")
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

	if !*noNet {
		queueLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "net_dev_queue", Program: objs.TraceNetDevQueue,
		})
		if err != nil {
			log.Fatalf("attach net_dev_queue raw tracepoint: %v", err)
		}
		defer queueLink.Close()
		xmitLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "net_dev_start_xmit", Program: objs.TraceNetDevStartXmit,
		})
		if err != nil {
			log.Fatalf("attach net_dev_start_xmit raw tracepoint: %v", err)
		}
		defer xmitLink.Close()
		kfreeLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "kfree_skb", Program: objs.TraceKfreeSKB,
		})
		if err != nil {
			log.Fatalf("attach kfree_skb raw tracepoint: %v", err)
		}
		defer kfreeLink.Close()
		receiveLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "netif_receive_skb", Program: objs.TraceNetifReceiveSKB,
		})
		if err != nil {
			log.Fatalf("attach netif_receive_skb raw tracepoint: %v", err)
		}
		defer receiveLink.Close()
	}
	var putPageLink link.Link
	if *putPage {
		putPageLink, err = link.Kprobe("put_page", objs.TracePutPage, nil)
		if err != nil {
			log.Fatalf("attach put_page kprobe: %v", err)
		}
		defer putPageLink.Close()
	}
	var coalesceEntryLink, coalesceReturnLink link.Link
	if *coalesce {
		coalesceEntryLink, err = link.Kprobe("skb_try_coalesce", objs.TraceSKBTryCoalesceEntry, nil)
		if err != nil {
			log.Fatalf("attach skb_try_coalesce kprobe: %v", err)
		}
		defer coalesceEntryLink.Close()
		coalesceReturnLink, err = link.Kretprobe("skb_try_coalesce", objs.TraceSKBTryCoalesceReturn, nil)
		if err != nil {
			log.Fatalf("attach skb_try_coalesce kretprobe: %v", err)
		}
		defer coalesceReturnLink.Close()
	}
	var pcpDrainLink link.Link
	if *pcpDrain {
		pcpDrainLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "mm_page_pcpu_drain", Program: objs.TraceMMPagePCPUDrain,
		})
		if err != nil {
			log.Fatalf("attach mm_page_pcpu_drain raw tracepoint: %v", err)
		}
		defer pcpDrainLink.Close()
	}
	var pcpCommitLink link.Link
	if *pcpCommit {
		pcpCommitLink, err = link.Kprobe("free_frozen_page_commit", objs.TraceFreeFrozenPageCommit, nil)
		if err != nil {
			log.Fatalf("attach free_frozen_page_commit kprobe: %v", err)
		}
		defer pcpCommitLink.Close()
	}
	var pageAllocLink link.Link
	if *pageAlloc {
		pageAllocLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "mm_page_alloc", Program: objs.TraceMMPageAlloc,
		})
		if err != nil {
			log.Fatalf("attach mm_page_alloc raw tracepoint: %v", err)
		}
		defer pageAllocLink.Close()
	}

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
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			log.Fatalf("read ring buffer: %v", err)
		}
		var ev event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		if ev.Kind == 5 {
			fmt.Printf("event=put_page tgid=%d tid=%d page=%#x refcount_before=%d\n",
				ev.TGID, ev.TID, ev.Page, ev.PageRefcount)
			continue
		}
		if ev.Kind == 6 {
			fmt.Printf("event=skb_try_coalesce tgid=%d tid=%d result=%d to=%#x from=%#x head=%#x len=%d data_len=%d end=%d task_frag_page=%#x task_frag_refcount=%d nr_frags=%d\n",
				ev.TGID, ev.TID, ev.CoalesceResult, ev.SKB, ev.CoalesceFrom, ev.Head,
				ev.Len, ev.DataLen, ev.EndOffset, ev.TaskFragPage, ev.TaskFragRefcount, ev.Shinfo[2])
			for i := 0; i < min(int(ev.Shinfo[2]), 3); i++ {
				off := 48 + i*16
				fmt.Printf("  frag=%d netmem=%#x len=%d offset=%d\n", i,
					binary.LittleEndian.Uint64(ev.Shinfo[off:off+8]),
					binary.LittleEndian.Uint32(ev.Shinfo[off+8:off+12]),
					binary.LittleEndian.Uint32(ev.Shinfo[off+12:off+16]))
			}
			continue
		}
		if ev.Kind == 7 {
			fmt.Printf("event=mm_page_pcpu_drain tgid=%d tid=%d page=%#x order=%d migratetype=%d refcount=%d\n",
				ev.TGID, ev.TID, ev.Page, ev.PageOrder, ev.PageMigratetype, ev.PageRefcount)
			continue
		}
		if ev.Kind == 8 {
			fmt.Printf("event=free_frozen_page_commit tgid=%d tid=%d page=%#x order=%d migratetype=%d refcount=%d pcp_count=%d high=%d high_min=%d high_max=%d batch=%d free_count=%d flags=%#x alloc_factor=%d\n",
				ev.TGID, ev.TID, ev.Page, ev.PageOrder, ev.PageMigratetype, ev.PageRefcount,
				ev.PCPCount, ev.PCPHigh, ev.PCPHighMin, ev.PCPHighMax, ev.PCPBatch,
				ev.PCPFreeCount, ev.PCPFlags, ev.PCPAllocFactor)
			continue
		}
		if ev.Kind == 9 {
			fmt.Printf("event=mm_page_alloc tgid=%d tid=%d page=%#x order=%d migratetype=%d gfp=%#x refcount=%d\n",
				ev.TGID, ev.TID, ev.Page, ev.PageOrder, ev.PageMigratetype, ev.PageGFP, ev.PageRefcount)
			continue
		}
		if *interesting && ev.Len < 30000 && !(ev.TaskFragPage != 0 && ev.Len < 128) {
			continue
		}
		fmt.Printf("event=%s tgid=%d tid=%d skb=%#x head=%#x data=%#x len=%d data_len=%d head_len=%d data_off=%d tail=%d end=%d task_frag_page=%#x task_frag_off=%d task_frag_size=%d task_frag_refcount=%d net=%d trans=%d csum_start=%d csum_offset=%d\n",
			kindName(ev.Kind), ev.TGID, ev.TID, ev.SKB, ev.Head, ev.Data, ev.Len, ev.DataLen,
			ev.HeadLen, ev.DataOffset, ev.TailOffset, ev.EndOffset, ev.TaskFragPage, ev.TaskFragOffset, ev.TaskFragSize, ev.TaskFragRefcount, ev.NetworkHeader, ev.TransportHeader,
			ev.CsumStart, ev.CsumOffset)
		fmt.Printf("  packet=%s\n", hex.EncodeToString(ev.Packet[:]))
		fmt.Printf("  tail=%s\n", hex.EncodeToString(ev.Tail[:]))
		fmt.Printf("  shinfo=%s\n", hex.EncodeToString(ev.Shinfo[:]))
		fmt.Printf("  skb_object=%s\n", hex.EncodeToString(ev.SKBObject[:]))
	}
}

func kindName(kind uint32) string {
	switch kind {
	case 1:
		return "net_dev_queue"
	case 2:
		return "net_dev_start_xmit"
	case 3:
		return "kfree_skb"
	case 4:
		return "netif_receive_skb"
	case 5:
		return "put_page"
	case 6:
		return "skb_try_coalesce"
	case 7:
		return "mm_page_pcpu_drain"
	case 8:
		return "free_frozen_page_commit"
	case 9:
		return "mm_page_alloc"
	default:
		return fmt.Sprintf("unknown_%d", kind)
	}
}
