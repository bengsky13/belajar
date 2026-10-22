package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	kvmIO                    = 0xae
	kvmGetAPIVersion         = 0x00
	kvmCreateVM              = 0x01
	kvmGetVCPUMmapSize       = 0x04
	kvmCreateVCPU            = 0x41
	kvmSetUserMemoryRegionNR = 0x46
	kvmRun                   = 0x80
	kvmSetRegsNR             = 0x82
	kvmGetSregsNR            = 0x83
	kvmSetSregsNR            = 0x84
	kvmExitHLT               = 5
	kvmAPIVersion            = 12
	kvmCodeGPA               = 0x1000
	kvmSparseGPA             = 64 << 20
	kvmSparseMarker          = 0xc7
	kvmAliasMarker           = 0x4d
	iocWrite                 = 1
	iocRead                  = 2
)

type kvmUserspaceMemoryRegion struct {
	Slot          uint32
	Flags         uint32
	GuestPhysAddr uint64
	MemorySize    uint64
	UserspaceAddr uint64
}

type kvmRegs struct {
	Rax, Rbx, Rcx, Rdx uint64
	Rsi, Rdi, Rsp, Rbp uint64
	R8, R9, R10, R11   uint64
	R12, R13, R14, R15 uint64
	Rip, Rflags        uint64
}

type kvmSegment struct {
	Base     uint64
	Limit    uint32
	Selector uint16
	Type     uint8
	Present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	Unusable uint8
	Padding  uint8
}

type kvmDtable struct {
	Base    uint64
	Limit   uint16
	Padding [3]uint16
}

type kvmSregs struct {
	CS, DS, ES, FS, GS, SS  kvmSegment
	TR, LDT                 kvmSegment
	GDT, IDT                kvmDtable
	CR0, CR2, CR3, CR4, CR8 uint64
	EFER, APICBase          uint64
	InterruptBitmap         [4]uint64
}

type kvmVCPU struct {
	fd  int
	run []byte
}

type kvmNPTProbe struct {
	kvmFD     int
	vmFD      int
	memory    []byte
	vcpuFault *kvmVCPU
	vcpuAlias *kvmVCPU
	expected  map[uint64]int
	count     int
	warmEnd   int
	firstEnd  int
}

func kvmIOC(dir, nr, size uintptr) uintptr {
	return dir<<30 | size<<16 | kvmIO<<8 | nr
}

func kvmIOCtl(fd int, request, argument uintptr) (uintptr, error) {
	result, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, argument)
	if errno != 0 {
		return 0, errno
	}
	return result, nil
}

func kvmSimpleRequest(nr uintptr) uintptr {
	return kvmIO<<8 | nr
}

func kvmSetFlatRealModeSegments(sregs *kvmSregs) {
	for _, segment := range []*kvmSegment{&sregs.CS, &sregs.DS, &sregs.ES, &sregs.FS, &sregs.GS, &sregs.SS} {
		segment.Base = 0
		// The touch program runs with real-mode instruction defaults but uses
		// 32-bit address-size overrides.  Hardware VMX enforces the hidden
		// segment limit even when CR0.PE is clear, unlike the permissive TCG
		// path used by the first NPT fixture.  Install flat unreal-mode data
		// segments so sparse GPAs above 64 KiB are valid on both backends.
		segment.Limit = ^uint32(0)
		segment.Selector = 0
		segment.G = 1
	}
}

func newKVMVCPU(vmFD, id, runSize int) (*kvmVCPU, error) {
	value, err := kvmIOCtl(vmFD, kvmSimpleRequest(kvmCreateVCPU), uintptr(id))
	if err != nil {
		return nil, err
	}
	fd := int(value)
	run, err := syscall.Mmap(fd, 0, runSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	var sregs kvmSregs
	if _, err := kvmIOCtl(fd, kvmIOC(iocRead, kvmGetSregsNR, unsafe.Sizeof(sregs)), uintptr(unsafe.Pointer(&sregs))); err != nil {
		return nil, fmt.Errorf("KVM_GET_SREGS: %w", err)
	}
	kvmSetFlatRealModeSegments(&sregs)
	if _, err := kvmIOCtl(fd, kvmIOC(iocWrite, kvmSetSregsNR, unsafe.Sizeof(sregs)), uintptr(unsafe.Pointer(&sregs))); err != nil {
		return nil, fmt.Errorf("KVM_SET_SREGS: %w", err)
	}
	return &kvmVCPU{fd: fd, run: run}, nil
}

func prepareKVMNPTProbe(count int) (*kvmNPTProbe, error) {
	if unsafe.Sizeof(kvmUserspaceMemoryRegion{}) != 32 || unsafe.Sizeof(kvmRegs{}) != 144 || unsafe.Sizeof(kvmSregs{}) != 312 {
		return nil, fmt.Errorf("unexpected KVM ABI sizes: region=%d regs=%d sregs=%d",
			unsafe.Sizeof(kvmUserspaceMemoryRegion{}), unsafe.Sizeof(kvmRegs{}), unsafe.Sizeof(kvmSregs{}))
	}
	kvmFD, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	version, err := kvmIOCtl(kvmFD, kvmSimpleRequest(kvmGetAPIVersion), 0)
	if err != nil {
		return nil, fmt.Errorf("KVM_GET_API_VERSION: %w", err)
	}
	if version != kvmAPIVersion {
		return nil, fmt.Errorf("KVM API version=%d, want %d", version, kvmAPIVersion)
	}
	value, err := kvmIOCtl(kvmFD, kvmSimpleRequest(kvmCreateVM), 0)
	if err != nil {
		return nil, fmt.Errorf("KVM_CREATE_VM: %w", err)
	}
	vmFD := int(value)
	length := kvmSparseGPA + count*pmdSpan + 4096
	memory, err := syscall.Mmap(-1, 0, length, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANON|mapNoReserve)
	if err != nil {
		return nil, fmt.Errorf("map nested guest memory: %w", err)
	}
	if err := syscall.Madvise(memory, madvNoHugepage); err != nil {
		return nil, fmt.Errorf("MADV_NOHUGEPAGE nested guest memory: %w", err)
	}
	memory[kvmCodeGPA] = 0xf4
	for i := 0; i < count; i++ {
		memory[kvmSparseGPA+i*pmdSpan] = kvmSparseMarker
	}
	expected, err := physicalPagesAtOffsets(memory, kvmSparseGPA, pmdSpan, count)
	if err != nil {
		return nil, fmt.Errorf("nested guest pagemap: %w", err)
	}
	region := kvmUserspaceMemoryRegion{
		MemorySize:    uint64(len(memory)),
		UserspaceAddr: uint64(uintptr(unsafe.Pointer(&memory[0]))),
	}
	if _, err := kvmIOCtl(vmFD, kvmIOC(iocWrite, kvmSetUserMemoryRegionNR, unsafe.Sizeof(region)), uintptr(unsafe.Pointer(&region))); err != nil {
		return nil, fmt.Errorf("KVM_SET_USER_MEMORY_REGION: %w", err)
	}
	runSize, err := kvmIOCtl(kvmFD, kvmSimpleRequest(kvmGetVCPUMmapSize), 0)
	if err != nil {
		return nil, fmt.Errorf("KVM_GET_VCPU_MMAP_SIZE: %w", err)
	}
	vcpuFault, err := newKVMVCPU(vmFD, 0, int(runSize))
	if err != nil {
		return nil, fmt.Errorf("create fault vCPU: %w", err)
	}
	vcpuAlias, err := newKVMVCPU(vmFD, 1, int(runSize))
	if err != nil {
		return nil, fmt.Errorf("create alias vCPU: %w", err)
	}
	warmEnd := count / 3
	firstEnd := warmEnd + count/3
	probe := &kvmNPTProbe{
		kvmFD: kvmFD, vmFD: vmFD, memory: memory, vcpuFault: vcpuFault, vcpuAlias: vcpuAlias,
		expected: expected, count: count, warmEnd: warmEnd, firstEnd: firstEnd,
	}
	if err := probe.touch(0, warmEnd); err != nil {
		return nil, fmt.Errorf("warm nested NPT leaves: %w", err)
	}
	if err := probe.run(probe.vcpuAlias, []byte{0xf4}); err != nil {
		return nil, fmt.Errorf("initialize alias vCPU: %w", err)
	}
	return probe, nil
}

func physicalPagesAtOffsets(mapping []byte, first, stride, count int) (map[uint64]int, error) {
	pagemap, err := os.Open("/proc/self/pagemap")
	if err != nil {
		return nil, err
	}
	defer pagemap.Close()
	base := uint64(uintptr(unsafe.Pointer(&mapping[0])))
	expected := make(map[uint64]int, count)
	var raw [8]byte
	for i := 0; i < count; i++ {
		virtual := base + uint64(first+i*stride)
		if _, err := pagemap.ReadAt(raw[:], int64((virtual/4096)*8)); err != nil {
			return nil, err
		}
		entry := binary.LittleEndian.Uint64(raw[:])
		if entry&(uint64(1)<<63) == 0 {
			return nil, fmt.Errorf("page %d is not present in pagemap", i)
		}
		pfn := entry & pagemapPFNMask
		if pfn == 0 {
			return nil, errors.New("pagemap PFNs are hidden; nested page ownership cannot be verified")
		}
		expected[(pfn<<12)&x86PTEAddressMask] = i
	}
	return expected, nil
}

func (p *kvmNPTProbe) run(vcpu *kvmVCPU, code []byte) error {
	if len(code) > 4096 {
		return errors.New("nested guest program exceeds its code page")
	}
	copy(p.memory[kvmCodeGPA:kvmCodeGPA+len(code)], code)
	regs := kvmRegs{Rip: kvmCodeGPA, Rsp: 0x8000, Rflags: 2}
	if _, err := kvmIOCtl(vcpu.fd, kvmIOC(iocWrite, kvmSetRegsNR, unsafe.Sizeof(regs)), uintptr(unsafe.Pointer(&regs))); err != nil {
		return fmt.Errorf("KVM_SET_REGS: %w", err)
	}
	for {
		if _, err := kvmIOCtl(vcpu.fd, kvmSimpleRequest(kvmRun), 0); err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("KVM_RUN: %w", err)
		}
		if len(vcpu.run) < 12 {
			return errors.New("KVM run mapping is too short")
		}
		exitReason := binary.LittleEndian.Uint32(vcpu.run[8:12])
		if exitReason != kvmExitHLT {
			return fmt.Errorf("KVM_RUN exit reason=%d, want HLT", exitReason)
		}
		return nil
	}
}

func kvmNPTTouchProgram(first, count int) ([]byte, error) {
	address := uint64(kvmSparseGPA) + uint64(first)*pmdSpan
	if count <= 0 || address > uint64(^uint32(0)) || address+uint64(count-1)*pmdSpan > uint64(^uint32(0)) {
		return nil, fmt.Errorf("nested touch range first=%d count=%d exceeds 32-bit real-mode addressing", first, count)
	}
	code := []byte{
		0x66, 0xbe, 0, 0, 0, 0, // mov esi, first GPA
		0x66, 0xb9, 0, 0, 0, 0, // mov ecx, count
		0x67, 0x8a, 0x06, // loop: mov al, [esi]
		0x66, 0x81, 0xc6, 0, 0, 0, 0, // add esi, 2 MiB
		0x66, 0x49, // dec ecx
		0x75, 0xf2, // jnz loop
		0xf4, // hlt
	}
	binary.LittleEndian.PutUint32(code[2:6], uint32(address))
	binary.LittleEndian.PutUint32(code[8:12], uint32(count))
	binary.LittleEndian.PutUint32(code[18:22], uint32(pmdSpan))
	return code, nil
}

func (p *kvmNPTProbe) touch(first, count int) error {
	code, err := kvmNPTTouchProgram(first, count)
	if err != nil {
		return err
	}
	return p.run(p.vcpuFault, code)
}

func (p *kvmNPTProbe) writeGPA(gpa uint32, value byte) error {
	code := []byte{0xb0, value, 0x67, 0xa2, 0, 0, 0, 0, 0xf4}
	binary.LittleEndian.PutUint32(code[4:8], gpa)
	return p.run(p.vcpuAlias, code)
}

func (p *kvmNPTProbe) changedMarkerPages() []int {
	var changed []int
	for i := 0; i < p.count; i++ {
		if p.memory[kvmSparseGPA+i*pmdSpan] != kvmSparseMarker {
			changed = append(changed, i)
		}
	}
	return changed
}
