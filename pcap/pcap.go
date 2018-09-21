package pcap

import (
	"PcapReader/layer2"
	"PcapReader/layer3"
	"encoding/binary"
	"fmt"
	"os"
)

type PcapPaserLayer int

const (
	Layer1 = iota /* only parser packet header */
	Layer2
	Layer3
	Layer4
)

type PcapFileHeader struct {
	magic    uint32
	major    uint16
	minor    uint16
	thisZone uint32
	sigFigs  uint32
	snapLen  uint32
	linkType uint32
}

type PcapPktHeader struct {
	TimestampH uint32
	TimestampL uint32
	CapLen     uint32
	Length     uint32
}

func Open(name string) (*os.File, error) {
	var readlen int

	fmt.Printf("Open pcap file %s ", name)
	fp, err := os.Open(name)
	if err != nil {
		fmt.Printf("failed with err %s.\n", err)
		return fp, err
	}

	fmt.Printf("success.\n")

	fmt.Printf("Read file ")
	buf := make([]byte, 24)
	readlen, _ = fp.Read(buf)
	if readlen == 0 {
		fmt.Printf("failed with readlen %d.\n", readlen)
		return fp, err
	}
	fp.Seek(24, 0)
	fmt.Printf("success.\n")

	FileHdr := new(PcapFileHeader)
	FileHdr.magic = binary.BigEndian.Uint32(buf[0:4])
	FileHdr.major = binary.LittleEndian.Uint16(buf[4:6])
	FileHdr.minor = binary.LittleEndian.Uint16(buf[6:8])
	FileHdr.thisZone = binary.BigEndian.Uint32(buf[8:12])
	FileHdr.sigFigs = binary.BigEndian.Uint32(buf[12:16])
	FileHdr.snapLen = binary.LittleEndian.Uint32(buf[16:20])
	FileHdr.linkType = binary.LittleEndian.Uint32(buf[20:24])
	fmt.Printf("Pcap file information:\n")
	fmt.Printf("magic    :%08X\n", FileHdr.magic)
	fmt.Printf("major    :%d\n", FileHdr.major)
	fmt.Printf("minor    :%d\n", FileHdr.minor)
	fmt.Printf("thisZone :%08X\n", FileHdr.thisZone)
	fmt.Printf("sigFigs  :%d\n", FileHdr.sigFigs)
	fmt.Printf("snapLen  :%d\n", FileHdr.snapLen)
	fmt.Printf("linkType :%d\n", FileHdr.linkType)

	return fp, err
}

func Decode(f *os.File, layer PcapPaserLayer) int {
	buf := make([]byte, 16)
	readlen, _ := f.Read(buf)
	if readlen == 0 {
		defer f.Close()
		return 0
	}

	pktHdr := new(PcapPktHeader)
	pktHdr.TimestampH = binary.LittleEndian.Uint32(buf[0:4])
	pktHdr.TimestampL = binary.LittleEndian.Uint32(buf[4:8])
	pktHdr.CapLen = binary.LittleEndian.Uint32(buf[8:12])
	pktHdr.Length = binary.LittleEndian.Uint32(buf[12:16])
	fmt.Printf("Packet header information:\n")
	fmt.Printf("TimestampH    :%08x\n", pktHdr.TimestampH)
	fmt.Printf("TimestampL    :%08x\n", pktHdr.TimestampL)
	fmt.Printf("CapLen        :%d\n", pktHdr.CapLen)
	fmt.Printf("Length        :%d\n", pktHdr.Length)

	if layer > Layer1 {
		pktData := make([]byte, pktHdr.CapLen)
		readlen, _ = f.Read(pktData)
		if readlen == 0 {
			defer f.Close()
			return 0
		}
		offset, ethType := layer2.EthParse(pktData)
		switch ethType {
		case layer2.ETH_P_ARP:
			layer3.ArpParse(buf)
			break

		case layer2.ETH_P_IP:
			layer3.Ipv4Parse(buf)
			break

		case layer2.ETH_P_IPV6:
			layer3.Ipv6Parse(buf)
			break
		}
		fmt.Printf("ethType:%04x, offset:%d\n", ethType, offset)
	} else {
		f.Seek((int64)(pktHdr.CapLen), 1)
	}

	return readlen
}
