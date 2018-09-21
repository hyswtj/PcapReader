package layer4

import (
	"encoding/binary"
	"fmt"
)

/* tcp header */
type tcpHeader struct {
	saddr   uint16
	daddr   uint16
	seq     uint32
	ack_seq uint32
	flags   uint16
	window  uint16
	csum    uint16
	urg_ptr uint16
}

/* udp header */
type udpHeader struct {
	saddr  uint16
	daddr  uint16
	length uint16
	csum   uint16
}

func TcpParse(b []byte) {
	tcpHdr := new(tcpHeader)
	tcpHdr.saddr = binary.BigEndian.Uint16(b[0:2])
	tcpHdr.daddr = binary.BigEndian.Uint16(b[2:4])
	tcpHdr.seq = binary.BigEndian.Uint32(b[4:8])
	tcpHdr.ack_seq = binary.BigEndian.Uint32(b[8:12])
	tcpHdr.flags = binary.BigEndian.Uint16(b[12:14])
	tcpHdr.window = binary.BigEndian.Uint16(b[14:16])
	tcpHdr.csum = binary.BigEndian.Uint16(b[16:18])
	tcpHdr.urg_ptr = binary.BigEndian.Uint16(b[18:20])
	fmt.Printf("Tcp information:\n")
}

func UdpParse(b []byte) {
	udpHdr := new(udpHeader)
	udpHdr.saddr = binary.BigEndian.Uint16(b[0:2])
	udpHdr.daddr = binary.BigEndian.Uint16(b[2:4])
	udpHdr.length = binary.BigEndian.Uint16(b[4:6])
	udpHdr.csum = binary.BigEndian.Uint16(b[6:8])
	fmt.Printf("Udp information:\n")
}
