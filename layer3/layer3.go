package layer3

import (
	"encoding/binary"
	"fmt"
)

/* arp header */
type arpHeader struct {
	ar_hrd uint16 /* format of hardware address   */
	ar_pro uint16 /* format of protocol address   */
	ar_hln uint8  /* length of hardware address   */
	ar_pln uint8  /* length of protocol address   */
	ar_op  uint16 /* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	ar_sha [6]byte /* sender hardware address  */
	ar_sip [4]byte /* sender IP address        */
	ar_tha [6]byte /* target hardware address  */
	ar_tip [4]byte /* target IP address        */
}

/* ipv4 header */
type ipv4Header struct {
	vhl     uint8
	tos     uint8
	tot_len uint16
	id      uint16
	flags   uint16
	ttl     uint8
	proto   uint8
	csum    uint16
	saddr   uint32
	daddr   uint32
}

/* ipv6 header */
type ipv6Header struct {
	ver_pri     uint8
	flow_lbl    [3]byte
	payload_len uint16
	next_hdr    uint8
	hop_limit   uint8
	saddr       [16]byte
	daddr       [16]byte
}

func ArpParse(b []byte) uint8 {
	arpHdr := new(arpHeader)
	arpHdr.ar_hrd = binary.BigEndian.Uint16(b[0:2])
	arpHdr.ar_pro = binary.BigEndian.Uint16(b[2:4])
	fmt.Printf("Arp information:\n")
	return 0
}

func Ipv4Parse(b []byte) uint8 {
	ipv4Hdr := new(ipv4Header)
	ipv4Hdr.tot_len = binary.BigEndian.Uint16(b[0:2])
	ipv4Hdr.id = binary.BigEndian.Uint16(b[2:4])
	fmt.Printf("Ipv4 information:\n")
	return ipv4Hdr.proto
}

func Ipv6Parse(b []byte) uint8 {
	ipv6Hdr := new(ipv6Header)
	ipv6Hdr.payload_len = binary.BigEndian.Uint16(b[0:2])
	fmt.Printf("Ipv6 information:\n")
	return ipv6Hdr.next_hdr
}
