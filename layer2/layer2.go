package layer2

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

type ethHeader struct {
	dstAddr [6]byte
	srcAddr [6]byte
	proto   uint16
}

type vlanHeader struct {
	vlanTCI   uint16
	nextProto uint16
}
type ETH_P_PROTO int

const (
	ETH_P_IP       = 0x0800
	ETH_P_ARP      = 0x0806
	ETH_P_8021Q    = 0x8100
	ETH_P_IPV6     = 0x86DD
	ETH_P_PPP_DISC = 0x8863
	ETH_P_PPP_SES  = 0x8864
	ETH_P_MPLS_UC  = 0x8847
	ETH_P_MPLS_MC  = 0x8848
	ETH_P_8021AD   = 0x88A8
)

func EthParse(b []byte) (int, uint16) {
	var ethHdr *ethHeader
	offset := 14
	ethHdr = *(**ethHeader)(unsafe.Pointer(&b))
	fmt.Printf("Ethernet header information:\n")
	fmt.Printf("DMAC    :%02x-%02x-%02x-%02x-%02x-%02x\n",
		ethHdr.dstAddr[0], ethHdr.dstAddr[1], ethHdr.dstAddr[2],
		ethHdr.dstAddr[3], ethHdr.dstAddr[4], ethHdr.dstAddr[5])
	fmt.Printf("SMAC    :%02x-%02x-%02x-%02x-%02x-%02x\n",
		ethHdr.srcAddr[0], ethHdr.srcAddr[1], ethHdr.srcAddr[2],
		ethHdr.srcAddr[3], ethHdr.srcAddr[4], ethHdr.srcAddr[5])
	ethHdr.proto = binary.BigEndian.Uint16(b[12:14])
	fmt.Printf("Proto   :%04x\n", ethHdr.proto)

	ethType := ethHdr.proto
	for true {
		switch ethType {
		case ETH_P_8021Q:
		case ETH_P_8021AD:
			var vhdr *vlanHeader = *(**vlanHeader)(unsafe.Pointer(&b[offset]))
			fmt.Printf("Vlan detected, TCI:%04x, next proto:%04x.\n", vhdr.vlanTCI, vhdr.nextProto)
			offset += 4
			break

		case ETH_P_MPLS_UC:
			break

		case ETH_P_MPLS_MC:
			break

		default:
			break
		}
		break
	}
	return offset, ethType
}
