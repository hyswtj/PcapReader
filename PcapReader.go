package main

import (
	"PcapReader/pcap"
	"fmt"
	"os"
)

func main() {
	var fileName string
	var packetCnt int = 0

	if len(os.Args) <= 1 {
		fmt.Println("Must be specify a input file.")
		os.Exit(0)
	}
	fileName = os.Args[1]
	fmt.Println("===============The pcap file reader.===============")
	fmt.Printf("Pcap file is:%s.\n", fileName)

	f, err := pcap.Open(fileName)
	if err != nil {
		fmt.Printf("Open pcap file %s failed with error %s.\n", fileName, err)
	}

	for true {
		if 0 == pcap.Decode(f, pcap.Layer2) {
			break
		}
		packetCnt++
	}

	fmt.Printf("Pcap file read finish, packet count %d.\n", packetCnt)
}
