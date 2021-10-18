/*
Copyright 2013-2014 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 3 bits
	ECN         uint8 // 3 bits
	Ctrl        uint8 // 6 bits
	Window      uint16
	Checksum    uint16 // Kernel will set this if it's 0
	Urgent      uint16
	Options     []TCPOption
}

type TCPOption struct {
	Kind        uint8
	Length      uint8
	Data        []byte
	SubType     uint8
	Version     uint8
	A           uint8
	B           uint8
	C           uint8
	H           uint8
	SenderKey   uint64
	ReceiverKey uint64
}

// Parse packet into TCPHeader structure
func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)  // top 4 bits
	tcp.Reserved = byte(mix >> 9 & 7) // 3 bits
	tcp.ECN = byte(mix >> 6 & 7)      // 3 bits
	tcp.Ctrl = byte(mix & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	//fmt.Println("DataOffset", tcp.DataOffset)
	for {
		option := NewOptions(r)
		if option != nil {
			tcp.Options = append(tcp.Options, *option)
		} else {
			break
		}
	}
	return &tcp
}

func NewOptions(r *bytes.Reader) *TCPOption {
	var option TCPOption
	err := binary.Read(r, binary.BigEndian, &option.Kind)
	if err == io.EOF {
		return nil
	}
	binary.Read(r, binary.BigEndian, &option.Length)

	if option.Kind == 30 {
		var mix uint8
		binary.Read(r, binary.BigEndian, &mix)
		option.SubType = byte(mix >> 4)
		option.Version = byte(mix & 0xff)

		binary.Read(r, binary.BigEndian, &mix)
		option.A = byte(mix >> 7)
		option.B = byte(mix >> 6 & 1)
		option.C = byte(mix >> 5 & 1)
		option.H = byte(mix & 1)
		binary.Read(r, binary.BigEndian, &option.ReceiverKey)
	} else {
		option.Data = make([]byte, option.Length-2)
		for i := 0; i < int(option.Length-2); i++ {
			binary.Read(r, binary.BigEndian, &option.Data[i])
		}
	}

	return &option
}

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func (option *TCPOption) Marshal(buf *bytes.Buffer) {

	binary.Write(buf, binary.BigEndian, option.Kind)
	if option.Length > 1 {
		binary.Write(buf, binary.BigEndian, option.Length)
		var mix uint8
		mix = uint8(option.SubType<<4) | option.Version
		binary.Write(buf, binary.BigEndian, mix)

		mix = uint8(option.A<<7) |
			uint8(option.B<<6) |
			uint8(option.C<<5) |
			uint8(option.H)

		binary.Write(buf, binary.BigEndian, mix)
		binary.Write(buf, binary.BigEndian, option.SenderKey)
		if option.ReceiverKey != 0 {
			binary.Write(buf, binary.BigEndian, option.ReceiverKey)
		}
	}
}

func (tcp *TCPHeader) Marshal() []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 | // top 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.ECN)<<6 | // 3 bits
		uint16(tcp.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		option.Marshal(buf)
		// binary.Write(buf, binary.BigEndian, option.Kind)
		// if option.Length > 1 {
		// 	binary.Write(buf, binary.BigEndian, option.Length)
		// 	//binary.Write(buf, binary.BigEndian, option.Data)
		// }
	}

	out := buf.Bytes()
	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

// TCP Checksum
func Csum(data []byte, srcip, dstip [4]byte) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	//fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		//fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}
