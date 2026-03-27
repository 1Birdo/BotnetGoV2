package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// packet types
const (
	pktPing     = 0x01
	pktPong     = 0x02
	pktCmd      = 0x03
	pktDiag     = 0x04
	pktHeartbeat = 0x05
	pktAuth     = 0x06
	pktAuthResp = 0x07
)

type pktHdr struct {
	Type   uint8
	Len    uint32
	Stamp  int64
	Chksum uint16
}

type pkt struct {
	Hdr  pktHdr
	Data []byte
}

func checksum(data []byte) uint16 {
	h := sha256.Sum256(data)
	return binary.BigEndian.Uint16(h[:2])
}

func mkPacket(typ uint8, payload []byte) pkt {
	ts := time.Now().UnixNano()
	p := pkt{
		Hdr:  pktHdr{Type: typ, Len: uint32(len(payload)), Stamp: ts},
		Data: payload,
	}
	tmp := make([]byte, 19+p.Hdr.Len)
	tmp[0] = p.Hdr.Type
	binary.BigEndian.PutUint32(tmp[1:5], p.Hdr.Len)
	binary.BigEndian.PutUint64(tmp[5:13], uint64(p.Hdr.Stamp))
	copy(tmp[19:], p.Data)
	p.Hdr.Chksum = checksum(append(tmp[0:17], tmp[19:]...))
	return p
}

func encodePkt(p pkt) ([]byte, error) {
	buf := make([]byte, 19+p.Hdr.Len)
	buf[0] = p.Hdr.Type
	binary.BigEndian.PutUint32(buf[1:5], p.Hdr.Len)
	binary.BigEndian.PutUint64(buf[5:13], uint64(p.Hdr.Stamp))
	binary.BigEndian.PutUint16(buf[17:19], p.Hdr.Chksum)
	copy(buf[19:], p.Data)
	return buf, nil
}

func decodePkt(data []byte) (pkt, error) {
	if len(data) < 19 {
		return pkt{}, fmt.Errorf("pkt too small")
	}
	var p pkt
	p.Hdr.Type = data[0]
	p.Hdr.Len = binary.BigEndian.Uint32(data[1:5])
	p.Hdr.Stamp = int64(binary.BigEndian.Uint64(data[5:13]))
	p.Hdr.Chksum = binary.BigEndian.Uint16(data[17:19])
	if len(data) < int(19+p.Hdr.Len) {
		return pkt{}, fmt.Errorf("incomplete pkt")
	}
	p.Data = make([]byte, p.Hdr.Len)
	copy(p.Data, data[19:19+p.Hdr.Len])
	want := checksum(append(data[0:17], data[19:19+p.Hdr.Len]...))
	if want != p.Hdr.Chksum {
		return pkt{}, fmt.Errorf("checksum mismatch")
	}
	return p, nil
}

func sendPkt(c net.Conn, p pkt) error {
	raw, err := encodePkt(p)
	if err != nil {
		return err
	}
	_, err = c.Write(raw)
	return err
}

func recvPkt(c net.Conn) (pkt, error) {
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	hdr := make([]byte, 19)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return pkt{}, err
	}
	pLen := binary.BigEndian.Uint32(hdr[1:5])
	if pLen > 16*1024 {
		return pkt{}, fmt.Errorf("pkt too large: %d", pLen)
	}
	body := make([]byte, pLen)
	if pLen > 0 {
		if _, err := io.ReadFull(c, body); err != nil {
			return pkt{}, err
		}
	}
	return decodePkt(append(hdr, body...))
}

func cmdToBytes(c cmdPayload) []byte {
	buf := make([]byte, 42)
	copy(buf[0:16], c.Method[:])
	copy(buf[16:20], c.TargetIP[:])
	binary.BigEndian.PutUint16(buf[20:22], c.Port)
	binary.BigEndian.PutUint32(buf[22:26], c.Duration)
	copy(buf[26:42], c.Pad[:])
	return buf
}
