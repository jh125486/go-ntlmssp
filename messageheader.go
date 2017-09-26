package ntlmssp

import (
	"bytes"
)

type MessageType uint32

var signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// MessageType constants
const (
	_                MessageType = iota
	NtLmNegotiate                // 1
	NtLmChallenge                // 2
	NtLmAuthenticate             // 3
)

type messageHeader struct {
	Signature [8]byte
	MessageType
}

func (h messageHeader) IsValid() bool {
	return bytes.Equal(h.Signature[:], signature[:]) &&
		h.MessageType >= NtLmNegotiate && h.MessageType <= NtLmAuthenticate
}

func newMessageHeader(t MessageType) messageHeader {
	return messageHeader{signature, t}
}
