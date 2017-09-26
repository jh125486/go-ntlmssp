package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

const expMsgBodyLen = 40

type negotiateMessageFields struct {
	messageHeader
	NegotiateFlags negotiateFlags

	Domain      varField
	Workstation varField

	Version
}

var defaultFlags = NTLMSSP_NEGOTIATE_TARGET_INFO |
	NTLMSSP_NEGOTIATE_56 |
	NTLMSSP_NEGOTIATE_128 |
	NTLMSSP_NEGOTIATE_UNICODE |
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
	NTLMSSP_NEGOTIATE_SIGN |
	NTLMSSP_NEGOTIATE_SEAL

//NewNegotiateMessage creates a new NEGOTIATE message with the
//flags that this package supports.
func NewNegotiateMessage(domainName, workstationName string) ([]byte, error) {
	payloadOffset := expMsgBodyLen
	flags := defaultFlags | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

	if domainName != "" {
		flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	}

	if workstationName == "" {
		workstationName = "go-ntlmssp"
	}
	flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

	msg := negotiateMessageFields{
		messageHeader:  newMessageHeader(NtLmNegotiate),
		NegotiateFlags: flags,
		Domain:         newVarField(&payloadOffset, len(domainName)),
		Workstation:    newVarField(&payloadOffset, len(workstationName)),
		Version:        DefaultVersion(),
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &msg); err != nil {
		return nil, err
	}
	if b.Len() != expMsgBodyLen {
		return nil, errors.New("incorrect body length")
	}

	payload := strings.ToUpper(domainName + workstationName)
	if _, err := b.WriteString(payload); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
