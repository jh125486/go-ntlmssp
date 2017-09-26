package ntlmssp

type negotiateFlags uint32

// Negotiate Flags per https://msdn.microsoft.com/en-us/library/cc236650.aspx
const (
	NTLMSSP_NEGOTIATE_56       negotiateFlags = 1 << 31 // W
	NTLMSSP_NEGOTIATE_KEY_EXCH                = 1 << 30 // V
	NTLMSSP_NEGOTIATE_128                     = 1 << 29 // U
	// r1
	// r2
	// r3
	NTLMSSP_NEGOTIATE_VERSION = 1 << 25 // T
	// r4
	NTLMSSP_NEGOTIATE_TARGET_INFO      = 1 << 23 // S
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 1 << 22 // R
	// r5
	NTLMSSP_NEGOTIATE_IDENTIFY                 = 1 << 20 // Q
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 1 << 19 // P
	// r6
	NTLMSSP_TARGET_TYPE_SERVER    = 1 << 17 // O
	NTLMSSP_TARGET_TYPE_DOMAIN    = 1 << 16 // N
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 1 << 15 // M
	// r7
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 1 << 13 // L
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 1 << 12 // K
	_ANONYMOUS                                 = 1 << 11 // J
	// r8
	NTLMSSP_NEGOTIATE_NTLM = 1 << 9 // H
	// r9
	NTLMSSP_NEGOTIATE_LM_KEY   = 1 << 7 // G
	NTLMSSP_NEGOTIATE_DATAGRAM = 1 << 6 // F
	NTLMSSP_NEGOTIATE_SEAL     = 1 << 5 // E
	NTLMSSP_NEGOTIATE_SIGN     = 1 << 4 // D
	// r10
	NTLMSSP_REQUEST_TARGET    = 1 << 2 // C
	NTLM_NEGOTIATE_OEM        = 1 << 1 // B
	NTLMSSP_NEGOTIATE_UNICODE = 1 << 0 // A
)

func (field negotiateFlags) Has(flags negotiateFlags) bool {
	return field&flags == flags
}

func (field *negotiateFlags) Unset(flags negotiateFlags) {
	*field = *field ^ (*field & flags)
}
