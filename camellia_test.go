package camellia

import (
	"bytes"
	"testing"
)

func Test_cameliaCipher_Encrypt(t *testing.T) {
	type params struct {
		key, message, cipher []byte
	}
	tests := []struct {
		name   string
		params params
	}{
		{
			name: "test camellia 128-bit",
			params: params{
				key: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
				message: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
				cipher: []byte{0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCameliaCipher(tt.params.key)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			var b [16]byte
			cipher.Encrypt(b[:], tt.params.message)
			if !bytes.Equal(b[:], tt.params.cipher) {
				t.Errorf("encrypt failed:\ngot : % 02x\nwant: % 02x", b, tt.params.cipher)
			}

			cipher.Decrypt(b[:], tt.params.cipher)
			if !bytes.Equal(b[:], tt.params.message) {
				t.Errorf("decrypt failed:\ngot : % 02x\nwant: % 02x", b, tt.params.message)
			}
		})
	}
}
