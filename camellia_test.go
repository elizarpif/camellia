package camellia

import (
	"bytes"
	"encoding/hex"
	"fmt"
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

func Test_rotate128Key(t *testing.T) {
	type args struct {
		k [2]uint64
		n int
	}
	tests := []struct {
		name  string
		args  args
		want  uint64
		want1 uint64
	}{
		{
			name: "test rotate",
			args: args{
				k: [2]uint64{uint64(12), uint64(5)},
				n: 0,
			},
			want:  uint64(12),
			want1: uint64(5),
		},
		{
			name: "test rotate 2",
			args: args{
				k: [2]uint64{uint64(1), uint64(1)},
				n: 2,
			},
			want:  uint64(4),
			want1: uint64(4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := rotate128Key(tt.args.k, uint(tt.args.n))
			if got != tt.want {
				t.Errorf("rotate128Key() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("rotate128Key() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	var vectors = []struct {
		key, plaintext, ciphertext, name string
	}{
		{
			name:       "test1",
			key:        "0123456789abcdeffedcba9876543210",
			plaintext:  "0123456789abcdeffedcba9876543210",
			ciphertext: "67673138549669730857065648eabe43",
		},
		{
			name:       "test3",
			key:        "0123456789abcdeffedcba98765432100011223344556677",
			plaintext:  "0123456789abcdeffedcba9876543210",
			ciphertext: "b4993401b3e996f84ee5cee7d79b09b9",
		},
		{
			name:       "test2",
			key:        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
			plaintext:  "0123456789abcdeffedcba9876543210",
			ciphertext: "9acc237dff16d76c20ef7c919e3a7509",
		},
	}

	for i, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := fromHex(v.key)
			plaintext := fromHex(v.plaintext)
			ciphertext := fromHex(v.ciphertext)
			buf := make([]byte, BLOCKSIZE)

			c, err := NewCameliaCipher(key)
			if err != nil {
				t.Fatalf("Test vector %d: Failed to create Camellia instance: %s", i, err)
			}

			c.Encrypt(buf, plaintext)
			fmt.Println(hex.EncodeToString(buf))
			if !bytes.Equal(ciphertext, buf) {
				t.Fatalf("Test vector %d:\nEncryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
			}

			c.Decrypt(buf, buf)
			fmt.Println(hex.EncodeToString(buf))
			if !bytes.Equal(plaintext, buf) {
				t.Fatalf("Test vector %d:\nDecryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(plaintext))
			}
		})
	}
}
