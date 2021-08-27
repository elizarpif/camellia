## Camellia

Library realizes the [Camellia](https://ru.wikipedia.org/wiki/Camellia) algorythm

```go
cipher, err := NewCameliaCipher(key)
if err != nil {
    log.Fatalf("err: %v", err)
}

var b [16]byte

cipher.Encrypt(b[:], messageText)
cipher.Decrypt(b[:], cipherText)
```
