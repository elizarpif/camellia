## Camellia

Библиотека, реализующая алгоритм [Camellia](https://ru.wikipedia.org/wiki/Camellia)

```go
cipher, err := NewCameliaCipher(key)
if err != nil {
    log.Fatalf("err: %v", err)
}

var b [16]byte

cipher.Encrypt(b[:], messageText)
cipher.Decrypt(b[:], cipherText)
```