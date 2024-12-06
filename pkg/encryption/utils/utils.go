package utils

import (
	"bytes"
	"fmt"
)

func PaddingKey(key []byte, reqKeySize int) ([]byte, error) {
	if len(key) > 16 {
		return nil, fmt.Errorf("padding: размер ключа должен быть >= %d байт", reqKeySize)
	}
	if len(key) < 16 {
		paddedKey := make([]byte, reqKeySize)
		copy(paddedKey, key)
		return paddedKey, nil
	}
	return key, nil
}

func Pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Pkcs7UnPadding Удаление PKCS#7 Padding
func Pkcs7UnPadding(data []byte) []byte {
	length := len(data)
	padding := int(data[length-1])
	return data[:length-padding]
}

//func
