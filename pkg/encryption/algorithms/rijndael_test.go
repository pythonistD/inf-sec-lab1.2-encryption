package algorithms

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_shiftRow(t *testing.T) {
	r := Rijndael{nk: 0, nb: 0, nr: 0, key: nil, keySchedule: nil, blockSize: 0}
	testCases := []struct {
		input    string
		expected string
	}{
		// Data -> ataD
		{"Data", "ataD"},
		// Java -> avaJ
		{"Java", "avaJ"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			inB := []byte(testCase.input)
			r.shiftRow(inB, 1)
			require.Equal(t, testCase.expected, string(inB))
		})
	}
}
func Test_subBytes(t *testing.T) {
	r := Rijndael{nk: 0, nb: 0, nr: 0, key: nil, keySchedule: nil, blockSize: 0}
	testCases := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{0x11, 0x7D, 0xCF}, []byte{0x82, 0xFF, 0x8A}},
		{[]byte{0x2B, 0x91, 0x7E}, []byte{0xF1, 0x81, 0xF3}},
	}
	for ind, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", ind), func(t *testing.T) {
			r.subBytes(testCase.input)
			require.Equal(t, testCase.expected, testCase.input)
		})
	}
}

func decodeHexStr(hexStr string) []uint32 {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Println("Ошибка при декодировании:", err)
		return nil
	}
	if len(bytes)%4 != 0 {
		fmt.Println("Ошибка: длина массива байт должна быть кратна 4")
		return nil
	}
	// Преобразование в массив uint32
	var uint32Array []uint32
	for i := 0; i < len(bytes); i += 4 {
		// Конвертация каждых 4 байт в uint32
		value := binary.BigEndian.Uint32(bytes[i : i+4]) // BigEndian или LittleEndian
		uint32Array = append(uint32Array, value)
	}
	return uint32Array
}

// Преобразование строки hex в массив байт
func hexStringToBytes(hexStr string) ([]byte, error) {
	// Декодирование строки в массив байт
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func Test_keyExpansion(t *testing.T) {
	r := Rijndael{
		nk: 4,
		nb: 4,
		nr: 10,
		key: []byte{0x01, 0xff, 0xae, 0x00,
			0x15, 0x16, 0xea, 0xbc,
			0xbb, 0x11, 0x00, 0x10,
			0xff, 0xb1, 0xc7, 0x86},
		keySchedule: nil,
		blockSize:   16,
	}
	hexStr := "01ffae001516eabcbb110010ffb1c786c839ea16dd2f00aa663e00ba998fc73cb9ff01f864d0015202ee01e89b61c6d4524b49ec369b48be34754956af148f82a0385a9596a3122ba2d65b7d0dc2d4ff95704c4203d35e69a1050514acc7d1eb734ea5d3709dfbbad198feae7d5f2f45fc5bcb2c8cc630965d5ece382001e17d00a3349b8c65040dd13bca35f13a2b489b52663a17376237c60ca8023736834aa8beb0a0bf89d29779857a954eb3f9df"
	expectedRoundKeys := decodeHexStr(hexStr)
	t.Run("", func(t *testing.T) {
		r.keyExpansion()
		fmt.Printf("Len: %d\n", len(r.keySchedule))
		fmt.Printf("Expected Len: %d\n", len(expectedRoundKeys))
		require.Len(t, r.keySchedule, len(expectedRoundKeys))
		require.Equal(t, expectedRoundKeys, r.keySchedule)
	})
}

func uint32Arr2Bytes(words []uint32) []byte {
	bytes := make([]byte, len(words)*4)

	for i, val := range words {
		binary.BigEndian.PutUint32(bytes[i*4:], val)
	}
	return bytes
}

func Test_addRoundKey(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)

	testCases := []struct {
		input    string
		expected string
	}{
		{"00000101030307070f0f1f1f3f3f7f7f", "01ffaf011615edbbb41e1f0fc08eb8f9"},
		{"4a0c0e34086b692fb9de4323761f9c7a", "8235e422d5446985dfe04399ef905b46"},
		{"4b51d28094023ee079728e85131689d2", "f2aed378f0d23fb27b9c8f6d88774f06"},
	}
	r.keyExpansion()
	for round, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", round), func(t *testing.T) {
			data, _ := hexStringToBytes(testCase.input)
			r.addRoundKey(data, r.keySchedule[4*round:4*round+4])
			tmp, _ := hexStringToBytes(testCase.expected)
			require.Equal(t, tmp, data)
		})
	}

}

func Test_shifRows(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)

	testCases := []struct {
		input    string
		expected string
	}{
		{"7c16797c475955ea8d72c076ba196c99", "7c59c09947726c7c8d1979eaba165576"},
		{"13966993031bf9979ee11aeedf60395a", "131b1a5a03e139939e606997df96f9ee"},
		{"89e466bc8cb5753721de733cc4f5846f", "89b5736f8cde84bc21f56637c4e4753c"},
	}
	r.keyExpansion()
	for round, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", round), func(t *testing.T) {
			data, _ := hexStringToBytes(testCase.input)
			r.shiftRows(data)
			tmp, _ := hexStringToBytes(testCase.expected)
			require.Equal(t, tmp, data)
		})
	}

}

func Test_mixColumns(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)

	testCases := []struct {
		input    string
		expected string
	}{
		{"7c59c09947726c7c8d1979eaba165576", "4a0c0e34086b692fb9de4323761f9c7a"},
		{"131b1a5a03e139939e606997df96f9ee", "4b51d28094023ee079728e85131689d2"},
		{"89b5736f8cde84bc21f56637c4e4753c", "d1026b9842009eb6174d419eedb48ebe"},
	}
	r.keyExpansion()
	for round, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", round), func(t *testing.T) {
			data, _ := hexStringToBytes(testCase.input)
			r.mixColumns(data)
			tmp, _ := hexStringToBytes(testCase.expected)
			require.Equal(t, tmp, data)
		})
	}
}

func Test_subBytesECB(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)

	testCases := []struct {
		input    string
		expected string
	}{
		{"01ffaf011615edbbb41e1f0fc08eb8f9", "7c16797c475955ea8d72c076ba196c99"},
		{"8235e422d5446985dfe04399ef905b46", "13966993031bf9979ee11aeedf60395a"},
		{"f2aed378f0d23fb27b9c8f6d88774f06", "89e466bc8cb5753721de733cc4f5846f"},
	}
	r.keyExpansion()
	for round, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", round), func(t *testing.T) {
			data, _ := hexStringToBytes(testCase.input)
			tmp, _ := hexStringToBytes(testCase.expected)

			r.subBytes(data)

			require.Equal(t, tmp, data)
		})
	}

}

func Test_encryptBlock(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)

	testCases := []struct {
		input    string
		expected string
	}{
		{"01ffaf011615edbbb41e1f0fc08eb8f9", "8235e422d5446985dfe04399ef905b46"},
		{"8235e422d5446985dfe04399ef905b46", "f2aed378f0d23fb27b9c8f6d88774f06"},
		{"f2aed378f0d23fb27b9c8f6d88774f06", "83492274749bd608233808c842a0013c"},
	}
	r.keyExpansion()
	for round, testCase := range testCases {
		t.Run(fmt.Sprintf("%d", round), func(t *testing.T) {
			data, _ := hexStringToBytes(testCase.input)
			tmp, _ := hexStringToBytes(testCase.expected)

			encryptedBlock := make([]byte, len(data))
			copy(encryptedBlock, data)

			r.subBytes(encryptedBlock)
			r.shiftRows(encryptedBlock)
			r.mixColumns(encryptedBlock)
			rKey := r.keySchedule[4*(round+1) : 4*(round+1)+4]
			fmt.Printf("round key: %x\n", rKey)
			r.addRoundKey(encryptedBlock, rKey)

			require.Equal(t, tmp, encryptedBlock)
		})
	}

}

func Test_EncryptECB(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)
	hexInput := "00000101030307070f0f1f1f3f3f7f7f"
	data, _ := hexStringToBytes(hexInput)
	hexEncryptedData := "d4712fdf16f46e1b170cbfdd94cad960be08b5bb2d6b0ee54a9abfcdbccdbcce"
	expectedEncryptedData, _ := hexStringToBytes(hexEncryptedData)

	t.Run("", func(t *testing.T) {
		res := r.EncryptECB(data)
		//require.Len(t, r.keySchedule, len(expectedRoundKeys))
		fmt.Printf("Encrypted data: %x\n", res)
		require.Equal(t, expectedEncryptedData, res)
	})
}

func Test_DecryptECB(t *testing.T) {
	var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := NewRijndael(key)
	hexInput := "d4712fdf16f46e1b170cbfdd94cad960be08b5bb2d6b0ee54a9abfcdbccdbcce"
	data, _ := hexStringToBytes(hexInput)
	hexEncryptedData := "00000101030307070f0f1f1f3f3f7f7f"
	expectedEncryptedData, _ := hexStringToBytes(hexEncryptedData)

	t.Run("", func(t *testing.T) {
		res := r.DecryptECB(data)
		//require.Len(t, r.keySchedule, len(expectedRoundKeys))
		require.Equal(t, expectedEncryptedData, res)
	})
}
