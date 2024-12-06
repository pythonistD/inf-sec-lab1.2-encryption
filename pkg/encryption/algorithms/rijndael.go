package algorithms

import (
	"encoding/binary"
	"fmt"
	"github.com/pythonistD/inf-sec-lab1.2-encryption/pkg/encryption"
	"github.com/pythonistD/inf-sec-lab1.2-encryption/pkg/encryption/utils"
)

type Rijndael struct {
	nk int
	nb int
	nr int

	key         []byte
	keySchedule []uint32
	blockSize   int
}

func NewRijndael(key []byte) (Rijndael, error) {
	switch len(key) {
	case 16:
		return Rijndael{
			nk:          4,
			nb:          4,
			nr:          10,
			key:         key,
			keySchedule: nil,
			blockSize:   16,
		}, nil
	default:
		return Rijndael{}, fmt.Errorf("NewRijndael: данный размер ключа не поддерживается %d", len(key))
	}
}

// shiftRow - делает циклический сдвиг влево
// для 32-битного(4 байтового) слова
func (r *Rijndael) shiftRow(row []byte, shift int) {
	tempRow := make([]byte, len(row))
	for ind, val := range row {
		pos := ind - shift
		if pos < 0 {
			pos = len(row) + pos
		}
		tempRow[pos] = val
	}
	copy(row, tempRow)
}

func (r *Rijndael) subBytes(state []byte) {
	for ind, val := range state {
		state[ind] = encryption.Sbox[val]
	}
	fmt.Printf("SubBytes:\n state: %x\n", state)
}

func (r *Rijndael) invSubBytes(state []byte) {
	for ind, val := range state {
		state[ind] = encryption.InvSbox[val]
	}
}

func (r *Rijndael) xor(a []byte, b []byte) {
	for ind, val := range a {
		a[ind] = val ^ b[ind]
	}
}

func (r *Rijndael) xorWords(w1 uint32, w2 uint32) uint32 {
	w1Byte := make([]byte, 4)
	binary.BigEndian.PutUint32(w1Byte, w1)
	w2Byte := make([]byte, 4)
	binary.BigEndian.PutUint32(w2Byte, w2)
	r.xor(w1Byte, w2Byte)
	return binary.BigEndian.Uint32(w1Byte)
}

func (r *Rijndael) g(w uint32, curRC uint32) uint32 {
	wByte := make([]byte, 4)
	binary.BigEndian.PutUint32(wByte, w)
	r.shiftRow(wByte, 1)
	r.subBytes(wByte)
	curRCByte := make([]byte, 4)
	binary.BigEndian.PutUint32(curRCByte, curRC)
	r.xor(wByte, curRCByte)
	return binary.BigEndian.Uint32(wByte)
}

// keyExpansion - функция, которая создаёт расписание ключей(round keys)
// результат работы функции - заполненный массив keySchedule структуры Rijndael
func (r *Rijndael) keyExpansion() {
	// Размер массива = кол-во раундовых ключей * кол-во 32-битных слов в одном ключе
	r.keySchedule = make([]uint32, 0, (r.nr+1)*encryption.RoundKeySizeWords)
	// Создаём первый раундовый ключ - k0
	for i := 0; i < r.nk; i++ {
		r.keySchedule = append(r.keySchedule, binary.BigEndian.Uint32(r.key[4*i:4*i+4]))
	}
	round := 1
	// Кол-во слов в key schedule = размер одного ключа * кол-во ключей
	amountOfWordsInKS := encryption.RoundKeySizeWords * (r.nr + 1)

	// Создаём k1-k10
	// На каждой итерации генерируется очередное слово round key
	for i := encryption.RoundKeySizeWords; i < amountOfWordsInKS; i++ {
		var w uint32
		if (i % r.nk) == 0 {
			gRes := r.g(r.keySchedule[i-1], encryption.Rcon[round])
			w = r.xorWords(r.keySchedule[i-r.nk], gRes)
			round++
		} else {
			w = r.xorWords(r.keySchedule[i-1], r.keySchedule[i-r.nk])
		}
		r.keySchedule = append(r.keySchedule, w)
	}
}

func (r *Rijndael) addRoundKey(state []byte, roundKey []uint32) {
	tmp := make([]byte, encryption.RoundKeySizeWords*encryption.WordSize)
	for ind, val := range roundKey {
		binary.BigEndian.PutUint32(tmp[4*ind:4*ind+4], val)
	}
	r.xor(state, tmp)
	fmt.Printf("AddRoundKey:\n state: %x\n", state)
}

// TO-DO: Протестировать эту функцию !!!!!!!
/*func (r *Rijndael) shiftRows(state []byte, shift int) {
	for i := 0; i < encryption.BlockSize; i += encryption.WordSize {
		r.shiftRow(state[i:i+encryption.WordSize], shift)
	}
}*/

func shiftRow(in []byte, i int, n int) {
	in[i], in[i+4*1], in[i+4*2], in[i+4*3] = in[i+4*(n%4)], in[i+4*((n+1)%4)], in[i+4*((n+2)%4)], in[i+4*((n+3)%4)]
}

func (r *Rijndael) shiftRows(state []byte) {
	shiftRow(state, 1, 1)
	shiftRow(state, 2, 2)
	shiftRow(state, 3, 3)
	fmt.Printf("ShiftRows:\n state: %x\n", state)
}

func (r *Rijndael) invShiftRows(state []byte) {
	shiftRow(state, 1, 3)
	shiftRow(state, 2, 2)
	shiftRow(state, 3, 1)
}

func gmul(a byte, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b // Полином x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

func mulWord(w []byte, matrix []byte) {
	tmp := make([]byte, 4)
	copy(tmp, w)

	w[0] = gmul(tmp[0], matrix[3]) ^ gmul(tmp[1], matrix[0]) ^ gmul(tmp[2], matrix[1]) ^ gmul(tmp[3], matrix[2])
	w[1] = gmul(tmp[0], matrix[2]) ^ gmul(tmp[1], matrix[3]) ^ gmul(tmp[2], matrix[0]) ^ gmul(tmp[3], matrix[1])
	w[2] = gmul(tmp[0], matrix[1]) ^ gmul(tmp[1], matrix[2]) ^ gmul(tmp[2], matrix[3]) ^ gmul(tmp[3], matrix[0])
	w[3] = gmul(tmp[0], matrix[0]) ^ gmul(tmp[1], matrix[1]) ^ gmul(tmp[2], matrix[2]) ^ gmul(tmp[3], matrix[3])
}

func (r *Rijndael) mixColumns(state []byte) {
	s := []byte{0x03, 0x01, 0x01, 0x02}
	for i := 0; i < encryption.BlockSize; i += encryption.WordSize {
		mulWord(state[i:i+encryption.WordSize], s)
	}
	fmt.Printf("MixColumns:\n state: %x\n", state)
}

func (r *Rijndael) invMixColumns(state []byte) {
	s := []byte{0x0b, 0x0d, 0x09, 0x0e}
	for i := 0; i < encryption.BlockSize; i += encryption.WordSize {
		mulWord(state[i:i+encryption.WordSize], s)
	}
}

func (r *Rijndael) encryptBlock(block []byte) []byte {
	encryptedBlock := make([]byte, len(block))
	copy(encryptedBlock, block)
	r.addRoundKey(encryptedBlock, r.keySchedule[0:4])
	for i := 0; i < r.nr-1; i++ {
		r.subBytes(encryptedBlock)
		r.shiftRows(encryptedBlock)
		r.mixColumns(encryptedBlock)
		r.addRoundKey(encryptedBlock, r.keySchedule[4*(i+1):4*(i+1)+4])
		round := i + 1
		fmt.Printf("After Round: %d\n state: %x\n\n", round, encryptedBlock)
	}
	r.subBytes(encryptedBlock)
	r.shiftRows(encryptedBlock)
	r.addRoundKey(encryptedBlock, r.keySchedule[4*r.nr:4*r.nr+4])
	return encryptedBlock
}

func (r *Rijndael) decryptBlock(block []byte) []byte {
	encryptedBlock := make([]byte, len(block))
	copy(encryptedBlock, block)
	r.addRoundKey(encryptedBlock, r.keySchedule[4*r.nr:4*r.nr+4])
	for i := r.nr - 1; i > 0; i-- {
		r.invShiftRows(encryptedBlock)
		r.invSubBytes(encryptedBlock)
		r.addRoundKey(encryptedBlock, r.keySchedule[4*i:4*i+4])
		r.invMixColumns(encryptedBlock)
		round := i + 1
		fmt.Printf("After Round: %d\n state: %x\n\n", round, encryptedBlock)
	}
	r.invShiftRows(encryptedBlock)
	r.invSubBytes(encryptedBlock)
	r.addRoundKey(encryptedBlock, r.keySchedule[0:4])
	return encryptedBlock
}

// EncryptECB ECB на вход функции должны преходить уже выровненные данные
// len(data) должен быть кратен 4
func (r *Rijndael) EncryptECB(data []byte) []byte {
	encryptedData := make([]byte, 0, len(data))
	paddedData := utils.Pkcs7Padding(data, 16)
	r.keyExpansion()
	for i := 0; i < len(paddedData); i += encryption.BlockSize {
		encryptedData = append(encryptedData,
			r.encryptBlock(paddedData[i:i+encryption.BlockSize])...)
	}
	return encryptedData
}
func (r *Rijndael) DecryptECB(data []byte) []byte {
	decryptedData := make([]byte, 0, len(data))
	r.keyExpansion()
	for i := 0; i < len(data); i += encryption.BlockSize {
		decryptedData = append(decryptedData,
			r.decryptBlock(data[i:i+encryption.BlockSize])...)
	}
	return utils.Pkcs7UnPadding(decryptedData)
}
