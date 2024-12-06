package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/pythonistD/inf-sec-lab1.2-encryption/pkg/encryption/algorithms"
	"github.com/pythonistD/inf-sec-lab1.2-encryption/pkg/encryption/utils"
	"io"
	"os"
	"strconv"
	"strings"
)

func cryptOrDecrypt() string {
	var flag = true
	var mod string
	var err error
	for flag {
		fmt.Println("1: Зашифровать\n2: Расшифровать")
		_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if mod != "1" && mod != "2" {
			fmt.Printf("Для выбора режима "+
				"необходимо выбрать 1 или 2, a не %v\n", mod)
			continue
		}
		flag = false
	}
	return mod
}

func fromCmdOrFile() string {
	var flag = true
	var mod string
	var err error
	for flag {
		fmt.Println("1: Ручной ввод(в консоль)\n2: Чтение из файла")
		_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if mod != "1" && mod != "2" {
			fmt.Printf("Для выбора режима "+
				"необходимо выбрать 1 или 2, a не %v\n", mod)
			continue
		}
		flag = false
	}
	return mod
}

func selectLang() string {
	var flag = true
	var mod string
	var err error
	for flag {
		fmt.Println("1: Русский\n2: Английский")
		_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if mod != "1" && mod != "2" {
			fmt.Printf("Для выбора режима "+
				"необходимо выбрать 1 или 2, a не %v\n", mod)
			continue
		}
		flag = false
	}
	if mod == "1" {
		return "ru"
	} else {
		return "en"
	}
}

func getShift() string {
	var flag = true
	var mod string
	var err error
	var n int
	for flag {
		fmt.Println("Введите Ключ шифрования - значение сдвига N")
		_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if n, err = strconv.Atoi(mod); err != nil {
			fmt.Printf("Необходимо ввести одно число"+
				"без пробелов, а не %v\n", mod)
			continue
		} else if n <= 0 {
			fmt.Println("Значение сдвига должное быть > 0")
			continue
		}
		flag = false
	}
	return mod
}
func getKeyword() string {
	var flag = true
	var mod string
	var err error
	for flag {
		fmt.Println("Введите ключевое слово:")
		_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if strings.TrimSpace(mod) == "" {
			fmt.Printf("Необходимо ввести одно ключевое слово"+
				", а не %v", mod)
			continue
		}
		flag = false
	}
	return mod
}

func getChars(desc io.Reader) []byte {
	scanner := bufio.NewScanner(desc)
	var lines []byte
	for scanner.Scan() {
		line := []byte(scanner.Text())
		line = append(line, '\n')
		lines = append(lines, line...)
	}
	fmt.Println("Содержимое файла:")
	fmt.Println("________________________")
	for _, v := range lines {
		fmt.Printf("%c", v)
	}
	fmt.Println("________________________")
	return lines
}

func getFileDescriptor() io.Reader {
	var flag = true
	var mod string
	var err error
	var desc io.Reader
	for flag {
		//fmt.Println("Введите путь до файла")
		//_, err = fmt.Scan(&mod)
		if err != nil {
			fmt.Println(err)
			continue
		}
		mod = "files/inData.txt"
		//mod = "files/outData.txt"
		if desc, err = os.Open(mod); err != nil {
			fmt.Printf("Ошибка чтения файла: %v\n", err)
			continue
		}
		flag = false
	}
	return desc
}

func hexStringToBytes(hexStr string) ([]byte, error) {
	// Декодирование строки в массив байт
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func Execute() {
	//var dataToWrite []rune

	mod := cryptOrDecrypt()
	fmt.Printf("Выбран режим: %s\n", mod)
	//lang := selectLang()
	keyword := getKeyword()
	chars := getChars(getFileDescriptor())

	paddedKey, _ := utils.PaddingKey([]byte(keyword), 16)
	r, _ := algorithms.NewRijndael(paddedKey)
	if mod == "1" {
		encrypted := r.EncryptECB(chars)
		fmt.Printf("Encrypted Data: %x", encrypted)
	} else if mod == "2" {
		s := string(chars)
		hexS, _ := hexStringToBytes(strings.TrimSpace(s))
		decrypted := r.DecryptECB(hexS)
		fmt.Printf("Decrypted Data: %s", string(decrypted))
	}
	/*err := fileio.WriteText(dataToWrite, "./files/outData.txt")
	if err != nil {
		fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
	}*/
}
