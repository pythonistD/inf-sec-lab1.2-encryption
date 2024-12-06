package cli

import (
	"bufio"
	"fmt"
	"github.com/pythonistD/inf-sec-lab1.1-encryption/pkg/encrypt"
	"io"
	"os"
	"strconv"
	"strings"
)
import (
	"github.com/pythonistD/inf-sec-lab1.1-encryption/internal/fileio"
	"github.com/pythonistD/inf-sec-lab1.1-encryption/pkg/dto"
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

func getChars(desc io.Reader) []rune {
	scanner := bufio.NewScanner(desc)
	var lines []rune
	for scanner.Scan() {
		line := []rune(scanner.Text())
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

func Execute() {
	var dataToWrite []rune

	mod := cryptOrDecrypt()
	fmt.Printf("Выбран режим: %s\n", mod)
	lang := selectLang()
	keyword := getKeyword()
	chars := getChars(getFileDescriptor())
	shift, _ := strconv.Atoi(getShift())
	inputDataDto := dto.InputDataDto{Symbols: chars, Shift: shift, Keyword: keyword, Lang: lang}
	if mod == "1" {
		encryptTable, err := encrypt.CreateEncryptTable(inputDataDto)
		if err != nil {
			fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
		}
		encryptedData, err := encrypt.CaesarCipherEncrypt(chars, encryptTable)
		dataToWrite = []rune(encryptedData)
		if err != nil {
			fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
		}
	} else if mod == "2" {
		encryptTable, err := encrypt.CreateEncryptTable(inputDataDto)
		decryptTable, err := encrypt.CreateDecryptTable(encryptTable)
		if err != nil {
			fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
		}
		decryptedData, err := encrypt.CaesarCipherDecrypt(chars, decryptTable)
		dataToWrite = []rune(decryptedData)
		if err != nil {
			fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
		}
	}
	err := fileio.WriteText(dataToWrite, "./files/outData.txt")
	if err != nil {
		fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
	}
}
