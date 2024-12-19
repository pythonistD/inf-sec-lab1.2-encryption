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
func writeBytesToFile(data []byte, filePath string) error {
	// Открываем файл для записи (если файл не существует - создаем)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("не удалось создать файл: %w", err)
	}
	defer file.Close()

	// Записываем байты в файл
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("ошибка записи в файл: %w", err)
	}
	return nil
}
func writeStringToFile(filePath string, content string) error {
	// Открываем файл в режиме записи (создаём, если не существует)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer file.Close()

	// Создаём буферизированный писатель
	writer := bufio.NewWriter(file)

	// Пишем строку в файл через буфер
	_, err = writer.WriteString(content)
	if err != nil {
		return fmt.Errorf("ошибка записи в файл: %w", err)
	}

	// Сбрасываем данные из буфера в файл
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("ошибка сброса буфера: %w", err)
	}
	return nil
}

func Execute() {
	var dataToWrite string

	mod := cryptOrDecrypt()
	fmt.Printf("Выбран режим: %s\n", mod)
	//lang := selectLang()
	keyword := getKeyword()
	chars := getChars(getFileDescriptor())

	paddedKey, _ := utils.PaddingKey([]byte(keyword), 16)
	r, _ := algorithms.NewRijndael(paddedKey)
	if mod == "1" {
		dataToWrite = hex.EncodeToString(r.EncryptECB(chars))
		fmt.Printf("Encrypted Data: %x", dataToWrite)
		err := writeStringToFile("C:\\Users\\user\\ProgrammingProjects\\GoProjects\\inf-sec-lab1.2-encryption\\files\\outData.txt", dataToWrite)
		if err != nil {
			fmt.Println("Ошибка записи в файл")
		}
		return
	} else if mod == "2" {
		s := string(chars)
		hexS, _ := hexStringToBytes(strings.TrimSpace(s))
		dataToWrite = string(r.DecryptECB(hexS))
		fmt.Printf("Decrypted Data: %s", string(dataToWrite))
		err := writeStringToFile("C:\\Users\\user\\ProgrammingProjects\\GoProjects\\inf-sec-lab1.2-encryption\\files\\outData.txt", dataToWrite)
		if err != nil {
			fmt.Println("Ошибка записи в файл")
		}
		return
	}
	err := writeStringToFile(dataToWrite, "./files/outData.txt")
	//err := fileio.WriteText(dataToWrite, "./files/outData.txt")
	if err != nil {
		fmt.Printf("Ошибка во время выполнения программы: %v\n", err)
	}
}
