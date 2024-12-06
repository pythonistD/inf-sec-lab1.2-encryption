package fileio

import (
	"fmt"
	"os"
)

func WriteText(symbols []rune, pathToFile string) error {
	var file *os.File
	file, err := os.OpenFile(pathToFile, os.O_CREATE, 0666)
	if err != nil {
		err = fmt.Errorf("Ошибка чтения файла: %w\n", err)
		return err
	}
	text := string(symbols)
	_, err = file.WriteString(text)
	if err != nil {
		err = fmt.Errorf("Ошибка записи в файл: %w\n", err)
		return err
	}
	return nil
}
