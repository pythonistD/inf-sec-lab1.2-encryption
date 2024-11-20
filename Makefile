.DEFAULT_GOAL := build
.PHONY: fmt lint vet build
fmt:
	go fmt ./...
lint: fmt
	golint ./...
vet: fmt
	go vet ./...
build:
	go build -o ./bin/encryptionApp ./cmd/encryptionApp/main.go
exec: build
	./bin/encryptionApp/main.exe
