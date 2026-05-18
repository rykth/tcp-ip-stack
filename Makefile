.PHONY: build test test-short lint fmt vet coverage

build:
	go build ./...

test:
	go test -race -count=1 ./...

test-short:
	go test -short -race ./...

test-integration:
	sudo -E go test -tags=integration -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
