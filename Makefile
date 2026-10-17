all: tools test gosec

build:
	go build ./...

test:
	go test ./... -coverpkg=./... -count=1 -coverprofile test-coverage.out

gosec:
	gosec ./...

tools:
	go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0

.PHONY: \
	all \
	build \
	tools \
	test \
	gosec
