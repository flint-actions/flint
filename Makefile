.PHONY: filesystem build

build:
	GOOS=linux GOARCH=amd64 go build .

filesystem:
	cd scripts && ./filesystem.sh

kernel:
	cd scripts && ./kernel.sh

lint:
	./scripts/shellcheck.sh

clean:
	rm -r build
	rm flint
