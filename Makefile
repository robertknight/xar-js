NODE_BIN_DIR=node_modules/.bin

all: build

clean:
	rm -rf build

build:
	$(NODE_BIN_DIR)/tsc

test:
	$(NODE_BIN_DIR)/mocha build/test/*.js

.PHONY: build test
