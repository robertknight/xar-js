NODE_BIN_DIR=node_modules/.bin

all: build

build:
	$(NODE_BIN_DIR)/tsc

test:
	$(NODE_BIN_DIR)/mocha build/test/*.js

.PHONY: build test
