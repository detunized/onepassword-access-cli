# `make run` dumps the whole account through a debugging proxy. Override the command with ARGS
# (`make run ARGS=login`), disable the proxy with `make run PROXY=`, or point it elsewhere with
# `make run PROXY=http://localhost:9090`.
PROXY ?= http://localhost:8888
ARGS ?= dump

PROXY_FLAG := $(if $(PROXY),--proxy $(PROXY),)

.PHONY: build run test lint

build:
	cargo build

run:
	cargo run -- $(PROXY_FLAG) $(ARGS)

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
