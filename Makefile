# `make run` downloads and prints the whole account. Words typed after `run` are the subcommand and
# the account, in either order:
#
#   make run accounts
#   make run my-account
#   make run my-account dump
#
# Add PROXY=http://localhost:8888 to watch the traffic through a debugging proxy.
ARGS ?= dump
ACCOUNT ?=
PROXY ?=

SUBCOMMANDS := accounts dump

# Everything typed after `run`. Make would otherwise try to build those words as targets, so they
# get no-op rules below.
ifneq ($(filter run,$(MAKECMDGOALS)),)
WORDS := $(filter-out run,$(MAKECMDGOALS))
ifneq ($(strip $(WORDS)),)
$(eval $(WORDS):;@:)
endif
endif

# A word that names a subcommand is the subcommand; anything else is the account name. Either falls
# back to the ARGS/ACCOUNT variables.
CMD := $(firstword $(filter $(SUBCOMMANDS),$(WORDS)) $(ARGS))
ACC := $(firstword $(filter-out $(SUBCOMMANDS),$(WORDS)) $(ACCOUNT))

PROXY_FLAG := $(if $(PROXY),--proxy $(PROXY),)
ACCOUNT_FLAG := $(if $(ACC),--account $(ACC),)

.DEFAULT_GOAL := build
.PHONY: build run test lint help

build:
	cargo build

run:
	cargo run -- $(PROXY_FLAG) $(ACCOUNT_FLAG) $(CMD)

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

help:
	@echo "build  compile the CLI"
	@echo "run    download and print an account, ARGS=dump by default"
	@echo "test   run the tests"
	@echo "lint   fmt and clippy"
	@echo ""
	@echo "make run accounts                     list the configured accounts"
	@echo "make run my-account                   dump a named account"
	@echo "make run PROXY=http://localhost:8888  dump through a MITM debugging proxy"
