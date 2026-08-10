# onepassword-access-cli

A local vibe coded test client for the 1Password access module in Bitwarden's
[sdk-internal](https://github.com/bitwarden/sdk-internal). It logs in to a real 1Password account,
downloads every vault, and prints the decrypted contents.

The module's own tests pin the crypto with known-answer vectors and the HTTP flows with `wiremock`,
but only a real account proves the protocol end to end. This is that check.

## Layout

The crate is consumed by path, so it must sit next to `sdk-internal`:

```
~/devel/bitwarden/
├── sdk-internal/       # the SDK, with crates/bitwarden-importers
└── onepassword-cli/    # this repo
```

## Build

```bash
cargo build
```

## Run

```bash
cp config.toml.example config.toml   # fill in a real account
make run accounts                    # list the configured accounts, no secrets printed
make run                             # download and print every vault
make run my-account                  # a named account
make run PROXY=http://localhost:8888 # through a MITM proxy, TLS verification off
```

`config.toml` holds the credentials and is git-ignored. The dump prints passwords, TOTP secrets and
SSH private keys in full: it is for inspecting your own account.

Only accounts whose second factor is an authenticator app work. Duo and WebAuthn are not
implemented and report `unsupported: account requires an unsupported 2FA method`.
