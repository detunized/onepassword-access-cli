# onepassword-cli

Interactive client for driving [`bitwarden-onepassword`](../sdk-internal/crates/bitwarden-onepassword)
against a real 1Password account.

The SDK crate's own tests cover the crypto primitives with known-answer vectors and the HTTP flows
with `wiremock`, but the protocol is unforgiving and only a real account proves it end to end. This
repo is that check. It lives outside `sdk-internal` so nothing about it ships.

It consumes the crate by path, so it always builds whatever is currently checked out next door:

```toml
bitwarden-onepassword = { path = "../sdk-internal/crates/bitwarden-onepassword" }
```

## Usage

```bash
cp config.toml.example config.toml   # then fill in real credentials
make run ARGS=accounts PROXY=        # list the configured accounts
make run ARGS=login PROXY=           # SRP + Secret Key + TOTP, session established
make run ARGS=list-vaults PROXY=     # keychain + keyset decrypt, vault attributes
make run ARGS=dump PROXY=            # every vault and item decrypted into the native model
```

The config holds several named accounts and marks one `default`. Pick another with
`ARGS="-a business-duo login"`, or `make 1p ACCOUNT=business-duo` from `~/devel/bitwarden`.

`config.toml` is git-ignored. `dump` prints decrypted secrets in full, which is the point: it is a
local tool for inspecting your own account.

Only accounts whose second factor is an authenticator app work. The crate does not implement Duo or
WebAuthn, and reports `unsupported: account requires an unsupported 2FA method` on those.

Drop `PROXY=` to route traffic through a MITM debugging proxy on `http://localhost:8888` (Charles,
Proxyman, mitmproxy). That disables TLS verification, so only use it against your own traffic.

## Where this came from

The importer was originally built in a standalone workspace (`~/devel/1p-rs`) and then imported into
`sdk-internal`. This CLI is that workspace's test client, pointed at the imported crate. The
`convert` subcommand is gone for now: mapping the native model onto Bitwarden ciphers has not been
imported yet.
