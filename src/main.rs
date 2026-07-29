//! Interactive client for driving `bitwarden-onepassword` against a real 1Password account.
//!
//! It exists so the SDK crate can be exercised end to end without a Bitwarden server: log in with
//! real credentials, download the vaults, and print the decrypted native model.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bitwarden_onepassword::model::{Field, Item, Vault};
use bitwarden_onepassword::{
    Client, Credentials, Region, Session, TotpResult, TwoFactorUi, generate_device_uuid,
};
use clap::{Parser, Subcommand};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha1::Sha1;

/// Local test client for the 1Password direct importer.
#[derive(Parser)]
#[command(name = "onepassword-cli", about, version)]
struct Cli {
    /// Path to the TOML config holding the accounts.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Which account to use. Defaults to the config's `default`, or to the only account when there
    /// is just one.
    #[arg(long, short)]
    account: Option<String>,

    /// Route all traffic through an HTTP proxy (e.g. http://localhost:8888 for Charles). Disables
    /// TLS certificate verification so a MITM debugging proxy can decrypt the traffic.
    #[arg(long)]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the accounts in the config.
    Accounts,
    /// Log in to 1Password and establish a session.
    Login,
    /// List the vaults accessible to the account.
    ListVaults,
    /// Download and print every vault and item in the native 1Password model.
    Dump,
}

/// The config file: a set of named accounts plus which one to use when none is given.
#[derive(Debug, Deserialize)]
struct Config {
    default: Option<String>,
    accounts: BTreeMap<String, Account>,
}

/// One account's credentials and connection settings.
#[derive(Debug, Deserialize)]
struct Account {
    username: String,
    password: String,
    secret_key: String,
    domain: Option<String>,
    device_id: Option<String>,
    proxy: Option<String>,
    totp_secret: Option<String>,
}

impl Config {
    /// Picks the requested account, falling back to `default` and then to the only account.
    fn select(mut self, name: Option<&str>) -> Result<(String, Account)> {
        let name = match name.map(str::to_string).or_else(|| self.default.clone()) {
            Some(name) => name,
            None if self.accounts.len() == 1 => self
                .accounts
                .keys()
                .next()
                .cloned()
                .expect("checked there is exactly one"),
            None => anyhow::bail!(
                "no account given and no `default` in the config; pick one of: {}",
                self.names()
            ),
        };

        let names = self.names();
        self.accounts
            .remove(&name)
            .map(|account| (name.clone(), account))
            .with_context(|| format!("no account named '{name}' in the config; found: {names}"))
    }

    fn names(&self) -> String {
        self.accounts.keys().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse config file {}", path.display()))
}

/// Prints the configured accounts without revealing any secrets.
fn list_accounts(config: &Config) -> Result<()> {
    if config.accounts.is_empty() {
        println!("No accounts in the config.");
        return Ok(());
    }

    let width = config
        .accounts
        .keys()
        .map(|name| name.chars().count())
        .max()
        .unwrap_or(0);

    for (name, account) in &config.accounts {
        let marker = if config.default.as_deref() == Some(name.as_str()) {
            "*"
        } else {
            " "
        };
        let domain = account.domain.as_deref().unwrap_or("my.1password.com");
        let totp = if account.totp_secret.is_some() {
            "totp"
        } else {
            "no totp"
        };
        println!(
            "{marker} {name:<width$}  {}  ({domain}, {totp})",
            account.username
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        config,
        account,
        proxy,
        command,
    } = Cli::parse();

    let config = load_config(&config)?;
    if matches!(command, Command::Accounts) {
        return list_accounts(&config);
    }

    let (name, account) = config.select(account.as_deref())?;
    println!("Using account '{name}' ({}).", account.username);

    match command {
        Command::Accounts => unreachable!("handled above"),
        Command::Login => login(name, account, proxy).await,
        Command::ListVaults => list_vaults(name, account, proxy).await,
        Command::Dump => dump(name, account, proxy).await,
    }
}

async fn authenticate(name: String, account: Account, proxy: Option<String>) -> Result<Session> {
    let device_uuid = match account.device_id {
        Some(id) => id,
        None => {
            let id = generate_device_uuid();
            println!("No device id for '{name}'; generated a new one: {id}");
            println!("Add `device_id = \"{id}\"` under [accounts.{name}] to reuse it next time.");
            id
        }
    };

    let region = account
        .domain
        .as_deref()
        .map_or(Region::Global, Region::parse);
    let credentials = Credentials {
        username: account.username,
        password: account.password,
        account_key: account.secret_key,
        domain: region.domain().to_string(),
        device_uuid,
    };

    let ui = CliTwoFactorUi {
        totp_secret: account.totp_secret,
    };
    let http = build_http_client(proxy.or(account.proxy).as_deref())?;
    Client::new(http)
        .login(&credentials, &ui)
        .await
        .context("login failed")
}

/// Supplies TOTP codes from `totp_secret` when present, otherwise prompts on stdin. Implements the
/// library's [`TwoFactorUi`] callback for the CLI.
struct CliTwoFactorUi {
    totp_secret: Option<String>,
}

#[async_trait]
impl TwoFactorUi for CliTwoFactorUi {
    async fn provide_totp(&self, attempt: u32) -> TotpResult {
        if let Some(secret) = &self.totp_secret {
            match generate_totp(secret) {
                Ok(passcode) => {
                    println!(
                        "Submitting a generated TOTP code (attempt {}).",
                        attempt + 1
                    );
                    return TotpResult::Code {
                        passcode,
                        remember_me: false,
                    };
                }
                Err(error) => eprintln!("Failed to generate a TOTP code: {error:#}"),
            }
        }

        print!("Enter the TOTP code (attempt {}): ", attempt + 1);
        if io::stdout().flush().is_err() {
            return TotpResult::Cancel;
        }
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => TotpResult::Cancel,
            Ok(_) => match line.trim() {
                "" => TotpResult::Cancel,
                code => TotpResult::Code {
                    passcode: code.to_string(),
                    remember_me: false,
                },
            },
        }
    }
}

/// Generates the current 6-digit TOTP for a base32 secret (RFC 6238, SHA-1, 30-second step).
fn generate_totp(secret: &str) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    generate_totp_at(secret, now)
}

fn generate_totp_at(secret: &str, unix_time: u64) -> Result<String> {
    let normalized = secret.trim().replace(' ', "").to_uppercase();
    let key = BASE32_NOPAD
        .decode(normalized.trim_end_matches('=').as_bytes())
        .context("invalid base32 TOTP secret")?;

    let counter = (unix_time / 30).to_be_bytes();
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&counter);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[19] & 0x0f) as usize;
    let binary = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);

    Ok(format!("{:06}", binary % 1_000_000))
}

async fn login(name: String, account: Account, proxy: Option<String>) -> Result<()> {
    let session = authenticate(name, account, proxy).await?;
    println!("Logged in as {}.", session.credentials().username);
    Ok(())
}

async fn list_vaults(name: String, account: Account, proxy: Option<String>) -> Result<()> {
    let mut session = authenticate(name, account, proxy).await?;
    let vaults = session
        .download_all_vaults()
        .await
        .context("failed to download vaults")?;

    for vault in &vaults {
        println!(
            "{} ({}) - {} item(s)",
            vault.name,
            vault.id,
            vault.items.len()
        );
    }
    Ok(())
}

async fn dump(name: String, account: Account, proxy: Option<String>) -> Result<()> {
    let mut session = authenticate(name, account, proxy).await?;
    let vaults = session
        .download_all_vaults()
        .await
        .context("failed to download vaults")?;

    print_vaults(&vaults);
    Ok(())
}

const BOLD: &str = "1";
const DIM: &str = "2";
const CYAN: &str = "36";
const YELLOW: &str = "33";

/// Prints every vault and item in the native model, including secret values. This is a local tool
/// for inspecting the user's own account, so it shows the decrypted data in full.
fn print_vaults(vaults: &[Vault]) {
    if vaults.is_empty() {
        println!("No accessible vaults.");
        return;
    }

    let color = io::stdout().is_terminal();
    let items: usize = vaults.iter().map(|vault| vault.items.len()).sum();
    println!(
        "{}",
        paint(
            &format!(
                "{} {} · {items} {}",
                vaults.len(),
                plural(vaults.len(), "vault"),
                plural(items, "item")
            ),
            DIM,
            color,
        )
    );

    for vault in vaults {
        print_vault(vault, color);
    }
}

fn print_vault(vault: &Vault, color: bool) {
    let count = vault.items.len();
    let rule = "─".repeat(72);

    println!();
    println!("{}", paint(&rule, DIM, color));
    println!(
        "{}   {}",
        paint(&vault.name, BOLD, color),
        paint(
            &format!("{count} {} · {}", plural(count, "item"), vault.id),
            DIM,
            color
        ),
    );
    println!("{}", paint(&rule, DIM, color));

    for item in &vault.items {
        print_item(item, color);
    }
}

fn print_item(item: &Item, color: bool) {
    println!();
    println!(
        "  {} {}   {}",
        paint("●", CYAN, color),
        paint(&item.title, BOLD, color),
        paint(&format!("[{}]", item.category), CYAN, color),
    );

    prop("id", &item.id, color);
    if !item.additional_info.is_empty() {
        prop("info", &item.additional_info, color);
    }
    if !item.username.is_empty() {
        prop("username", &item.username, color);
    }
    if !item.password.is_empty() {
        prop("password", &item.password, color);
    }
    for (label, value) in unique_urls(item) {
        let shown = if label.is_empty() {
            value
        } else {
            format!("{value}  ({label})")
        };
        prop("url", &shown, color);
    }
    for otp in &item.otps {
        prop("otp", &format!("{} = {}", otp.label, otp.secret), color);
    }
    if !item.note.is_empty() {
        prop("note", &item.note.replace('\n', " "), color);
    }
    if let Some(ssh) = &item.ssh_key {
        prop(
            "ssh key",
            &format!("{} ({})", ssh.key_type, ssh.fingerprint),
            color,
        );
        if !ssh.public_key.is_empty() {
            prop("pubkey", &ssh.public_key, color);
        }
        if !ssh.private_key.is_empty() {
            println!("    {}", paint("private key", DIM, color));
            println!("{}", ssh.private_key);
        }
    }

    print_fields(&item.fields, color);
}

/// Prints one aligned `key   value` property line.
fn prop(key: &str, value: &str, color: bool) {
    println!("    {} {value}", paint(&format!("{key:<9}"), DIM, color));
}

/// Prints the section fields grouped under their section titles, with aligned labels.
fn print_fields(fields: &[Field], color: bool) {
    if fields.is_empty() {
        return;
    }

    let width = fields
        .iter()
        .map(|field| field.label.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, 28);

    let mut current: Option<&str> = None;
    for field in fields {
        if current != Some(field.section.as_str()) {
            current = Some(field.section.as_str());
            let header = if field.section.is_empty() {
                "Fields"
            } else {
                field.section.as_str()
            };
            println!("    {}", paint(header, YELLOW, color));
        }

        let label = if field.label.is_empty() {
            "—"
        } else {
            field.label.as_str()
        };
        let kind = if field.kind.is_empty() || field.kind == "string" {
            String::new()
        } else {
            paint(&format!("  ({})", field.kind), DIM, color)
        };
        println!(
            "      {} {}{kind}",
            paint(&format!("{label:<width$}"), DIM, color),
            field.value,
        );
    }
}

/// Collects an item's URLs (main URL first), dropping empties and duplicates.
fn unique_urls(item: &Item) -> Vec<(String, String)> {
    let mut urls: Vec<(String, String)> = Vec::new();
    let candidates = std::iter::once((String::new(), item.url.clone()))
        .chain(item.urls.iter().map(|u| (u.label.clone(), u.value.clone())));
    for (label, value) in candidates {
        if !value.is_empty() && !urls.iter().any(|(_, existing)| *existing == value) {
            urls.push((label, value));
        }
    }
    urls
}

/// Wraps `text` in an ANSI color code when writing to a terminal, otherwise returns it unchanged.
fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

fn build_http_client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy) = proxy {
        let proxy_config =
            reqwest::Proxy::all(proxy).with_context(|| format!("invalid proxy URL {proxy}"))?;
        builder = builder
            .proxy(proxy_config)
            .danger_accept_invalid_certs(true);
        eprintln!("Routing traffic through {proxy} with TLS verification disabled.");
    }
    builder.build().context("failed to build the HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_rfc6238_totp_codes() {
        // The RFC 6238 SHA-1 test secret ("12345678901234567890") in base32, with the 8-digit
        // reference values truncated to the 6 digits this generator produces.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let cases = [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ];
        for (time, expected) in cases {
            assert_eq!(
                generate_totp_at(secret, time).unwrap(),
                expected,
                "at {time}"
            );
        }
    }
}
