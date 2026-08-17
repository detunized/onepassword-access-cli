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
use bitwarden_importers::onepassword_access::model::{Item, Vault};
use bitwarden_importers::onepassword_access::wire::{VaultItemOverview, VaultItemSectionField};
use bitwarden_importers::onepassword_access::{
    Client, Credentials, SignInAddress, SignInDomain, TotpResult, TwoFactorUi, generate_device_uuid,
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

/// The address an account signs in at when the config says nothing.
const DEFAULT_SIGN_IN_ADDRESS: &str = "my.1password.com";

/// Resolves what the config file holds: a domain shorthand, or a full sign-in address.
///
/// The SDK takes the subdomain and the domain apart, so a full address has to be split here.
fn sign_in_address(value: &str) -> Result<SignInAddress> {
    let value = value.trim().to_lowercase();

    let shorthand = match value.as_str() {
        "global" | "com" | "us" => Some(SignInDomain::Global),
        "europe" | "eu" => Some(SignInDomain::Europe),
        "canada" | "ca" => Some(SignInDomain::Canada),
        "enterprise" | "ent" => Some(SignInDomain::Enterprise),
        _ => None,
    };
    if let Some(domain) = shorthand {
        return Ok(SignInAddress::new("my", domain)?);
    }

    // Enterprise comes first: it ends in `.1password.com` too, and matching that one first would
    // leave `acme.ent` as the subdomain.
    let domains = [
        SignInDomain::Enterprise,
        SignInDomain::Global,
        SignInDomain::Europe,
        SignInDomain::Canada,
    ];
    for domain in domains {
        if let Some(subdomain) = value.strip_suffix(&format!(".{}", domain.as_str())) {
            return Ok(SignInAddress::new(subdomain, domain)?);
        }
    }

    anyhow::bail!("'{value}' is not a 1Password sign-in address")
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
        let domain = account.domain.as_deref().unwrap_or(DEFAULT_SIGN_IN_ADDRESS);
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

#[tokio::main(flavor = "current_thread")]
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
        Command::Dump => dump(name, account, proxy).await,
    }
}

/// Builds everything a command needs: the client, the credentials and the 2FA callback.
fn prepare(
    name: String,
    account: Account,
    proxy: Option<String>,
) -> Result<(Client, Credentials, CliTwoFactorUi)> {
    let device_uuid = match account.device_id {
        Some(id) => id,
        None => {
            let id = generate_device_uuid();
            println!("No device id for '{name}'; generated a new one: {id}");
            println!("Add `device_id = \"{id}\"` under [accounts.{name}] to reuse it next time.");
            id
        }
    };

    let credentials = Credentials {
        username: account.username,
        password: account.password,
        account_key: account.secret_key,
        sign_in_address: sign_in_address(
            account.domain.as_deref().unwrap_or(DEFAULT_SIGN_IN_ADDRESS),
        )?,
        device_uuid,
    };

    let ui = CliTwoFactorUi {
        totp_secret: account.totp_secret,
    };
    let http = build_http_client(proxy.or(account.proxy).as_deref())?;

    Ok((Client::new(http), credentials, ui))
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
                    return TotpResult::Code(passcode);
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
                code => TotpResult::Code(code.to_string()),
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

async fn dump(name: String, account: Account, proxy: Option<String>) -> Result<()> {
    let (client, credentials, ui) = prepare(name, account, proxy)?;
    let vaults = client
        .download_all_vaults(&credentials, &ui)
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
    let overview = &item.overview;
    let details = &item.details;

    println!();
    println!(
        "  {} {}   {}",
        paint("●", CYAN, color),
        paint(
            overview.title.as_deref().unwrap_or("(untitled)"),
            BOLD,
            color
        ),
        paint(&format!("[{}]", item.category), CYAN, color),
    );

    prop("id", &item.id, color);
    opt_prop("info", overview.ainfo.as_deref(), color);

    // The designation fields: a login's username and password.
    for field in details.fields.iter().flatten() {
        let label = field
            .designation
            .as_deref()
            .or(field.name.as_deref())
            .unwrap_or("field");
        opt_prop(label, field.value.as_deref(), color);
    }
    // A Password item keeps its secret here instead.
    opt_prop("password", details.password.as_deref(), color);

    for (label, value) in unique_urls(overview) {
        let shown = if label.is_empty() {
            value
        } else {
            format!("{value}  ({label})")
        };
        prop("url", &shown, color);
    }

    if let Some(tags) = &overview.tags
        && !tags.is_empty()
    {
        prop("tags", &tags.join(", "), color);
    }
    if let Some(note) = &details.note
        && !note.is_empty()
    {
        prop("note", &note.replace('\n', " "), color);
    }
    for past in details.password_history.iter().flatten() {
        let value = past.value.as_deref().unwrap_or("");
        prop(
            "was",
            &format!("{value}  (at {})", past.time.unwrap_or(0)),
            color,
        );
    }

    print_sections(item, color);
}

/// Prints one aligned `key   value` property line.
fn prop(key: &str, value: &str, color: bool) {
    println!("    {} {value}", paint(&format!("{key:<9}"), DIM, color));
}

/// Prints a property only when it carries a non-empty value.
fn opt_prop(key: &str, value: Option<&str>, color: bool) {
    if let Some(value) = value
        && !value.is_empty()
    {
        prop(key, value, color);
    }
}

/// Prints every section with its fields, and unpacks any SSH key attributes.
fn print_sections(item: &Item, color: bool) {
    for section in item.details.sections.iter().flatten() {
        let fields: Vec<_> = section.fields.iter().flatten().collect();
        if fields.is_empty() {
            continue;
        }

        let header = section
            .name
            .as_deref()
            .filter(|t| !t.is_empty())
            .unwrap_or("Fields");
        println!("    {}", paint(header, YELLOW, color));

        let width = fields
            .iter()
            .map(|f| f.name.as_deref().unwrap_or("").chars().count())
            .max()
            .unwrap_or(0)
            .clamp(4, 28);

        for field in fields {
            let label = field
                .name
                .as_deref()
                .filter(|t| !t.is_empty())
                .unwrap_or("—");
            let kind = match field.kind.as_deref() {
                None | Some("string") => String::new(),
                Some(kind) => paint(&format!("  ({kind})"), DIM, color),
            };
            println!(
                "      {} {}{kind}",
                paint(&format!("{label:<width$}"), DIM, color),
                field_value(field),
            );

            if let Some(ssh) = field.attributes.as_ref().and_then(|a| a.ssh_key.as_ref()) {
                opt_prop("fingerprint", ssh.fingerprint.as_deref(), color);
                opt_prop("pubkey", ssh.public_key.as_deref(), color);
                if let Some(private_key) = &ssh.private_key {
                    println!("    {}", paint("private key", DIM, color));
                    println!("{private_key}");
                }
            }
        }
    }
}

/// Renders a section field's polymorphic value: strings pass through, anything else as JSON.
fn field_value(field: &VaultItemSectionField) -> String {
    match &field.value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Collects an item's URLs (main URL first), dropping empties and duplicates.
fn unique_urls(overview: &VaultItemOverview) -> Vec<(String, String)> {
    let mut urls: Vec<(String, String)> = Vec::new();
    let candidates = std::iter::once((String::new(), overview.url.clone().unwrap_or_default()))
        .chain(overview.urls.iter().flatten().map(|u| {
            (
                u.name.clone().unwrap_or_default(),
                u.url.clone().unwrap_or_default(),
            )
        }));
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
