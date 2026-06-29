//! Vault commands: show, get, add, remove, open, close, purge.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Context;
use arboard::Clipboard;

use crate::secrets::{
    decode_base64, decrypt, encode_base64, encrypt, get_unlocked_key,
    gen_salt, lock, master_hash, unlock,
};
use crate::storage::{get_json, write_json};
use crate::structs::{CSVfile, File, IndividualService};
use crate::ui::{
    display_services, obscure_cipher, print_vault_open_hint, prompt_choose_entry,
    prompt_confirm_bulk_add, prompt_confirm_copy_to_clipboard, prompt_confirm_remove,
    prompt_confirm_remove_all, prompt_master_password, prompt_new_master_password,
    prompt_purge, prompt_service_password,
};

/// Creates the vault file on first run by prompting for a new master password.
pub fn new_user() -> anyhow::Result<()> {
    let password = prompt_new_master_password()?;
    let user: String = whoami::username()?;

    let salt = gen_salt();
    let stored_salt = salt.to_string();
    let (_, auth) = master_hash(&password, &salt);

    let first = File {
        master_password: auth,
        user,
        salt: stored_salt,
        vault: vec![],
    };
    write_json(&first).context("Error creating new json file")?;
    Ok(())
}

/// Handles the `add` command, dispatching to bulk/generated/clipboard/manual add.
pub fn handle_add(
    clipboard: &mut Clipboard,
    f: Option<PathBuf>,
    s: Option<String>,
    u: Option<String>,
    generate: bool,
    from_clipboard: bool,
) -> anyhow::Result<()> {
    let enc = get_unlocked_key()?;

    if let Some(f) = f {
        bulk_add(f, enc)
    } else if generate {
        add_generate(clipboard, s, u, enc)
    } else if from_clipboard {
        clipboard_add(s, u, enc)
    } else {
        manual_add(s, u, enc)
    }
}

/// Handles the `get` command: finds matching entries and copies the password to the clipboard.
pub fn handle_get(c: &mut Clipboard, s: Option<String>, u: Option<String>) -> anyhow::Result<()> {
    let mut vault = get_json()?.vault;
    vault = get_service_vec_service(&s, vault);
    vault = get_service_vec_user(&u, vault);

    if vault.len() == 1 {
        password_to_clipboard_check(c, vault.first())?;
    } else {
        let vault_obsc = obscure_cipher(&vault);
        println!("multiple entries matched your search");
        display_services(&vault_obsc);
        if !vault.is_empty() {
            password_to_clipboard_check(c, prompt_choose_entry(&vault))?;
        }
    }
    return Ok(());

    fn password_to_clipboard_check(c: &mut Clipboard, o: Option<&IndividualService>) -> anyhow::Result<()> {
        match o {
            Some(e) => match password_to_clipboard(c, e) {
                Ok(_) => {
                    println!("Password copied to clipboard");
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Err(e) => println!("Error copying to clipboard: {e}"),
            },
            None => println!("process has been aborted"),
        }
        Ok(())
    }
}

/// Decrypts an entry's password and copies it to the clipboard, reopening the vault if needed.
fn password_to_clipboard(c: &mut Clipboard, entry: &IndividualService) -> anyhow::Result<()> {
    if get_unlocked_key().is_err() {
        println!("reopen vault before continuing");
        open_vault()?;
    }
    let enc = get_unlocked_key()?;

    let plaintext = decrypt(
        &decode_base64(&enc),
        &entry.service_nonce,
        &entry.service_cipher,
    )
    .context("Decryption failed")?;

    c.set_text(plaintext)?;
    Ok(())
}

/// Handles the `show` command: lists passwords for a service, masked by default.
pub fn handle_show(n: Option<String>, all: bool) -> anyhow::Result<()> {
    let vault = get_json()?.vault;
    if !all {
        let mut services = get_service_vec_service(&n, vault);
        services = obscure_cipher(&services);
        println!(
            "Passwords hidden by default. include flag --all to show the passwords in plaintext"
        );
        display_services(&services);
    } else {
        let mut services = get_service_vec_service(&n, vault);
        let plain_pass = decrypt_entries(&services)?;
        for (serv, pass) in services.iter_mut().zip(plain_pass.iter()) {
            serv.service_cipher = pass.clone();
        }
        display_services(&services);
    }
    Ok(())
}

/// Decrypts the password of every given entry.
fn decrypt_entries(s: &Vec<IndividualService>) -> anyhow::Result<Vec<String>> {
    let enc = get_unlocked_key()?;
    let mut res = Vec::new();
    for e in s {
        match decrypt(&decode_base64(&enc), &e.service_nonce, &e.service_cipher) {
            Ok(s) => res.push(s),
            Err(e) => println!("error decrypting password from entry: {e}"),
        }
    }
    Ok(res)
}

/// Filters a vault entry list to those whose service name contains the given string.
fn get_service_vec_service(s: &Option<String>, v: Vec<IndividualService>) -> Vec<IndividualService> {
    match s {
        Some(name) => v.into_iter().filter(|x| x.service_name.contains(name)).collect(),
        None => v,
    }
}

/// Filters a vault entry list to those whose username contains the given string.
fn get_service_vec_user(s: &Option<String>, v: Vec<IndividualService>) -> Vec<IndividualService> {
    match s {
        Some(name) => v.into_iter().filter(|x| x.service_username.contains(name)).collect(),
        None => v,
    }
}

/// Manually adds a password entry by prompting the user for it.
fn manual_add(s: Option<String>, u: Option<String>, e: String) -> anyhow::Result<()> {
    let service_name = s.unwrap_or_default();
    let user_name = u.unwrap_or_default();
    println!("adding entry: service: {} | user: {}", service_name, user_name);
    let pass = prompt_service_password();
    let (cipher, nonce) = encrypt(&decode_base64(&e), pass)?;
    add_to_vault(encode_base64(nonce), service_name, user_name, encode_base64(cipher))
}

/// Adds a password entry using a randomly generated password.
fn add_generate(clipboard: &mut Clipboard, s: Option<String>, u: Option<String>, e: String) -> anyhow::Result<()> {
    let service_name = s.unwrap_or_default();
    let user_name = u.unwrap_or_default();

    let password = gen_plain_password();
    let (cipher, nonce) = encrypt(&decode_base64(&e), password.clone())?;
    add_to_vault(encode_base64(nonce), service_name, user_name, encode_base64(cipher))?;

    if prompt_confirm_copy_to_clipboard()? {
        clipboard.set_text(password)?;
        println!("Password copied to clipboard");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    Ok(())
}

/// Adds a password entry using whatever text is currently in the clipboard.
fn clipboard_add(s: Option<String>, u: Option<String>, e: String) -> anyhow::Result<()> {
    let password = Clipboard::new()
        .context("Failed to initialize clipboard")?
        .get_text()
        .context("Failed to read from clipboard")?;
    let service_name = s.unwrap_or_default();
    let user_name = u.unwrap_or_default();
    println!("adding entry: service: {} | user: {} (password from clipboard)", service_name, user_name);
    let (cipher, nonce) = encrypt(&decode_base64(&e), password)?;
    add_to_vault(encode_base64(nonce), service_name, user_name, encode_base64(cipher))
}

/// Generates a random plaintext password.
fn gen_plain_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789)(*&^%$#@!";
    let mut rng = rand::thread_rng();
    (0..12)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Appends a new entry to the vault file, keeping it sorted by service name.
fn add_to_vault(
    service_nonce: String,
    service_name: String,
    service_username: String,
    service_password: String,
) -> anyhow::Result<()> {
    let mut f = get_json()?;
    f.vault.push(IndividualService {
        service_nonce,
        service_name,
        service_username,
        service_cipher: service_password,
    });
    f.vault.sort_by(|a, b| a.service_name.cmp(&b.service_name));
    write_json(&f).context("error writing to json")?;
    println!("service and password securely written to json");
    Ok(())
}

/// Bulk-adds passwords read from a CSV file, after confirming with the user.
fn bulk_add(f: PathBuf, e: String) -> anyhow::Result<()> {
    let v = read_from_csv(f).context("error reading")?;
    let mut vault_entries: Vec<IndividualService> = Vec::new();
    for entry in v {
        match encrypt(&decode_base64(&e), entry.password) {
            Ok((cipher, nonce)) => {
                vault_entries.push(IndividualService {
                    service_name: entry.service,
                    service_username: entry.user,
                    service_nonce: encode_base64(nonce),
                    service_cipher: encode_base64(cipher),
                });
            }
            Err(e) => println!("error encrypting entry: {e}"),
        }
    }
    display_services(&obscure_cipher(&vault_entries));
    if prompt_confirm_bulk_add()? {
        let mut f = get_json()?;
        f.vault.append(&mut vault_entries);
        f.vault.sort_by(|a, b| a.service_name.cmp(&b.service_name));
        write_json(&f).context("error writing csv entries to vault")?;
        println!("successfully added csv entries to vault");
    } else {
        println!("aborting process of adding");
    }
    Ok(())
}

/// Reads vault entries to add from a CSV file.
fn read_from_csv(f: PathBuf) -> anyhow::Result<Vec<CSVfile>> {
    let mut reader = csv::Reader::from_path(f)?;
    let results = reader
        .deserialize()
        .collect::<Result<Vec<CSVfile>, csv::Error>>()?;
    Ok(results)
}

/// Handles the `remove` command: deletes either all entries or those matching a search.
pub fn remove_password(s: Option<String>, u: Option<String>, a: bool) -> anyhow::Result<()> {
    let mut whole_vault = get_json()?.vault;

    if a {
        if prompt_confirm_remove_all()? {
            println!("Removing all entries");
            delete_entries(vec![])?;
        } else {
            println!("aborting removal process");
        }
    } else {
        let mut smaller_vault = whole_vault.clone();
        smaller_vault = get_service_vec_service(&s, smaller_vault);
        smaller_vault = get_service_vec_user(&u, smaller_vault);
        if smaller_vault.is_empty() {
            println!("no entries matched. no passwords to delete")
        } else {
            display_services(&obscure_cipher(&smaller_vault));
            let v_set: HashSet<_> = smaller_vault.into_iter().collect();
            whole_vault.retain(|i| !v_set.contains(i));
            if prompt_confirm_remove()? {
                delete_entries(whole_vault)?;
            } else {
                println!("aborting removal process");
            }
        }
    }
    Ok(())
}

/// Overwrites the vault's entries with the given list, reopening the vault if needed.
fn delete_entries(s: Vec<IndividualService>) -> anyhow::Result<()> {
    if get_unlocked_key().is_err() {
        println!("reopen vault before continuing");
        open_vault()?;
    }
    let mut f = get_json()?;
    f.vault = s;
    write_json(&f).context("error deleting passwords")?;
    println!("password(s) deleted");
    Ok(())
}

/// Handles the `open` command: unlocks the vault for a session if it isn't already open.
pub fn open_vault() -> anyhow::Result<()> {
    if get_unlocked_key().is_ok() {
        println!("vault already opened");
        return Ok(());
    }
    print_vault_open_hint();
    let enc_key = prompt_master_password()?;
    unlock(enc_key).context("error opening vault")?;
    println!("vault opened");
    Ok(())
}

/// Handles the `close` command: locks the vault if it's currently open.
pub fn close_vault() -> anyhow::Result<()> {
    if let Err(e) = get_unlocked_key() {
        println!("vault already closed: {e}");
        return Ok(());
    }
    lock().context("Error closing vault")?;
    println!("Vault closed");
    Ok(())
}

/// Handles the `purge` command, requiring the user to type a confirmation phrase.
pub fn purge_all() -> anyhow::Result<()> {
    if prompt_purge()? {
        let path = crate::storage::vault_path()?;
        std::fs::remove_file(&path).context("failed to delete vault file")?;
        println!("everything has been deleted");
    } else {
        println!("purge has been aborted");
    }
    Ok(())
}
