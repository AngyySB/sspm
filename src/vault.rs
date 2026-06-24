//! Vault commands: show, get, add, remove, open, close, purge.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Context;
use arboard::Clipboard;
use colored::Colorize;
use dialoguer::{Confirm, Input, Password};
use rand::Rng;

use crate::secrets::{
    check_master_password, decode_base64, decrypt, encode_base64, encrypt, get_unlocked_key,
    gen_salt, lock, master_hash, unlock,
};
use crate::storage::{get_json, write_json};
use crate::structs::{CSVfile, File, IndividualService};
use crate::ui::{display_services, obscure_cipher};

/// Creates the vault file on first run by prompting for a new master password.
pub fn new_user() -> anyhow::Result<()> {
    //user creates password
    let password: String = Password::new()
        .with_prompt("Create your password (if you lose this, you lose access)")
        .with_confirmation("Confirm your password", "Passwords not matching")
        .validate_with(|i: &String| -> std::result::Result<(), String> {
            if i.is_empty() || i.chars().count() < 7 {
                Err("Password must be longer than 6".red().bold().to_string())
            } else if !i.is_ascii() {
                Err("Only ASCII characters allowed".red().bold().to_string())
            } else {
                Ok(())
            }
        })
        .interact()?;

    //sets username the same as OS username
    let user: String = whoami::username()?;

    //create salt, then turn into string
    let salt = gen_salt();
    let stored_salt = salt.to_string();
    let (_, auth) = master_hash(&password, &salt);
    //println!("{user} | {password} | {salt}");

    //struct for initial json file on first creation
    let first = File {
        master_password: auth,
        user,
        salt: stored_salt,
        vault: vec![],
    };
    write_json(&first).context("Error creating new json file")?;
    Ok(())
}

/// Handles the `add` command, dispatching to bulk/generated/manual add.
pub fn handle_add(f: Option<PathBuf>, s: Option<String>, u: Option<String>, g: bool) -> anyhow::Result<()> {
    let enc = get_unlocked_key()?;

    if let Some(f) = f {
        bulk_add(f, enc)
    } else if g {
        add_generate(s, u, enc)
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
        println!("{}", "multiple entries matched your search".bold().green());
        display_services(&vault_obsc);
        if !vault.is_empty() {
            password_to_clipboard_check(c, choose_entry(&vault))?;
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

/// Prompts the user to pick one entry by number from a list of matches.
fn choose_entry(s: &[IndividualService]) -> Option<&IndividualService> {
    let input: String = Input::new()
        .with_prompt("please enter number corresponding to entry or type 0 to exit")
        .validate_with(|i: &String| -> std::result::Result<(), String> {
            match i.parse::<usize>() {
                Ok(n) => {
                    if n == 0 || s.get(n - 1).is_some() {
                        Ok(())
                    } else {
                        Err("number does not correspond to any entry".to_string())
                    }
                }
                Err(_) => Err("please type a number".to_string()),
            }
        })
        .interact()
        .unwrap();

    let number_input: usize = input.parse().unwrap();
    println!("{number_input}");
    if number_input == 0 {
        None
    } else {
        Some(s.get(number_input - 1).unwrap())
    }
}

/// Decrypts an entry's password and copies it to the clipboard, reopening the vault if needed.
fn password_to_clipboard(c: &mut Clipboard, entry: &IndividualService) -> anyhow::Result<()> {
    if get_unlocked_key().is_err() {
        println!("reopen vault before continuing");
        open_vault()?;
    }
    let enc = get_unlocked_key()?;

    let decrypted_password = decrypt(
        &decode_base64(&enc),
        &entry.service_nonce,
        &entry.service_cipher,
    )
    .context("Decryption failed")?;

    c.set_text(decrypted_password)?;
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

        for (servs, pass) in services.iter_mut().zip(plain_pass.iter()) {
            servs.service_cipher = pass.clone();
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
fn get_service_vec_service(
    s: &Option<String>,
    v: Vec<IndividualService>,
) -> Vec<IndividualService> {
    match s {
        Some(name) => v
            .into_iter()
            .filter(|x| x.service_name.contains(name))
            .collect(),
        None => v,
    }
}

/// Filters a vault entry list to those whose username contains the given string.
fn get_service_vec_user(s: &Option<String>, v: Vec<IndividualService>) -> Vec<IndividualService> {
    match s {
        Some(name) => v
            .into_iter()
            .filter(|x| x.service_username.contains(name))
            .collect(),
        None => v,
    }
}

/// Manually adds a password entry by prompting the user for it.
fn manual_add(s: Option<String>, u: Option<String>, e: String) -> anyhow::Result<()> {
    let service_name = s.unwrap_or_default();
    let user_name = u.unwrap_or_default();
    //let f = get_json();
    println!(
        "adding entry: service: {} | user: {}",
        service_name, user_name
    );
    let pass = service_password();

    let (c, n) = encrypt(&decode_base64(&e), pass)?;
    add_to_vault(encode_base64(n), service_name, user_name, encode_base64(c))
}

/// Prompts the user for a service password with confirmation.
fn service_password() -> String {
    Password::new()
        .with_prompt("Enter password for service")
        .with_confirmation("confirm password", "passwords not matching")
        .interact()
        .unwrap()
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

/// Adds a password entry using a randomly generated password.
fn add_generate(s: Option<String>, u: Option<String>, e: String) -> anyhow::Result<()> {
    let service_name = s.unwrap_or_default();
    let user_name = u.unwrap_or_default();

    let password = gen_plain_password();

    let (c, n) = encrypt(&decode_base64(&e), password)?;
    add_to_vault(encode_base64(n), service_name, user_name, encode_base64(c))
}

/// Generates a random plaintext password.
fn gen_plain_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789)(*&^%$#@!";
    let length: usize = 12;
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Bulk-adds passwords read from a CSV file, after confirming with the user.
fn bulk_add(f: PathBuf, e: String) -> anyhow::Result<()> {
    let v = read_from_csv(f).context("error reading")?;
    let mut vault_entries: Vec<IndividualService> = Vec::new();
    for entry in v {
        match encrypt(&decode_base64(&e), entry.password) {
            Ok((c, n)) => {
                vault_entries.push(IndividualService {
                    service_name: entry.service,
                    service_username: entry.user,
                    service_nonce: encode_base64(n),
                    service_cipher: encode_base64(c),
                });
            }
            Err(e) => println!("error encrypting entry: {e}"),
        }
    }
    display_services(&obscure_cipher(&vault_entries));
    let conf = Confirm::new()
        .with_prompt("add these to your vault?")
        .default(false)
        .interact()?;
    if conf {
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
        let conf = Confirm::new()
            .with_prompt("This will delete ALL passwords stored in the vault. Are you sure?")
            .default(false)
            .wait_for_newline(true)
            .interact()?;

        if conf {
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
            let conf = Confirm::new()
                .with_prompt("This will delete these entries. Are you sure?")
                .default(false)
                .wait_for_newline(true)
                .interact()?;

            if conf {
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
    println!(
        "This will open the vault until timeout or  until manually closed with {}\n",
        "sspm close".purple().bold()
    );
    let enc_key = input_master_password()?;
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

/// Repeatedly prompts for the master password until it matches.
fn input_master_password() -> anyhow::Result<String> {
    loop {
        // 1. Get the raw input from the user without a dialoguer validator
        let input = Password::new()
            .with_prompt("Input your master password")
            .interact()?;

        // 2. Run the expensive check EXACTLY once
        match check_master_password(&input) {
            Ok(hashed_password) => return Ok(hashed_password),
            Err(_) => {
                println!("{}", "Wrong password!".bold().red());
            }
        }
    }
}

/// Handles the `purge` command, requiring the user to type a confirmation phrase.
pub fn purge_all() -> anyhow::Result<()> {
    let password: String = Input::new()
        .with_prompt("type PURGE to delete everything")
        .interact()?;

    if password == "PURGE" {
        println!("{}", "everything has been deleted".bold().green());
    } else {
        println!("purge has been aborted");
    }
    Ok(())
}
