//! All user-facing interaction: prompts, confirmations, and display.

use colored::Colorize;
use dialoguer::{Confirm, Input, Password};
use tabled::{Table, settings::Style};

use crate::secrets::check_master_password;
use crate::structs::{IndividualService, TblServices};

/// Replaces each entry's password with a fixed mask so it isn't shown in plaintext.
pub fn obscure_cipher(s: &[IndividualService]) -> Vec<IndividualService> {
    let mut service = s.to_vec();
    for p in &mut service {
        p.service_cipher = "**********".to_string();
    }
    service
}

/// Renders a list of vault entries as a numbered table.
pub fn display_services(s: &[IndividualService]) {
    let mut table_vec: Vec<TblServices> = Vec::new();
    for (index, serv) in s.iter().enumerate() {
        table_vec.push(TblServices {
            number: index + 1,
            name: &serv.service_name,
            username: &serv.service_username,
            password: &serv.service_cipher,
        });
    }
    if table_vec.is_empty() {
        println!("no entries matched");
    } else {
        println!("{}", Table::new(table_vec).with(Style::modern()));
    }
}

/// Prompts the user to create a new master password with confirmation and validation.
pub fn prompt_new_master_password() -> anyhow::Result<String> {
    Password::new()
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
        .interact()
        .map_err(Into::into)
}

/// Prompts the user to enter and confirm a service password.
pub fn prompt_service_password() -> String {
    Password::new()
        .with_prompt("Enter password for service")
        .with_confirmation("confirm password", "passwords not matching")
        .interact()
        .unwrap()
}

/// Loops prompting for the master password until it matches the stored hash.
pub fn prompt_master_password() -> anyhow::Result<String> {
    loop {
        let input = Password::new()
            .with_prompt("Input your master password")
            .interact()?;
        match check_master_password(&input) {
            Ok(enc_key) => return Ok(enc_key),
            Err(_) => println!("{}", "Wrong password!".bold().red()),
        }
    }
}

/// Prompts the user to pick one entry by number from a list of matches.
pub fn prompt_choose_entry(s: &[IndividualService]) -> Option<&IndividualService> {
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

    let n: usize = input.parse().unwrap();
    println!("{n}");
    if n == 0 {
        None
    } else {
        Some(s.get(n - 1).unwrap())
    }
}

/// Prints the hint shown when the vault is being opened.
pub fn print_vault_open_hint() {
    println!(
        "This will open the vault until timeout or until manually closed with {}\n",
        "sspm close".purple().bold()
    );
}

/// Asks whether to copy the generated password to the clipboard.
pub fn prompt_confirm_copy_to_clipboard() -> anyhow::Result<bool> {
    Confirm::new()
        .with_prompt("Copy generated password to clipboard?")
        .default(true)
        .interact()
        .map_err(Into::into)
}

/// Asks whether to add the previewed bulk entries to the vault.
pub fn prompt_confirm_bulk_add() -> anyhow::Result<bool> {
    Confirm::new()
        .with_prompt("add these to your vault?")
        .default(false)
        .interact()
        .map_err(Into::into)
}

/// Asks whether to delete all entries in the vault.
pub fn prompt_confirm_remove_all() -> anyhow::Result<bool> {
    Confirm::new()
        .with_prompt("This will delete ALL passwords stored in the vault. Are you sure?")
        .default(false)
        .wait_for_newline(true)
        .interact()
        .map_err(Into::into)
}

/// Asks whether to delete the displayed matched entries.
pub fn prompt_confirm_remove() -> anyhow::Result<bool> {
    Confirm::new()
        .with_prompt("This will delete these entries. Are you sure?")
        .default(false)
        .wait_for_newline(true)
        .interact()
        .map_err(Into::into)
}

/// Prompts the user to type "PURGE" to confirm full deletion.
pub fn prompt_purge() -> anyhow::Result<bool> {
    let input: String = Input::new()
        .with_prompt("type PURGE to delete everything")
        .interact()?;
    Ok(input == "PURGE")
}
