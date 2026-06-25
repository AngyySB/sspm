mod secrets;
mod storage;
mod structs;
mod ui;
mod vault;

use anyhow::Context;
use clap::Parser;

use secrets::get_unlocked_key;
use structs::{Cli, Service};
use vault::{
    close_vault, handle_add, handle_get, handle_show, new_user, open_vault, purge_all,
    remove_password,
};

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut clipboard = arboard::Clipboard::new().context("Failed to initialize clipboard")?;

    //check if user has file already
    if !storage::vault_path()?.try_exists().context("Error checking file")? {
        new_user()?;
    }

    if args.service != Service::Open
        && args.service != Service::Close
        && get_unlocked_key().is_err()
    {
        println!("Open vault before continuing");
        open_vault()?;
    }

    //check functionality user wants
    match args.service {
        Service::Show { name, all } => handle_show(name, all),
        Service::Get { service, user } => handle_get(&mut clipboard, service, user),
        Service::Add {
            file,
            service,
            user,
            generate,
        } => handle_add(&mut clipboard, file, service, user, generate),
        Service::Remove { service, user, all } => remove_password(service, user, all),
        Service::Open => open_vault(),
        Service::Close => close_vault(),
        Service::Purge => purge_all(),
    }
}
