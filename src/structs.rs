use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::Tabled;

pub const KEY_DESC: &str = "master_key";
pub const TIMEOUT: usize = 300;

#[derive(Parser, Debug)]
#[command(name = "sspm", about = "Super Simple Password Manager")]
pub struct Cli {
    #[command(subcommand)]
    pub service: Service,
}

#[derive(Debug, Subcommand, PartialEq)]
pub enum Service {
    Show {
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Get {
        #[arg(short, long, num_args(0..=1))]
        service: Option<String>,
        #[arg(short, long, num_args(0..=1))]
        user: Option<String>,
    },
    Add {
        #[arg(short, long, exclusive = true)]
        file: Option<PathBuf>,
        #[arg(short, long)]
        service: Option<String>,
        #[arg(short, long)]
        user: Option<String>,
        #[arg(long)]
        generate: bool,
    },
    Remove {
        #[arg(short, long)]
        service: Option<String>,
        #[arg(short, long)]
        user: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Open,
    Close,
    Purge,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct File {
    pub master_password: String,
    pub user: String,
    pub salt: String,
    pub vault: Vec<IndividualService>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, Hash, PartialEq)]
pub struct IndividualService {
    pub service_nonce: String,
    pub service_name: String,
    pub service_username: String,
    pub service_cipher: String,
}

#[derive(Tabled)]
pub struct TblServices<'a> {
    #[tabled(rename = "")]
    pub number: usize,
    #[tabled(rename = "SERVICE")]
    pub name: &'a String,
    #[tabled(rename = "USERNAME")]
    pub username: &'a String,
    #[tabled(rename = "PASSWORD")]
    pub password: &'a String,
}

#[derive(Debug, Deserialize)]
pub struct CSVfile {
    pub service: String,
    pub user: String,
    pub password: String,
}
