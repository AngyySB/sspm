//! Display-only functionality for presenting vault data to the user.

use tabled::{Table, settings::Style};

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
