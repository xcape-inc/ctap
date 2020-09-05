use csv::{Reader, StringRecord};
use serde_derive::Deserialize;
use std::env;
use std::fs::File;
use std::io::{Result, Write};
use std::iter::FromIterator;
use std::string::String;

fn main() {
    parse_error_codes().expect("Failed to parse error codes")
}

fn parse_error_codes() -> Result<()> {
    println!("cargo:rerun-if-changed=ctap_error_codes.csv");
    let mut out_file = File::create(format!(
        "{}/ctap_error_codes.rs",
        env::var("OUT_DIR").unwrap()
    ))?;
    out_file.write_all(b"static CTAP_ERROR_CODES: &[(usize, &str, &str)] = &[")?;
    let mut rdr = Reader::from_path("ctap_error_codes.csv")?;
    rdr.set_headers(StringRecord::from_iter(&["code", "name", "desc"]));
    #[derive(Debug, Deserialize)]
    struct ErrorCode {
        code: String,
        name: String,
        desc: String,
    }
    for result in rdr.deserialize() {
        let record: ErrorCode = result.unwrap();
        out_file.write_all(
            format!(
                "({}, \"{}\", \"{}\"),\n",
                i64::from_str_radix(&record.code[2..], 16).unwrap(),
                record.name,
                record.desc
            )
            .as_bytes(),
        )?;
    }
    out_file.write_all(b"];")
}
