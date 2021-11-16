use std::env;
use std::fs;
use std::path::{Path,PathBuf};
use std::io::BufReader;
use std::io::prelude::*;
use std::string::String;
use std::iter::FromIterator;

extern crate bindgen;

fn gen_syscall() -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = String::new();
    for entry in Path::new("syscall-tables").read_dir()? {
        let p = entry?.path();
        let filename = if let Some(f) = p.file_name() {
            f
        } else {
            continue
        };
        let arch = if let Some(a) = filename.to_string_lossy().into_owned().strip_suffix("_table.h") {
            a.to_string()
        } else {
            continue
        };
        buf.push_str("{ let mut t = HashMap::new(); for (num, name) in &[");

        // Entries look like
        //     _S(0, "io_setup")
        // Just get rid of the _S.
        let defs = BufReader::new(fs::File::open(p)?)
            .lines()
            .filter(|line| line.as_ref().unwrap().starts_with("_S("))
            .map(|line| line.unwrap())
            .map(|line| line.strip_prefix("_S").unwrap().to_string());
        for def in defs {
            buf.push_str(def.as_str());
            buf.push(',');
        }
        buf.push_str("] { t.insert(*num, name.as_bytes()); } ");
        buf.push_str(format!(" hm.insert(&b\"{}\"[..], t); }}\n", &arch).as_str());
    }
    Ok(buf)
}

fn main() -> Result<(),Box<dyn std::error::Error>> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const.rs");
    let msg_file = "audit-specs/messages/message-dictionary.csv";
    let fields_file = "audit-specs/fields/field-dictionary.csv";

    let mut constants: Vec<(String, String)> =
        BufReader::new(fs::File::open(msg_file)?)
        .lines()
        .skip(1) // skip over header
        .map(|line| line.unwrap().split(',').map(|x|x.to_string()).collect::<Vec<_>>())
        .map(|fields| 
             (fields[0].strip_prefix("AUDIT_").unwrap().to_string(), fields[1].clone()))
        .collect();

    // Artificial record
    constants.push(("PARENT_INFO".into(), "0xffffff00".into()));

    let fields: Vec<(String, String)> =
        BufReader::new(fs::File::open(fields_file)?)
        .lines()
        .skip(3) // skip over heder and regex describing a* mess
        .map(|line| line.unwrap().split(',').map(|x|x.to_string()).collect::<Vec<_>>())
        .map(|fields|
             (fields[0].clone(), fields[1].clone()))
        .collect();

    let mut template = Vec::new();
    fs::File::open("src/const.rs.in")?.read_to_end(&mut template)?;
    let template = String::from_utf8(template)?;

    let buf = template
        .replace("/* @EVENT_CONST@ */",
                 &String::from_iter(
                     constants.iter()
                         .map(|(name,value)|format!(r#"("{}", {}), "#, name, value))))
        .replace("/* @FIELD_TYPES@ */",
                 &String::from_iter(
                     fields.iter()
                         .filter(|(_,typ)| typ == "encoded" || typ.starts_with("numeric"))
                         .map(|(name, typ)| {
                             match typ.as_str() {
                                 "numeric hexadecimal" => format!(r#"("{}", FieldType::NumericHex),"#, name),
                                 "numeric decimal" => format!(r#"("{}", FieldType::NumericDec),"#, name),
                                 "numeric octal" => format!(r#"("{}", FieldType::NumericOct),"#, name),
                                 "numeric" => format!(r#"("{}", FieldType::Numeric),"#, name),
                                 "encoded" => format!(r#"("{}", FieldType::Encoded),"#, name),
                                 _ => format!(r#"("{}", FieldType::Invalid),"#, name),
                             }
                         })))
        .replace("/* @CONSTANTS@ */",
                 &String::from_iter(
                     constants.iter()
                         .map(|(name,value)|format!("#[allow(dead_code)] pub const {}: MessageType = MessageType({});\n", name, value))))
        .replace("/* @SYSCALL_BUILD@ */", &gen_syscall()?)
        .into_bytes();

    fs::write(&dest_path, &buf)?;

    // sockaddr
    bindgen::Builder::default()
        .header("src/sockaddr.h")
        .rust_target(bindgen::RustTarget::Stable_1_47)
        .allowlist_type("^sockaddr_.*")
        .allowlist_var("^AF_.*")
        .rustfmt_bindings(false)
        .generate()
        .expect("unable to generate bindings")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("sockaddr.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs"); 
    println!("cargo:rerun-if-changed=const.rs.in"); 
    println!("cargo:rerun-if-changed=src/sockaddr.h");
    println!("cargo:rerun-if-changed={}", msg_file);
    println!("cargo:rerun-if-changed={}", fields_file);

    Ok(())
}
