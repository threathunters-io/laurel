use std::env;
use std::fs;
use std::path::Path;
use std::io::BufReader;
use std::io::prelude::*;
use std::string::String;
use std::iter::FromIterator;

fn main() -> Result<(),Box<dyn std::error::Error>> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const.rs");
    let msg_file = "audit-specs/messages/message-dictionary.csv";
    let fields_file = "audit-specs/fields/field-dictionary.csv";

    let constants: Vec<(String, String)> =
        BufReader::new(fs::File::open(msg_file)?)
        .lines()
        .skip(1) // skip over header
        .map(|line| line.unwrap().split(',').map(|x|x.to_string()).collect::<Vec<_>>())
        .map(|fields| 
             (fields[0].strip_prefix("AUDIT_").unwrap().to_string(), fields[1].clone()))
        .collect();

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
                 String::from_iter(
                     constants.iter()
                         .map(|(name,value)|format!(r#"("{}", {}), "#, name, value)))
                 .as_str())
        .replace("/* @FIELD_TYPES@ */",
                 String::from_iter(
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
                         }))
                 .as_str())
        .replace("/* @CONSTANTS@ */",
                 String::from_iter(
                     constants.iter()
                         .map(|(name,value)|format!("#[allow(dead_code)] pub const {}: MessageType = MessageType({});\n", name, value)))
                 .as_str())
        .into_bytes();

    fs::write(&dest_path, &buf)?;

    println!("cargo:rerun-if-changed=build.rs"); 
    println!("cargo:rerun-if-changed=const.rs.in"); 
    println!("cargo:rerun-if-changed={}", msg_file);
    println!("cargo:rerun-if-changed={}", fields_file);

    Ok(())
}
