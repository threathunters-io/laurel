use std::env;
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::string::String;

extern crate bindgen;

fn gen_syscall() -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = String::new();
    for entry in Path::new("src/tbl/syscall").read_dir()? {
        let p = entry?.path();
        let filename = if let Some(f) = p.file_name() {
            f
        } else {
            continue;
        };
        let arch = if let Some(a) = filename
            .to_string_lossy()
            .into_owned()
            .strip_suffix("_table.h")
        {
            a.to_string()
        } else {
            continue;
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
        buf.push_str("] { t.insert(*num, *name); } ");
        buf.push_str(format!(" hm.insert(\"{arch}\", t); }}\n").as_str());
    }
    Ok(buf)
}

fn gen_uring_ops() -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = String::new();
    let mut defs: Vec<Option<String>> = (0..64).map(|_| None).collect();
    for (k, v) in BufReader::new(fs::File::open("src/tbl/uringop_table.h")?)
        .lines()
        .map(|line| line.unwrap())
        .filter_map(|line| line.strip_prefix("_S(").map(String::from))
        .filter_map(|line| line.strip_suffix(')').map(String::from))
        .filter_map(|line| {
            line.as_str().split_once(',').map(|(k, v)| {
                (
                    k.trim().to_string(),
                    v.trim_matches(|c: char| c.is_whitespace() || c == '"')
                        .to_string(),
                )
            })
        })
    {
        let num: usize = k.parse()?;
        defs[num] = Some(v);
    }
    for def in defs {
        let frag = match def {
            Some(s) => format!(r#"Some(b"{s}"), "#),
            None => "None, ".to_string(),
        };
        buf.push_str(&frag);
    }
    Ok(buf)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const.rs");

    let mut template = Vec::new();
    fs::File::open("src/const.rs.in")?.read_to_end(&mut template)?;
    let template = String::from_utf8(template)?;

    let buf = template
        .replace("/* @SYSCALL_BUILD@ */", &gen_syscall()?)
        .replace("/* @URING_OPS@ */", &gen_uring_ops()?)
        .into_bytes();

    fs::write(dest_path, buf)?;

    #[cfg(target_os = "linux")]
    bindgen::Builder::default()
        .header("src/sockaddr.h")
        .allowlist_type("^sockaddr_.*")
        .allowlist_var("^AF_.*")
        .layout_tests(false)
        .generate()
        .expect("unable to generate bindings")
        .write_to_file(std::path::PathBuf::from(env::var("OUT_DIR").unwrap()).join("sockaddr.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=const.rs.in");
    #[cfg(target_os = "linux")]
    println!("cargo:rerun-if-changed=src/sockaddr.h");

    Ok(())
}
