use std::cell::RefCell;
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::rc::Rc;

use crate::coalesce::Coalesce;
use crate::types::Event;

fn process_record<T>(c: &mut Coalesce, text: T) -> Result<(), Box<dyn Error>>
where
    T: AsRef<[u8]>,
{
    for line in BufReader::new(text.as_ref())
        .lines()
        .filter(|line| match line {
            Ok(l) if l.is_empty() => false,
            Ok(l) if l.starts_with("#") => false,
            _ => true,
        })
    {
        let mut line = line.unwrap().clone();
        line.push('\n');
        c.process_line(line.as_bytes())?;
    }
    Ok(())
}

#[test]
fn golden() -> Result<(), Box<dyn Error>> {
    let prefix: PathBuf = "src/testdata".parse()?;

    let mut do_write = false;
    for (k, _v) in std::env::vars() {
        if k == "WRITE_GOLDEN" {
            do_write = true;
        }
    }

    for file in &[
        "record-adjntpval.txt",
        "record-anom-promiscuous.txt",
        "record-avc-apparmor.txt",
        "record-bind-ipv4-bigendian.txt",
        "record-execve-long.txt",
        "record-execve.txt",
        "record-login.txt",
        "record-nscd.txt",
        "record-perl-reverse-shell.txt",
        "record-ptrace.txt",
        "record-syscall-key.txt",
        "record-syscall-nullkey.txt",
        "record-weblogic.txt",
    ] {
        let buf: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let emit_fn = |e: &Event| {
            use std::ops::DerefMut;
            let mut b = buf.borrow_mut();
            crate::json::to_writer(b.deref_mut(), e).unwrap();
            b.deref_mut().push(b'\n');
        };

        let mut c = Coalesce::new(emit_fn);
        c.settings.enrich_uid_groups = false;
        c.settings.enrich_pid = false;
        c.settings.enrich_script = false;

        let txtfile = prefix.join(file);
        println!("processing {}", txtfile.to_string_lossy());
        process_record(&mut c, std::fs::read(&txtfile)?)?;

        let mut jsonfile = txtfile.clone();
        jsonfile.set_extension("json");

        if do_write {
            println!("writing {}", jsonfile.to_string_lossy());
            std::fs::write(jsonfile, buf.borrow().as_slice())?;
        } else {
            println!("comparing against {}", jsonfile.to_string_lossy());
            let got = buf.borrow();
            let expected = std::fs::read(jsonfile)?;
            print!("     got = {}", String::from_utf8_lossy(&got));
            print!("expected = {}", String::from_utf8_lossy(&expected));
            assert!(*got == expected);
        }
    }

    Ok(())
}
