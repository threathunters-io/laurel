#[macro_use]
extern crate bencher;
extern crate gperftools;

use bencher::Bencher;

use gperftools::profiler::PROFILER;

use std::process;

use laurel::coalesce::Coalesce;

fn measure(bench: &mut Bencher, s: bool) {
    // simulate edr-loadgen behavior: this process simulates many process spawns
    let ppid = process::id();
    let mut sink = std::io::sink();

    bench.iter(|| {
        let mut c = if s {
            Coalesce::new( |msg| { serde_json::to_writer(&mut sink, &msg).unwrap() } )
        } else {
            Coalesce::new( |_| {} )
        };
        c.settings.translate_universal = true;
        c.settings.translate_userdb = true;
        c.settings.enrich_script = false;

        for i in 0 .. 1000 {
            let pid = ppid + 100000 + i;
            let ms = (i / 1000) % 1000;
            let seq = i % 1000;
            for line in &[
                format!(r#"node=asdfghjk type=SYSCALL msg=audit(1615114232.{:03}:{:03}): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid={} pid={} auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="true" exe="/bin/true" key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="user" GID="user" EUID="user" SUID="user" FSUID="user" EGID="user" SGID="user" FSGID="user"
"#, ms, seq, ppid, pid),
                format!(r#"node=asdfghjk type=EXECVE msg=audit(1615114232.{:03}:{:03}): argc=1 a0="true"
"#, ms, seq),
                format!(r#"node=asdfghjk type=CWD msg=audit(1615114232.{:03}:{:03}): cwd="/home/user/tmp"
"#, ms, seq),
                format!(r#"node=asdfghjk type=PATH msg=audit(1615114232.{:03}:{:03}): item=0 name="/bin/true" inode=261214 dev=ca:03 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0OUID="root" OGID="root"
"#, ms, seq),
                format!(r#"node=asdfghjk type=PATH msg=audit(1615114232.{:03}:{:03}): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=262146 dev=ca:03 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0OUID="root" OGID="root"
"#, ms, seq),
                format!(r#"node=asdfghjk type=PROCTITLE msg=audit(1615114232.{:03}:{:03}): proctitle="true"
"#, ms, seq),
                format!(r#"node=asdfghjk type=EOE msg=audit(1615114232.{:03}:{:03}): 
"#, ms, seq),
            ] {
                c.process_line(Vec::from(line.as_bytes())).unwrap();
            }
        }
    });
}

fn parse_only(bench: &mut Bencher) {
    measure(bench, false)
}

fn parse_serialize(bench: &mut Bencher) {
    measure(bench, true)
}

benchmark_group!(b, parse_only, parse_serialize);

fn main() {
    laurel::constants::initialize();

    PROFILER
        .lock()
        .unwrap()
        .start(format!("{}.prof", std::env::args().next().unwrap()))
        .unwrap();
    let test_opts = bencher::TestOpts::default();
    // if let Some(arg) = std::env::args().skip(1).find(|arg| *arg != "--bench") {
    //     test_opts.filter = Some(arg);
    // }
    let mut benches = Vec::new();
    benches.extend(b());
    bencher::run_tests_console(&test_opts, benches).unwrap();
    PROFILER.lock().unwrap().stop().unwrap();
}
