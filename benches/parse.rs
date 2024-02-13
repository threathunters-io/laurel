use laurel::parser::parse;

use std::hint::black_box;

use divan;

use gperftools::profiler::PROFILER;

#[divan::bench]
fn parse_syscall() {
    let _ = black_box(
        parse(Vec::from(&br#"node=asdfghjk type=SYSCALL msg=audit(1615114232.123:45678): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=1492834 pid=1492836 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="true" exe="/bin/true" key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="user" GID="user" EUID="user" SUID="user" FSUID="user" EGID="user" SGID="user" FSGID="user"
"#[..]), false));
}

#[divan::bench]
fn parse_execve_short() {
    let _ = black_box(parse(
        Vec::from(
            &br#"node=asdfghjk type=EXECVE msg=audit(1615114232.123:45678): argc=1 a0="true"
"#[..],
        ),
        false,
    ));
}

fn main() {
    laurel::constants::initialize();
    PROFILER
        .lock()
        .unwrap()
        .start(format!("{}.prof", std::env::args().next().unwrap()))
        .unwrap();
    divan::main();
    PROFILER.lock().unwrap().stop().unwrap();
}
