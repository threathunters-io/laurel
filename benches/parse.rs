#[macro_use]
extern crate bencher;
extern crate gperftools;

use bencher::Bencher;

use gperftools::profiler::PROFILER;

// use std::process;

fn measure(bench: &mut Bencher, line: &[u8]) {
    let line = line.to_vec();
    bench.iter(|| {
        for _ in 0..1000 {
            laurel::parser::parse(line.clone(), false).unwrap();
        }
    });
}

fn parse_syscall(bench: &mut Bencher) {
    measure(bench, &br#"node=asdfghjk type=SYSCALL msg=audit(1615114232.123:45678): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=1492834 pid=1492836 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="true" exe="/bin/true" key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="user" GID="user" EUID="user" SUID="user" FSUID="user" EGID="user" SGID="user" FSGID="user"
"#[..])
}

fn parse_execve_short(bench: &mut Bencher) {
    measure(
        bench,
        &br#"node=asdfghjk type=EXECVE msg=audit(1615114232.123:45678): argc=1 a0="true"
"#[..],
    )
}

benchmark_group!(b, parse_syscall, parse_execve_short);

fn main() {
    laurel::constants::initialize();

    let test_opts = bencher::TestOpts::default();
    // if let Some(arg) = std::env::args().skip(1).find(|arg| *arg != "--bench") {
    //     test_opts.filter = Some(arg);
    // }
    let mut benches = Vec::new();
    benches.extend(b());
    PROFILER
        .lock()
        .unwrap()
        .start(format!("{}.prof", std::env::args().next().unwrap()))
        .unwrap();
    bencher::run_tests_console(&test_opts, benches).unwrap();
    PROFILER.lock().unwrap().stop().unwrap();
}
