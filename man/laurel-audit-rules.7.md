---
title: laurel - Advice for writing Audit rulesets for use with `laurel(8)`
section: 7
header: System Administration Utilities
footer: laurel 0.7.0
---
# NAME
laurel-audit-rules - Advice for writing Audit rulesets for use with `laurel(8)`

# SYNOPSIS
This page contains suggestions for Linux Audit rulesets that are
useful to aid in detecting common attacker's tactics.

# Note about auditctl(8) error messages

It is not possible for /auditctl(8)/ ro load file watches for files or
directories that are not present. Depending on the rule set, it will
spam possibly lots of error messages to standard error. The specific
file watches are not installed, but those error messages can be
ignored otherwise.

# File watches
## Authentication/authorization
```
-w /etc/group           -p wa -k wr_group
-w /etc/passwd          -p wa -k wr_passwd
-w /etc/shadow          -p wa -k wr_passwd
-w /etc/pam.conf        -p wa -k wr_pam
-w /etc/pam.d/          -p wa -k wr_pam
-w /etc/ssh/sshd_config -p wa -k wr_sshd
-w /etc/sudoers         -p wa -k wr_sudo
-w /etc/sudoers.d       -p wa -k wr_sudo
```
## cron, at
```
-w /etc/crontab              -p wa -k wr_cron
-w /etc/cron.d/              -p wa -k wr_cron
-w /etc/cron.daily/          -p wa -k wr_cron
-w /etc/cron.hourly/         -p wa -k wr_cron
-w /etc/cron.monthly/        -p wa -k wr_cron
-w /etc/cron.weekly/         -p wa -k wr_cron
-w /etc/cron.yearly/         -p wa -k wr_cron
-w /etc/cron.allow           -p wa -k wr_cron
-w /etc/cron.deny            -p wa -k wr_cron
-w /var/spool/cron/crontabs/ -p wa -k wr_cron
-w /etc/at.allow             -p wa -k wr_cron
-w /etc/at.deny              -p wa -k wr_cron
-w /var/spool/cron/atjobs/   -p wa -k wr_cron
```
## systemd

Systemd also has cron-like timer mechanism. udev triggers have also
been abused for persistence. Note that watching the files in `/etc` is
not sufficient.
``` 
-w /etc/systemd     -p wa -k wr_systemd
-w /lib/systemd     -p wa -k wr_systemd
-w /usr/lib/systemd -p wa -k wr_systemd
-w /etc/udev        -p wa -k wr_systemd
-w /lib/udev        -p wa -k wr_systemd
-w /usr/lib/udev    -p wa -k wr_systemd
```
## Dynamic linkers
```
-w /lib/ld-linux.so.2          -p wa -k wr_ldso
-w /lib64/ld-linux-x86-64.so.2 -p wa -k wr_ldso
-w /lib/ld-musl-x86_64.so.1    -p wa -k wr_ldso
-w /lib/ld-musl-i386.so.1      -p wa -k wr_ldso
-w /etc/ld.so.conf             -p wa -k wr_ldso
-w /etc/ld.so.conf.d           -p wa -k wr_ldso
-w /etc/ld.so.preload          -p wa -k wr_ldso
```

## Mandatory access control (SELinux, AppArmor) manipulation
```
-w /etc/selinux         -p wa -k wr_selinux
-w /usr/share/selinux   -p wa -k wr_selinux
-w /usr/libexec/selinux -p wa -k wr_selinux

-w /etc/apparmor.d              -p wa -k wr_apparmor
-w /usr/lib/apparmor            -p wa -k wr_apparmor
-w /usr/share/apparmor          -p wa -k wr_apparmor
-w /usr/share/apparmor-features -p wa -k wr_apparmor
```

## Kernel modules
```
-w /etc/modprobe.conf -p wa -k wr_modules
-w /etc/modprobe.d/   -p wa -k wr_modules
-w /lib/modules/      -p wa -k wr_modules
```

## Auditd + Laurel
```
-w /etc/audit/        -p wa -k wr_audit_config
-w /etc/libaudit.conf -p wa -k wr_audit_config
-w /etc/audisp/       -p wa -k wr_audit_config
-w /etc/laurel/       -p wa -k wr_laurel_confg
```

# Log specific program executions

## Possible tampering with auditd, laurel
```
-w /sbin/auditctl   -p x -k wr_audit_tools
-w /sbin/auditd     -p x -k wr_audit_tools
-w /usr/sbin/laurel -p x -k wr_audit_tools
```

# Log specific "harmless" programs executions
Adding context to system service activities is useful because together
with Laurel's process labels (`label-process.label-keys`,
`label-process.propagate-labels`), it enables more accurate detection
rules that can help recognize benign system management activity.
```
-w /usr/sbin/sshd -p x -k sshd

-w /usr/bin/yum                -p x -k pkg_mgmt
-w /usr/bin/rpm                -p x -k pkg_mgmt
-w /usr/bin/dnf                -p x -k pkg_mgmt
-w /usr/bin/dpkg               -p x -k pkg_mgmt
-w /usr/bin/apt                -p x -k pkg_mgmt
-w /usr/bin/apt-get            -p x -k pkg_mgmt
-w /usr/bin/apt-key            -p x -k pkg_mgmt
-w /usr/bin/apt-add-repository -p x -k pkg_mgmt
-w /usr/bin/aptitude           -p x -k pkg_mgmt
-w /usr/bin/aptitude-curses    -p x -k pkg_mgmt
-w /usr/bin/wajig              -p x -k pkg_mgmt
-w /usr/bin/snap               -p x -k pkg_mgmt
-w /usr/sbin/yast2             -p x -k pkg_mgmt
-w /usr/bin/zypper             -p x -k pkg_mgmt

-w /usr/bin/containerd        -p x -k container
-w /usr/bin/podman            -p x -k container
-w /usr/bin/runc              -p x -k container
-w /usr/bin/dockerd           -p x -k container
-w /usr/bin/docker            -p x -k container
-w /usr/bin/docker-containerd -p x -k container
-w /usr/bin/docker-runc       -p x -k container

-w /usr/sbin/cron -p x -k sched_task
-w /usr/sbin/atd  -p x -k sched_task

-w /usr/sbin/httpd              -p x -k apache-httpd
-w /usr/local/apache2/bin/httpd -p x -k apache-httpd

-w /usr/sbin/nginx                         -p x -k nginx
-w /usr/local/nginx/sbin/nginx             -p x -k nginx
-w /usr/local/openresty/nginx/sbin/nginx   -p x -k nginx
```
# Syscalls

## Log all fork and exec calls for reliable process tracking

For reliable process tracking that is required for assigning and
propagating process labels, it is useful to have the Linux Audit
subsystem produce events for all `fork`/`exec` style syscalls.
```
## Ignore clone( flags=CLONE_VM|… ), log other process-creating calls
-a never,exit  -F arch=b32 -S clone -F a2&0x100
-a never,exit  -F arch=b64 -S clone -F a2&0x100
-a always,exit -F arch=b32 -S fork,vfork,clone,clone3 -k fork
-a always,exit -F arch=b64 -S fork,vfork,clone,clone3 -k fork
-a always,exit -F arch=b32 -S execve,execveat
-a always,exit -F arch=b64 -S execve,execveat
```
It is only important that Laurel gets to observe these events. To
reduce log volume, Laurel's filtering settings should be used, e.g.:
``` ini
[filter]
filter-keys = ["fork"]
filter-action = drop
keep-first-per-process = true
```

## Log usage of ptrace

We are interested in ptrce usage, but not in every transaction (`PEEK`, `POKE`, `CONT`)
```
-a never,exit -F arch=b32 -S ptrace -F a0>=1 -F a0<=7
-a never,exit -F arch=b64 -S ptrace -F a0>=1 -F a0<=7
-a always,exit -F arch=b32 -S ptrace
-a always,exit -F arch=b64 -S ptrace
```
## Log BPF usage

Usage of BPF should be restricted to few processes; log everything
except data transfer operations because they would put too much load
on the system.
```
-a never,exit -F arch=b32 -S bpf -F a0>=1 -F a0<=4
-a never,exit -F arch=b64 -S bpf -F a0>=1 -F a0<=4
-a never,exit -F arch=b32 -S bpf -F a0>=0xb -F a0<=0xf
-a never,exit -F arch=b64 -S bpf -F a0>=0xb -F a0<=0xf
-a never,exit -F arch=b32 -S bpf -F a0=0x13
-a never,exit -F arch=b64 -S bpf -F a0=0x13
-a always,exit -F arch=b32 -S bpf -F success=1
-a always,exit -F arch=b64 -S bpf -F success=1
```
## Log kernel module loading, unloading
```
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k module
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k module
```

# SEE ALSO
`audit.rules(7)`, `laurel(8)`

# AUTHOR
- Hilko Bengen <<bengen@hilluzination.de>>
