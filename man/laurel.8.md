---
title: laurel
section: 8
header: System Administration Utilities
footer: laurel 0.6.1
---

# NAME
laurel(8) -- transform, enrich Linux audit logs

# SYNOPSIS

`laurel` is an `auditd(8)` plug-in that parses Linux audit events,
enriches them with local information, and transforms them into a
JSONlines-based output format intended for consumption by log
processing and SIEM software.

# OPTIONS
**-c FILE**, **-\-config=FILE**
: path to configuration file (default: unset)

**-d**, **-\-dry-run**
: Only parse configuration and exit

**-h**, **-\-help**
: Print short help text and exit

**-v**, **-\-version**
: Print version and exit

# DESCRIPTION

`laurel` is typically configured to be spawned by `auditd(8)` itself or by
`audispd(8)` (for 2.x _auditd_ versions). All audit events are fed to
`laurel` via its standard input channel.

Sample configuration file `/etc/audit/plugins.d/laurel.conf`:
```
active = yes
direction = out
type = always
format = string
path = /usr/sbin/laurel
args = --config /etc/laurel/config.toml
```

An alternative setup consists of an AF_UNIX socket to which
`auditd(8)` writes events. A connection is then established by
`laurel` (see `input` setting below). In this case, the operator is
responsible for starting and restarting `laurel`.

Example configuration file:
```
active = yes
direction = out
path = builtin_af_unix
type = builtin
args = 0600 /var/run/laurel.sock
format = string
```

# CONFIGURATION

Configuration of `laurel` itself is done through a single
configuration file in TOML format.

## main section

This section contains basic operation parameters.

- `user`: `laurel` is started as `root` by `auditd`, but it drops to
  a dedicated user as soon as possible. Default: unset
- `directory`: The base directory into which all files are written.
  Default: `.` (current directory)
- `statusreport-period`: How often stats are written to Syslog, in
  seconds. Default: unset
- `input`: `laurel` can consume audit events from standard input or
  connect to a listening socket specified as `unix:/path/to/socket` at
  start. Defaulkt: `stdin`
- `marker`: A string that is written to the log on startup and
  whenever `laurel` writes a status report. Default: none

<!-- `user` and `directory` are unset by default for debugging -->

## `[auditlog]` section

This section describes the main audit log file. `laurel` performs its
own log file rotation, just like `auditd(8)`.

- `file`: Filename for the audit log file. Default: `audit.log`
- `size`: Size in bytes after which the log file is rotated. Default:
  10MiB
- `generations`: Number of generations to keep after rotation.
  Default: 5
- `read-users`: List of users that are granted read access
  to the log file using POSIX ACLs. Default: empty
- `line-prefix`: A string that is prepended to every line. Default:
  unset

## `[filterlog]` section

This section describes the log file for filtered-out log events (see
below). The `file`, `size`, `generations`, `read-users`, `line-prefix`
configuration items work just like for the audit log.

## `[transform]` section

- `execve-argv`: The list of `EXECVE.a*` fields are transformed to an
  `ARGV` list or `ARGV_STR` string. Set to `array`, `string` (or
  both). Default: `array`
- `execve-argv-limit-bytes`: Arguments are cut out of the middle long
   argument lists in `EXECVE.ARGV` or `EXECVE.ARGV_STR` so that this
   limit is not exceeded. Default: unset

## `[translate]` section

Options that can be configured here correspond to what `auditd(8)`
does when configured with `log_format=ENRICHED`.

- `userdb`: Add translations for `uid` and `gid` fields. Default: false
- `universal`: Add translations for everything else: `SYSCALL.arch`,
  `SYSCALL.syscall`, `SOCKADDR.saddr`
- `drop-raw`: Drop raw (numeric) syscall, arch, UID, GID values if
  they are translated. Default: false

## `[enrich]` section

Options that can be configured here actually add information to events

- `execve-env`: A list of environment variables to dump for `exec`
  events. Default: `["LD_PRELOAD", "LD_LIBRARY_PATH"]`
- `container`: Add container information for processes running within
  container runtimes. Default: true
- `pid`: Add context information for process IDs. Default: true
- `script`: If an `exec` syscall spawns a script (as opposed to a
  binary), add a `SCRIPT` entry to the `SYSCALL` record. A script is
  assumed if the first `PATH` entry does not correspond to file
  mentioned  in `SYSCALL.exe`. Default: true
- `user-groups`: Add groups that the user ("uid") is a member of.
  Default: true

## `[label-process]` section

Labels can be attached to processes and are added to any event
associated with those processes. These labels can be propagated from
parent to child processes.

- `label-exe.<regexp> = <label-name>`: Regular expressions/label
  mappings applied to binary executables (`SYSCALL.exe`) on `exec`
  calls. Default: none
- `label-script.<regexp> = <label-name>`: Regular expressions/label
  mappings applied to scripts (`SYSCALL.SCRIPT`, see `enrich.script`
  description above) on `exec` calls. Default: none
- `label-keys`: A list of keys that are applied as a process label,
  see `auditctl(8)`'s `-k` option. Default: none
- `unlabel-exe.<regexp> = <label-name>`: Like `label-exe`, but for
  removing labels
- `unlabel-script.<regexp> = <label-name>`: Like `label-script`, but
  for removing labels
- `propagate-labels`: List of labels that are propagated to child
  processes. Default: empty

## `[filter]` section

Filters make `laurel` drop entire events from the log file while still
using them for internal processing such as process tracking.

- `filter-keys`: A list of strings that are matched against
  `SYSCALL.key` to drop the event. Default: empty
- `filter-null-keys`: Filter events without specified key. Default: false
- `filter-labels`: A list of strings that are matched against process
  labels. Default: empty
- `filter-raw-lines`: A list of regular expression that are matched
  against individual input lines as written by `auditd(8)`. Events
  that contain such lines are then filtered. Default: empty
- `filter-action`: What to do with filtered events? `drop` or `log` to the
  filterlog defined above.

# SIGNALS

`SIGHUP` causes `laurel` to process any buffered input and restart. It
can be used to reconfigure `laurel` without having restarting
`auditd(8)` which would likely lead to lost audit messages.

# AUTHORS
- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt <<sergej@msgpeek.net>>
