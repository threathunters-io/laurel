---
title: laurel2audit
section: 8
header: System Administration Utilities
footer: laurel 0.7.0
---

# NAME

laurel2audit(8) -- transform Laurel logs to back to original Linux Audit format

# SYNOPSIS

This is a simple filter that reads logs written by `laurel(8)` and
outputs Linux Audit logs that the audit tools and `laurel` itself
should be able to digest.

# NOTES

"Enriched" (i.e. ALL_CAPS) keys in audit records are discarded.

`EXECVE` records are output on one, possibly very long, line.

If `laurel` has transformed `EXECVE` argument lists to single strings
(`ARGV_STR`), that transformation may have been lossy: There is no way
to discern space characters as gaps between arguments from space
characters as part of individual arguments.

An end-of-event (`EOE`) marker is output for every event. This marker
is not part of the original `audit.log` file, but it has originally
been transmitted by the kernel and is passed by `auditd(8)` to
plugins.

# BUGS

- URL-encoded single bytes within strings are not yet handled.
- Possibly more.

# SEE ALSO

`laurel(8)`, `aulast(8)`, `aulastlog(8)`, `aureport(8)`, `ausearch(8)`, `ausyscall(8)`, `auvirt(8)`

# AUTHORS

- Hilko Bengen <<bengen@hilluzination.de>>
