# Debugging Laurel (even in production)

The `run-debug.sh` script in this directory is intended to be run from
the project root dir by a regular user with sudo privileges.

It runs a _laurel_ debug build with a custom configuration. The
configuration is built from a template. If the template contained in
the script is not good enough, place your own template into
`contrib/debug/config.toml.template`.

Audit log data is read from a local socket `/var/run/audispd_events`.
The _auditd_ `af_unix` plugin has to be enabled for this to work. Edit
the configuration file `/etc/audit/plugins.d/af_unix.conf`:

```
active = yes
direction = out
path = builtin_af_unix
type = builtin 
args = 0644 /var/run/audispd_events
format = string
```



