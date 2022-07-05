## Build from source…

_LAUREL_ is written in Rust. To build it, a reasonably recent Rust compiler (we currently use 1.48), `cargo`, and the 
`libacl` library and its header files (Debian: `libacl1-dev`, RedHat: `libacl-devel`) are required.

``` console
$ cargo build --release
$ sudo install -m755 target/release/laurel /usr/local/sbin/laurel
```

## …or use one of the provided binaries

For tagged releases, two types of binaries are created:

- a statically-linked, [musl-libc](https://musl.libc.org) version, built on Alpine 3.14,
- a dynamically-linked version based on GNU libc, built on Debian 10.

The static build lacks the ability to perform user and group lookups using the _nsswitch_ facility used on GNU-libc-based systems, therefore it should be avoided on systems where other user/group databases than `/etc/passwd` and `/etc/group` are used (cf. issue #84).

## Configure, use

- Create a dedicated user, e.g.:
    ``` console
    $ sudo useradd --system --home-dir /var/log/laurel --create-home _laurel
    ```
- Configure _LAUREL_: Copy the provided annotated [example](etc/laurel/config.toml) to `/etc/laurel/config.toml` and customize it.
- Register _LAUREL_ as an _audisp_ plugin: Copy the provided [example](etc/audit/plugins.d/laurel.conf) to `/etc/audisp/plugins.d/laurel.conf` or `/etc/audit/plugins.d/laurel.conf` (depending on your _auditd_ version).
- If you are running SELinux, compile the provided policy and install it into the running kernel:
    ``` console
    $ make -C contrib/selinux
    $ sudo semodule -i contrib/selinux/laurel.pp
    $ sudo restorecon -v -R -F /usr/local/sbin/laurel /etc/laurel /var/log/laurel
    ```
- Tell _auditd(8)_ to re-evaluate its configuration
    ``` console
    $ sudo pkill -HUP auditd
    ```

## Test, Debug

For debugging and other testing purposes, _LAUREL_ can be run without specifying any configuration file. It will not change users and read events from standard input, just as it would when called from _auditd_. Log entries arewritten to `audit.log` in the current working directory.
