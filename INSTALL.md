# _LAUREL_ installation instructions

## Either build from source…

_LAUREL_ is written in Rust. To build it, a reasonably recent Rust compiler is required, we currently use 1.48 for development. Also:
- `cargo`
- `clang`
- the `libacl` library and its header files (Debian: `libacl1-dev`, RedHat: `libacl-devel`, Alpine: `acl-dev`)

Build binary, install:
``` console
$ cargo build --release
$ sudo install -m755 target/release/laurel /usr/local/sbin/laurel
```

## …or use one of the provided binaries

For tagged releases, two types of binaries are created:

- a statically-linked, [musl-libc](https://musl.libc.org) version, built on Alpine 3.14,
- a dynamically-linked version based on GNU libc, built on Debian 10.
- a dynamically-linked version based on an older version of GNU libc, built on CentOS 7.

The static build lacks the ability to perform user and group lookups using the _nsswitch_ facility used on GNU-libc-based systems, therefore it should be avoided on systems where other user/group databases than local `/etc/passwd` and `/etc/group` files are used (cf. issue #84).

The provided binaries are built using Github's CI mechanism. See `.github/workflows/` for details.

Extract binary, install:
``` console
$ tar xzf laurel-$FLAVOR.tar.gz laurel
$ sudo install -m755 laurel /usr/local/sbin/laurel
```

## Set up _auditd_ to use _LAUREL_ and configure _LAUREL_ itself

- Create a dedicated user, e.g.:
    ``` console
    $ sudo useradd --system --home-dir /var/log/laurel --create-home _laurel
    ```
- Configure _LAUREL_: Copy the provided annotated [example](etc/laurel/config.toml) to `/etc/laurel/config.toml` and customize it.
- Register _LAUREL_ as an _auditd_ plugin: Copy the provided [example](etc/audit/plugins.d/laurel.conf) to `/etc/audisp/plugins.d/laurel.conf` or `/etc/audit/plugins.d/laurel.conf` (depending on your _auditd_ version).
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

For debugging and other testing purposes, _LAUREL_ can be run without specifying any configuration file. It will then not change users and read events from standard input, just as it would when called from _auditd_. Log entries are written to `audit.log` in the current working directory.
