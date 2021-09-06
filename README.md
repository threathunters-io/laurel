# Linux Audit – Usable, Robust, Easy Logging

Logs produced by the Linux Audit subsystem and _auditd(8)_ contain information that can be very useful in a SIEM context (if a useful ruleset has been configured). However, the format is not well-suited for at-scale analysis: Events are usually split across different lines that have to be merged using a message identifier. Files and program executions are logged via `PATH` and `EXECVE` elements, but a limited character set for strings causes many of those entries to be hex-encoded. For a more detailed discussion, see [Practical _auditd(8)_ problems](practical-auditd-problems.md)

_LAUREL_ solves these problems by consuming audit events, parsing and transforming them into more data and writing them out as a JSON-based log format, while keeping all information intact that was part of the original audit log. It does not replace _auditd(8)_ as the consumer of audit messages from the kernel. Instead, it uses the _audisp_ ("audit dispatch") interface to receive messages via _auditd(8)_. Therefore, it can peacefully coexist with other consumers of audit events (e.g. some EDR products).

Refer to [JSON-based log format](json-format.md) for a description of the log format.

We developed this tool because we were not content with feature sets and performance characteristics of existing projects and products. Please refer to [Performacne](performance.md) for details.

## Build from source

_LAUREL_ is written in Rust. To build it, a reasonably recent Rust compiler (we currently use 1.48), `cargo`, and the 
`libacl` library and its header files (Debian: `libacl1-dev`, RedHat: `libacl-devel`) are required.

``` console
$ cargo build --release
$ sudo install -m755 target/release/laurel /usr/local/sbin/laurel
```

## Configure, use

- Create a dedicated user, e.g.:
    ``` console
	$ sudo useradd --system --home-dir /var/lib/laurel --create-home _laurel
	```
- Configure _LAUREL_, write to `/etc/laurel/config.toml`:
    ``` toml
    directory = "/var/log/laurel"
    user = "_laurel"
    
    [auditlog]
    file = "audit.log"
    size = 1000000
    generations = 10
    read-users = [ "splunk" ]
	```
- Register _LAUREL_ as an _audisp_ plugin, write to (depending on your _auditd_ version) `/etc/audisp/plugins.d/laurel.conf` or `/etc/audit/plugins.d/laurel.conf`:
    ``` ini
    active = yes
    direction = out
    type = always
    format = string
    path = /usr/local/sbin/laurel
    args = --config /etc/laurel/config.toml
	```
  
- Tell _auditd(8)_ to re-evaluate its configuration
    ``` console
    $ sudo pkill -HUP auditd
    ```

## License

GNU General Public License, version 3

## Authors

- Hilko Bengen <<bengen@hilluzination.de>>
- Sergej Schmidt
