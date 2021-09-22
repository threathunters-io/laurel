# JSON-based log format produced by _LAUREL_

This document describes the structure and encoding for the JSON-based log format that is produced by LAUREL.

## Structure

Every audit log line produced by _LAUREL_ is one single JSON object that contains at least an `ID` field.

`SYSCALL`, `EXECVE`, `CWD`, `PROCTITLE` fields point to single JSON objects.

`PATH`, `SOCKADDR` fields point to lists of JSON objects.

Every other kernel-produced audit message not mentioned above results in field pointing to a list of JSON objects. Details may change after the list of kernel audit message types has been reviewed.

Some entries contain transformed data as lists:
- `SYSCALL.(a0 … a3)` fields are transformed into `SYSCALL.ARGV`
- `EXECVE.a*` fields are transformed into `EXECVE.ARGV`
- `PROCTITLE.proctitle` is split at NULL bytes and transformed into `PROCTITLE.ARGV`.

More transformations will likely be added in the future.

## Encoding of invalid UTF-8 strings and binary data

- Most byte values that represent printable ASCII characters are reproduced as-is (but are subject to JSON string escaping rules).
- Bytes that map to non-printable ASCII characters (less than 32/0x20; 127/0x7f) are percent-encoded.
- Byte values that map to `%` (37/0x25) and `+` (42/0x2b) are percent-encoded.
- Byte values outside of the ASCII range (greater than 127/0x7f) are percent-encoded.

Handling of valid UTF-8 sequences will likely change in the future.

Rationale: The [JSON specification](https://datatracker.ietf.org/doc/html/rfc8259) mandates that "text exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8". JSON strings are comprised of Unicode character and thus cannot be used to represent arbitrary binary data. However, most values we think of as "strings" on Unix systems (processes, file names, command line arguments, environment variables) are, in reality, octet strings with varying restrictions. Being able to store those values without losing detail is important for log files that are used in a security context.

## Numeric values

Numbers in the Linux audit logs may have been formatted as decimal (e.g. user id), hexadecimal (e.g. syscall arguments) or octal numbers (e.g. file modes). Decimal numbers are serialized as regular JSON numbers, i.e. without double quotes. Since JSON number literals do not support octal or hexadecimal encoding, those numbers are serialized as JSON strings with a `0o` or `0x` prefix, e.g. `"0o1337"` or `"0xcafe"`.
