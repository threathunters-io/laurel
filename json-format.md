# JSON-based log format produced by _LAUREL_

This document describes the structure and encoding for the JSON-based log format that is produced by LAUREL.

## Structure

Every audit log line produced by _LAUREL_ is one single JSON object that contains at least an `ID` field.

`SYSCALL`, `EXECVE`, `CWD`, `PROCTITLE` fields point to single JSON objects.

`PATH`, `SOCKADDR` fields point to a list of JSON objects.

Every other kernel-produced audit message not mentioned above results in field pointing to a list of JSON objects. Details may change after the list of kernel audit message types has been reviewed.

Some entries contain transformed data as lists:
- `SYSCALL.(a0 … a3)` fields are transformed into `SYSCALL.ARGV`
- `EXECVE.a*` fields are transformed into `EXECVE.ARGV`
- `PROCTITLE.proctitle` is split at NULL bytes and transformed into `PROCTITLE.ARGV`.

More transformations will likely be added in the future.

## Encoding of invalid UTF-8 strings and binary data

Since it is not possible to represent arbitrary binary data within JSON strings without applying some encoding, non-printable ASCII characters, the `%` (37), and the `+` (43) ASCII character are percent-encoded.

This behavior may change in the future so that valid UTF-8 byte sequences will be output as-is.

## Numeric values

Numbers in the Linux audit logs may have been formatted as decimal (e.g. user id), hexadecimal (e.g. syscall arguments) or octal numbers (e.g. file modes). Decimal numbers are serialized as regular JSON numbers, i.e. without string quotes. Since JSON number literls do not support octal or decimal encoding, those numbers are serialized as JSON strings with a prefix, e.g. `"0o1337"` or `"0xcafe"`.
