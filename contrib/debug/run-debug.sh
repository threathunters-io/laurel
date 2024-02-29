#!/bin/sh

set -eu

readonly AUDISPD_EVENTS=/var/run/audispd_events
USER=$(id -un)

if ! [ -S "$AUDISPD_EVENTS" ]; then
    echo "Please enable the af_unix plugin (/etc/audit/plugins.d/af_unix.conf" >&2
    exit 1
fi

config=$(mktemp -t laurel-config.toml.XXXXXXXXXX)
trap 'rm -f $config' EXIT

sedexpr="s,%USER%,$USER,g; s,%AUDISPD_EVENTS%,$AUDISPD_EVENTS,g"
dir=$(dirname "$0")

if [ -e "$dir/config.toml.template" ]; then
    echo "Writing $dir/config.toml.template to $config..."
    sed "$sedexpr" > "$config" < "$dir/config.toml.template"
else
    echo "Writing internal default template to $config..."
    sed "$sedexpr" > "$config" <<EOF
directory = "."
user = "%USER%"
input = "unix:%AUDISPD_EVENTS%"
marker = "test-$$"

[auditlog]
file = "audit.log"
size = 100000000
generations = 2

[filterlog]
file = "filter.log"
size = 100000000
generations = 2

[transform]

execve-argv = [ "array" ]

[translate]

universal = true
user-db = true
drop-raw = false

[enrich]

pid = true
execve-env = [ "LD_PRELOAD", "LD_LIBRARY_PATH" ]
container = true

[label-process]

label-exe.'^/usr/bin/date$' = "date"
label-exe.'^/usr/bin/sleep$' = "sleep"

[filter]

filter-keys = [ "fork" ]
filter-labels = [ "date", "sleep" ]
filter-action = "log"

EOF
fi

echo "Starting Laurel..."
sudo ./target/debug/laurel -c "$config"
