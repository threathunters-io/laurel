#!/bin/sh
set -x

### Variables
LAUREL_VERSION="v0.1.3"
LAUREL_SERVICE_USER="_laurel"
LAUREL_LOG_PATH="/var/log/laurel"
LAUREL_BINARY_PATH="/usr/local/sbin"
DOWNLOAD_CMD="echo 'No downloader tool found. Please install first any like curl, wget.'"
AUDITD_PLUGIN_PATH="none" # will be selected later...
### END Variables


# Check if script is running with sudo permission
[ "$(id -u)" != "0" ] && echo "This script must be run as root, because we must create files in /etc and a user if necessary. Please rerun the script with 'sudo'." && exit 1

# Check which plugin path exist for the current auditd:
if [[ -d "/etc/audisp/plugins.d" ]];then
    AUDITD_PLUGIN_PATH="/etc/audisp/plugins.d"
elif [[ -d "/etc/audit/plugins.d" ]];then
    AUDITD_PLUGIN_PATH="/etc/audit/plugins.d"
fi

# Check if service user exist
if [[ -z $(cat /etc/passwd|grep "$LAUREL_SERVICE_USER") ]]; then
    # If not create it
    useradd --system --home-dir "$LAUREL_LOG_PATH" --create-home "$LAUREL_SERVICE_USER"
fi


#
# Install Laurel binary, and download (optional) if not existing:
#
TMP_FILE_PATH="/tmp/laurel-$LAUREL_VERSION-x86_64-musl.tar.gz"
if [[ -f $TMP_FILE_PATH ]]; then
    echo "Reuse existing File $TMP_FILE_PATH"
    mkdir /tmp/laurel
    tar -xzv -C /tmp/laurel -f "$TMP_FILE_PATH"
    # Install binary
    mv /tmp/laurel/laurel "$LAUREL_BINARY_PATH"
    # Cleanup
    rm -Rf /tmp/laurel*
else
    echo "Laurel package $TMP_FILE_PATH was not found, I try to download it..."
    if [[ "$(command -v curl)" ]]; then
        DOWNLOAD_CMD="curl -o /tmp/laurel-$LAUREL_VERSION-x86_64-musl.tar.gz"
        echo "I found curl so I try to download with curl..."
    elif [[ "$(command -v wget)" ]]; then
        DOWNLOAD_CMD="wget -T 5"
        echo "I found wget so I try to download with wget..."
    fi
    $DOWNLOAD_CMD "https://github.com/threathunters-io/laurel/releases/download/$LAUREL_VERSION/laurel-$LAUREL_VERSION-x86_64-musl.tar.gz"
    RESULT=$?
    [[ $RESULT -ne 0 ]] && echo "Download was successful. I restart the script." && sh $0 && exit 0
    [[ $RESULT -eq 0 ]] && echo "Download was NOT successful. Please download manually and add it to $TMP_FILE_PATH. Then restart the script." && rm -f $TMP_FILE_PATH && exit 0
fi

#
# Configure LAUREL: Copy the provided annotated example to /etc/laurel/config.toml and customize it.
#
mkdir -p /etc/laurel
cat > /etc/laurel/config.toml << EOF
# Write log files relative to this directory
directory = "$LAUREL_LOG_PATH"
# Drop privileges from root to this user
user = "$LAUREL_SERVICE_USER"

[auditlog]
# Base file name for the JSONL-based log file
file = "audit.log"
# Rotate when log file reaches this size (in bytes)
size = 1000000
# When rotating, keep this number of generations around
generations = 10
# Grant read permissions on the log files to these users, using
# POSIX ACLs
read-users = [ "splunk" ]

[transform]

# "array" (the default) causes EXECVE a0, a1, a2 … arguments to be
# output as a list of strings, "ARGV". This is the default, it allows
# analysts to reliably reproduce what was executed.
#
# "string" causes arguments to be concatenated into a single string,
# separated by space characters, "ARGV_STR". This form allows for
# easier grepping, but it is impossible to tell if space characters in
# the resulting string are a separator or were part of an individual
# argument in the original command line.

execve-argv = [ "array" ]

#  execve-argv = [ "array", "string" ]

EOF


#
# Register LAUREL as an audisp plugin: Copy the provided example to /etc/audisp/plugins.d/laurel.conf or /etc/audit/plugins.d/laurel.conf (depending on your auditd version).
#
cat > "$AUDITD_PLUGIN_PATH/laurel.con" << EOF
active = yes
direction = out
type = always
format = string
path = $LAUREL_BINARY_PATH/laurel
args = --config /etc/laurel/config.toml

EOF


#
# Tell auditd(8) to re-evaluate its configuration
#
pkill -HUP auditd
