#!/bin/bash

# Function to calculate hashes
calculate_hashes() {
    local output_file=$1
    > "$output_file"
    for file in "${FILES_TO_CHECK[@]}"; do
        echo "Processing $file..."
        if [ -f "$file" ]; then
            hash=$(sha256sum "$file" | cut -d' ' -f1)
            echo "$file: $hash" >> "$output_file"
        elif [ -d "$file" ]; then
            hash=$(find "$file" -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
            echo "$file: $hash" >> "$output_file"
        fi
        echo "Done processing $file."
    done

    # Calculate hash for SSH authorized_keys files
    for user_home in /home/*; do
        if [ -d "$user_home/.ssh" ]; then
            auth_keys_file="$user_home/.ssh/authorized_keys"
            if [ -f "$auth_keys_file" ]; then
                echo "Processing $auth_keys_file..."
                hash=$(sha256sum "$auth_keys_file" | cut -d' ' -f1)
                echo "$auth_keys_file: $hash" >> "$output_file"
                echo "Done processing $auth_keys_file."
            fi
        fi
    done

    # Calculate hash for firewall rules
    echo "Processing firewall rules..."
    firewall_hash=$(iptables-save | grep -v -E '^(#|:)' | sort | sha256sum | cut -d' ' -f1)
    echo "Firewall Rules: $firewall_hash" >> "$output_file"
    echo "Done processing firewall rules."
}

# Files and directories to be checked
FILES_TO_CHECK=(
    "/etc/passwd"      # User account information
    "/etc/shadow"      # Encrypted user passwords
    "/etc/group"       # Group information
    "/etc/sudoers"     # sudo configuration
    "/etc/hosts"       # Static table lookup for hostnames
    "/etc/network/interfaces"  # Network interface configuration
    "/etc/resolv.conf"  # DNS resolver configuration
    "/etc/hosts.allow"  # TCP wrapper access control (allowed hosts)
    "/etc/hosts.deny"   # TCP wrapper access control (denied hosts)
    "/etc/ssh/sshd_config"  # SSH server configuration
    "/etc/ssh/ssh_config"   # SSH client configuration
    "/etc/pam.d/"      # PAM (Pluggable Authentication Modules) configuration
    "/etc/apparmor/"   # AppArmor security profiles
    "/etc/crontab"     # System-wide crontab
    "/var/spool/cron/" # User-specific crontabs
    "/etc/init.d/"     # SysV init scripts
    "/etc/iptables/"   # iptables configuration files (if stored here)
)

#    "/var/log/auth.log"  # Authentication log
#    "/var/log/syslog"    # System log
#    "/var/log/messages"  # General message log

# Output files
OUTPUT_FILE="hashes.txt"
TEMP_FILE="temp_hashes.txt"
MODIFIED_FILE="modified_files.txt"

# Ask the user if they want to verify integrity of a previous output
echo ""
echo "Do you want to verify the integrity of a previous output? (y/n)"
read -r response
echo ""

if [ "$response" = "y" ]; then
    # Request the previous checksum from the user
    echo "Enter the checksum of the previous output:"
    read -r previous_checksum
    echo ""

    # Calculate new hashes
    calculate_hashes "$TEMP_FILE"

    # Calculate checksum of the temporary file
    if [ -f "$TEMP_FILE" ]; then
        current_checksum=$(sha256sum "$TEMP_FILE" | cut -d' ' -f1)
        
        # Compare checksums
        if [ "$previous_checksum" = "$current_checksum" ]; then
            echo ""
            echo "No changes detected."
            echo ""
        else
            echo ""
            echo "Changes detected. Saving new hashes to $OUTPUT_FILE"
            echo ""
            
            # Identify which files were modified
            if [ -f "$OUTPUT_FILE" ]; then
                diff <(sort "$OUTPUT_FILE") <(sort "$TEMP_FILE") > "$MODIFIED_FILE"
                echo "Modified files or rules:"
                echo ""
                cat "$MODIFIED_FILE"
            fi
            
            mv "$TEMP_FILE" "$OUTPUT_FILE"
            echo ""
            echo "New checksum: $current_checksum"
            echo ""
        fi
    else
        echo "Error: $TEMP_FILE not found."
    fi
else
    # Calculate hashes and save to output file
    calculate_hashes "$OUTPUT_FILE"
    # Calculate checksum of the hashes.txt file
    checksum=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
    echo ""
    echo ""
    echo "Checksum of $OUTPUT_FILE: $checksum"
    echo ""
    
fi

# Clean up temporary files
rm -f "$TEMP_FILE" "$MODIFIED_FILE"
