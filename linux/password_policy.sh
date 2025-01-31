#!/bin/bash

# NOTE: Installs libpam_cracklib

# Path 
PWFILE="/etc/security/pwquality.conf"
PAMFILE="/etc/pam.d/common-password"

SYSAUTH="/etc/pam.d/system-auth"
PWAUTH="/etc/pam.d/password-auth"


# Check if requires root privilege
if [[ $EUID -ne 0 ]]; then
   echo "Script must be run with sudo" 1>&2
   exit 1
fi

# Set the requirements, placeholder
declare -A configs
configs=(
    ["retry"]="3"
    ["minlen"]="16"
)

    # ["dcredit"]="-1"
    # ["ucredit"]="-1"
    # ["ocredit"]="-1""
    # ["deny"]="-1"
    # ["unlock"]="-1"
    # ["pwhist"]="-1"


# Configure settings
if [ -f $PWFILE ]; then
    for item in "${!configs[@]}"; do
        if grep -q "^.*$item.*$" $PWFILE; then
            sed -i "s/^.*$item.*$/$item=${configs[$item]}/" $PWFILE
        else
            echo "$item=${configs[$item]}" | tee -a $PWFILE
        fi
    done
else
    if [ -x "$(command -v yum)" ]; then
        yum install -y pam
    elif [ -x "$(command -v apt)" ]; then
        apt update && apt install -y libpam-pwquality
    fi

    new_line="password required pam_pwquality.so "
    for item in "${!configs[@]}"; do
        new_line+=" ${item}=${configs[$item]}"
    done

    # Password quality config
    if [ -f $PAMFILE ]; then
        sed -i "/pam_pwquality\.so/ c\\$new_line" $PAMFILE
    else
        echo $new_line >> $PAMFILE
    fi 
fi

# Edit in system-auth, password-auth 
if [ -f $SYSAUTH ]; then
    sed -i "/auth        required      pam_env.so/a auth        required      pam_tally2.so deny=$deny unlock_time=$unlock" /etc/pam.d/system-auth
    sed -i "/account     required      pam_unix.so/a account     required      pam_tally2.so" /etc/pam.d/system-auth
    sed -i "s/^password.*pam_unix.so/& remember=$pwhist/" /etc/pam.d/system-auth
fi

if [ -f $PWAUTH ]; then
    sed -i "/auth        required      pam_env.so/a auth        required      pam_tally2.so deny=$deny unlock_time=$unlock" /etc/pam.d/password-auth
    sed -i "/account     required      pam_unix.so/a account     required      pam_tally2.so" /etc/pam.d/password-auth
    sed -i "s/^password.*pam_unix.so/& remember=$pwhist/" /etc/pam.d/password-auth
fi
