#!/bin/bash
#
# Setup mail server, local DNS resolver and Roundcube webmail

DEBUG='true'

set -euo pipefail

# set -x enables a mode of the shell where all executed commands are printed to the terminal. 
# It's used for debugging, which is a typical use case for set -x: printing every command.
# As it is executed may help you to visualize the control flow of the script if it is not functioning as expected.
# set +x disables it.
[ "$DEBUG" == 'true' ] && set -x

LOCATION_OF_MY_FILES='/root/mail-server-setup/templates'
WWW_ROOT='/var/www/example.com'
WWW_PROD_ROOT="${WWW_ROOT}/prod"

# You can always check the current version: https://roundcube.net/download/
ROUNDCUBE_VERSION="1.4.12"
ROUNDCUBE_ROOT_LOCATION="${WWW_PROD_ROOT}/roundcube-installation-path"

# GLOBALS:
#   LOCATION_OF_MY_FILES
function replace_with_my_file() {
  local ORIGINAL_TO_REPLACE \
        MY_REPLACEMENT

  ORIGINAL_TO_REPLACE="$1"

  # Replace / with % to get replacement file path
  MY_REPLACEMENT="$(echo "$ORIGINAL_TO_REPLACE" | sed 's;/;%;g')"

  MY_REPLACEMENT="${LOCATION_OF_MY_FILES}/${MY_REPLACEMENT}"

  if [[ ! -f "$MY_REPLACEMENT" ]]; then 
    echo "MY_REPLACEMENT: $MY_REPLACEMENT file dont exists"
    return 1
  else
    echo "MY_REPLACEMENT: $MY_REPLACEMENT file exists"
  fi
  
  if [[ -f "$ORIGINAL_TO_REPLACE" ]]; then 
    echo "ORIGINAL_TO_REPLACE: $ORIGINAL_TO_REPLACE file exists"
    rm "$ORIGINAL_TO_REPLACE"
    mv "$MY_REPLACEMENT" "$ORIGINAL_TO_REPLACE"
    cp "$ORIGINAL_TO_REPLACE" "$MY_REPLACEMENT"
  else
    echo "[!] Error no such file ORIGINAL_TO_REPLACE: $ORIGINAL_TO_REPLACE"
    return 1
  fi  
}

#######################################
# Globals: 
#   ROUNDCUBE_ROOT_LOCATION
#######################################
function setup_roundcube_fail2ban() {
  local ROUNDCUBE_USERLOGINS_LOG

  ROUNDCUBE_USERLOGINS_LOG="${ROUNDCUBE_ROOT_LOCATION}/logs/userlogins.log"
  # Check if the jail exists (2 ways):
  # fail2ban-client status | grep -iq 'roundcube-auth'
  # grep -iq 'roundcube-auth' /etc/fail2ban/jail.local
  if fail2ban-client status | grep -iq roundcube-auth; then 
    : # do nothing
  else
    echo "--> Appending entry to: /etc/fail2ban/jail.local"
    cat <<EOF >> /etc/fail2ban/jail.local

[roundcube-auth]
enabled = true
maxretry = 5
bantime = 5m
port     = http,https
filter = roundcube-auth
logpath  = $ROUNDCUBE_USERLOGINS_LOG
EOF
    systemctl restart fail2ban
    # Verify that is all ok
    systemctl status fail2ban

  fi
}

################################################################################
### Setting up Roundcube webmail
# https://www.linuxbabe.com/ubuntu/install-roundcube-webmail-ubuntu-20-04-apache-nginx
#
# Somebodys roundcube plugins
# https://notes.sagredo.eu/en/qmail-notes-185/roundcube-plugins-35.html
################################################################################
function setup_roundcube_webmail() {
  ### Download Roundcube Webmail on Ubuntu 20.04
  wget "https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBE_VERSION}/roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz"

  # Extract the tarball, move the newly created folder to web root (/var/www/) and rename it as roundcube at the same time.
  tar xvf "roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz"
  mv roundcubemail-${ROUNDCUBE_VERSION}/* "$ROUNDCUBE_ROOT_LOCATION" 


  ### Install Dependencies

  # Install required PHP extensions.
  apt-get install -y php-net-ldap2 php-net-ldap3 php-imagick php7.4-common php7.4-gd php7.4-imap php7.4-json php7.4-curl php7.4-zip php7.4-xml php7.4-mbstring php7.4-bz2 php7.4-intl php7.4-gmp
  # Install Composer, which is a dependency manager for PHP.
  apt-get install -y composer
  # Change into the roundcube directory.
  cd "$ROUNDCUBE_ROOT_LOCATION"
  # Use Composer to install all needed dependencies (3rd party libraries) for Roundcube Webmail.

  # It will throw a warning but it must be run as root
  composer install --no-dev

  # If you see the nothing to install or update message, then all dependencies are installed.

  # Make the web server user (www-data) as the owner of the temp and logs directory so that web server can write to these two directories.
  chown www-data:www-data temp/ logs/ -R


  ### Create a MariaDB Database and User for Roundcube

  # Execute SQL file creating database, user and granting priviledges
  #mysql -u root < roundcube_setup.sql
  # OR sth like
  #
  # Then create a new database for Roundcube using the following command. 
  # This tutorial name it roundcube, you can use whatever name you like for the database.
  mysql -u root -e "CREATE DATABASE roundcube DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;"
  # Next, create a new database user on localhost using the following command. 
  # Again, this tutorial name it roundcubeusername, you can use whatever name you like. 
  # Replace password with your preferred password.
  mysql -u root -e "CREATE USER roundcubeusername@localhost IDENTIFIED BY 'your_password';"
  # Then grant all permission of the new database to the new user so later on Roundcube webmail can write to the database.
  mysql -u root -e "GRANT ALL PRIVILEGES ON roundcube.* TO roundcubeusername@localhost;"
  # Flush the privileges table for the changes to take effect.
  mysql -u root -e "flush privileges;"


  # Import the initial tables to roundcube database.
  mysql roundcube < "${ROUNDCUBE_ROOT_LOCATION}/SQL/mysql.initial.sql"

  ### Finish the Installation in Web Browser
  # https://mail.example.com/installer/

  press_anything_to_continue "
  (Enter) Press any key to continue 
  THIS IS TEMPORARY HERE!
  "

  # This was generated by installer and have to be put here
  # More configuration options: https://github.com/roundcube/roundcubemail/wiki/Configuration

  cp "${LOCATION_OF_MY_FILES}/%var%www%example.com%mail%config%config.inc.php" "${ROUNDCUBE_ROOT_LOCATION}/config/config.inc.php"

  # Copy mime.types file for error: Mimetype to file extension mapping:  NOT OK 
  cp "${LOCATION_OF_MY_FILES}/%var%www%example.com%mail%config%mime.types" "${ROUNDCUBE_ROOT_LOCATION}/config/mime.types"


  # After completing the installation and the final tests please 
  # remove the whole installer folder from the document root of the webserver 
  # or make sure that 'enable_installer' option in config.inc.php is disabled.
  #
  # These files may expose sensitive configuration data like server passwords
  # and encryption keys to the public. 
  # Make sure you cannot access this installer from your browser.
  rm "${ROUNDCUBE_ROOT_LOCATION}/installer/" -r


  ### Configure the Password Plugin in Roundcube

  # Roundcube includes a password plugin that allows users to change 
  # their passwords from the webmail interface.

  # However, we need to configure this plugin before it will work. 
  # Run the following command to copy the distributed password plugin config file to a new file.
  cp "${ROUNDCUBE_ROOT_LOCATION}/plugins/password/config.inc.php.dist" "${ROUNDCUBE_ROOT_LOCATION}/plugins/password/config.inc.php"

  mv "${LOCATION_OF_MY_FILES}/%var%www%example.com%mail%plugins%password%config.inc.php" "${ROUNDCUBE_ROOT_LOCATION}/plugins/password/config.inc.php"

  # Since this file contains the database password, 
  # we should allow only the www-data user to read and write to this file.
  chown www-data:www-data "${ROUNDCUBE_ROOT_LOCATION}/plugins/password/config.inc.php"
  chmod 600 "${ROUNDCUBE_ROOT_LOCATION}/plugins/password/config.inc.php"


  # Use client_max_body_size and set it to the desired value in your server blocks. Nginx will directly drop the handling of the request if the request body exceeds the size specified in this directive. Please note that you won't get any POST submitted in that case.

  # There are 3 plugins in Roundcube for attachments/file upload:
  #
  # * database_attachments
  # * filesystem_attachments
  # * redundant_attachments
  #
  # Roundcube can use only one plugin for attachments/file uploads. 
  # I found that the 'database_attachment' plugin can be error_prone and cause you trouble. 


  ### For problems check: /var/log/nginx/example.com/mail.err

  # This file have to exist before restarting fail2ban bcs of /etc/fail2ban/jail.local
  mkdir_if_not_exists "${ROUNDCUBE_ROOT_LOCATION}/logs"
  [[ -f "${ROUNDCUBE_ROOT_LOCATION}/logs/userlogins.log" ]] || touch "${ROUNDCUBE_ROOT_LOCATION}/logs/userlogins.log"
}

function setup_amavis() {
  apt-get install -y amavisd-new 

  # Enable auto-start at boot time.
  systemctl enable amavis

  # Check logs of amavis
  #journalctl -eu amavis 

  # Viruses are commonly spread as attachments to email messages. 
  # Install the following packages for Amavis to extract and scan archive files 
  # in email messages such as .7z, .cab, .doc, .exe, .iso, .jar, and .rar files.
  apt-get install -y arj bzip2 cabextract cpio rpm2cpio file gzip lhasa nomarch pax p7zip-full unzip zip lrzip lzip liblz4-tool lzop unrar-free
  # unrar-free is replacement for original: rar unrar packages names

  # NOTE: that if your server doesn’t use a fully-qualified domain name (FQDN) 
  # as the hostname, Amavis might fail to start. And the OS hostname might change,
  # so it’s recommended to set a valid hostname directly in the Amavis configuration file.
  # IN: /etc/amavis/conf.d/05-node_id
  replace_with_my_file "/etc/amavis/conf.d/05-node_id"
  systemctl restart amavis

  ### Integrate Amavis with ClamAV

  apt-get install -y clamav clamav-daemon
  # There will be two systemd services installed by ClamAV:
  #   clamav-daemon.service: the Clam AntiVirus userspace daemon
  #   clamav-freshclam.service: the ClamAV virus database updater

  # Check journal/log
  #journalctl -eu clamav-freshclam

  systemctl restart clamav-daemon

  # The clamav-freshclam.service will check ClamAV virus database updates once per hour.

  # Now we need to turn on virus-checking in Amavis.
  replace_with_my_file "/etc/amavis/conf.d/15-content_filter_mode"

  # There are lots of antivirus scanners in the /etc/amavis/conf.d/15-av_scanners file.
  # ClamAV is the default. Amavis will call ClamAV via the /var/run/clamav/clamd.ctl Unix socket. 
  # We need to add user clamav to the amavis group.
  adduser clamav amavis
  systemctl restart amavis clamav-daemon

  # Test: if received email have:
  # ex. header: X-Virus-Scanned: Debian amavisd-new at example.com
}


function upgrade_roundcube() {
  ### How to Upgrade Roundcube

  # Download the Roundcube latest version to your home directory.
  cd ~
  wget https://github.com/roundcube/roundcubemail/releases/download/1.5.0/roundcubemail-1.5.0-complete.tar.gz
  # Extract the archive.
  tar xvf roundcubemail-1.5.0-complete.tar.gz
  # Change the owner to www-data.
  chown www-data:www-data roundcubemail-1.5.0/ -R
  # Then run the install script.
  roundcubemail-1.5.0/bin/installto.sh "${ROUNDCUBE_ROOT_LOCATION}/"
  # Once it’s done, log into Roundcube webmail and click the 
  # About button to check what version of Rouncube you are using.
}

function command_exists() {
  command -v "$@" >/dev/null 2>&1
}

function press_anything_to_continue() {
  local PROMPT_MESSAGE
  if [[ $# -eq 1 ]]; then
    PROMPT_MESSAGE="$1"
  else
    PROMPT_MESSAGE="Press any key to continue"
  fi
  read -n 1 -s -r -p "$PROMPT_MESSAGE"
  # -n defines the required character count to stop reading
  # -s hides the user's input
  # -r causes the string to be interpreted "raw" (without considering backslash escapes)
  echo ""
}

function mkdir_if_not_exists() {
  local DIRECTORY
  DIRECTORY="$1"
  if [[ ! -d "$DIRECTORY" ]]; then
    mkdir "$DIRECTORY"
  fi
}


# Pflogsumm is a great tool to create a summary of Postfix logs. Install it on Ubuntu with:
apt-get install -y pflogsumm

### Using the mail program to Send and Read Email
# Now let’s install a command-line MUA (mail user agent)
apt-get install -y mailutils


# Ensure cron is installed and working
apt-get install -y cron
systemctl enable cron
systemctl start cron

################################################################################
# 1
################################################################################
NEW_HOSTNAME='mail.example.com'
POSTFIX_main_mailer_type='Internet Site'
POSTFIX_mailname="example.com"
##########################################

# update && upgrade is enough I think
apt-get update -y && sudo apt-get upgrade -y && apt-get autoremove -y && apt-get autoclean -y

# cp /etc/hostname
hostnamectl set-hostname "$NEW_HOSTNAME" # Equivalent of replacing /etc/hostname
replace_with_my_file "/etc/hosts"
replace_with_my_file "/etc/aliases" # Email Aliases
newaliases

# Install postfix
#printf "\n[debconf-set-selections]\n\n"
# Taken from: https://serverfault.com/a/144010
debconf-set-selections -v <<< "postfix postfix/main_mailer_type string $POSTFIX_main_mailer_type"
debconf-set-selections -v <<< "postfix postfix/mailname string $POSTFIX_mailname"

apt-get install -y postfix

# Open TCP Port 25 (inbound) in Firewall
ufw allow 25/tcp

### Restart Postfix for the changes to take effect.
systemctl restart postfix

### Upgrading Postfix

# If you run sudo apt update, then sudo apt upgrade, 
# and the system is going to upgrade Postfix, you might be prompted to choose
# a configuration type for Postfix again. This time you should choose:
# 'No configuration' to leave your current configuration file untouched.
debconf-set-selections <<< "postfix postfix/main_mailer_type string No configuration"
apt-get update -y && sudo apt-get upgrade -y 

################################################################################
# 2
################################################################################
ufw allow 80,443,587,465,143,993/tcp

# POP: If you use POP3 to fetch emails (For Gmail), then also open port 110 and 995.
ufw allow 110,995/tcp

# cp all_config_postfix
replace_with_my_file "/etc/postfix/main.cf"
replace_with_my_file "/etc/postfix/master.cf"

# install dovecot
apt-get install -y dovecot-core dovecot-imapd 

# POP: If you use POP3 to fetch emails, then also install the dovecot-pop3d package.
apt-get install -y dovecot-pop3d

# cp all_config_dovecot

# Dovecot main configuration file
replace_with_my_file "/etc/dovecot/dovecot.conf"
# The config file for mailbox locations and namespaces
replace_with_my_file "/etc/dovecot/conf.d/10-mail.conf"
# Master config file
replace_with_my_file "/etc/dovecot/conf.d/10-master.conf"
# Authentication config file.
replace_with_my_file "/etc/dovecot/conf.d/10-auth.conf"
# SSL/TLS config file.
replace_with_my_file "/etc/dovecot/conf.d/10-ssl.conf"
# Auto-create Sent and Trash Folder
replace_with_my_file "/etc/dovecot/conf.d/15-mailboxes.conf"

################################################################################
# 3
################################################################################

### Install PostfixAdmin on Ubuntu 20.04 Server
apt-get install -y dbconfig-no-thanks
apt-get install -y postfixadmin
apt-get remove -y dbconfig-no-thanks

press_anything_to_continue "
(Enter) Press any key to continue and later answear:

<YES>
Choose DBMS (only if you have more than 1 DBMS (example MySQL and postgreSQL) installed)
Unix socket.
default
(Enter)
(Enter)
2x MySQL postfixadmin password
(Enter)
"

# YES
# Choose db (if you have mysql and other installed)
# Unix socket.
# default
# (enter) to keep 'postfixadmin'
# (enter)
# (password 2wice (should not contain the # ) 
# choose the default database administrative user. 

dpkg-reconfigure postfixadmin

# PostfixAdmin
replace_with_my_file "/etc/dbconfig-common/postfixadmin.conf"
replace_with_my_file "/etc/postfixadmin/dbconfig.inc.php"

mkdir /usr/share/postfixadmin/templates_c

# If your system can’t find the setfacl command, you need to install the acl package.
command_exists 'setfacl' || apt-get install -y acl
# Give www-data user read, write and execute permissions on this dir
setfacl -R -m u:www-data:rwx /usr/share/postfixadmin/templates_c/

# Create Nginx Config File for PostfixAdmin
# ALREADY DONE: cp /etc/nginx/conf.d/postfixadmin.conf 
nginx -t && systemctl reload nginx

# Now you should be able to see the PostfixAdmin web-based install wizard
# at http://example.com/your-postfix-path/setup.php

# Install Required and Recommended PHP Modules
apt-get install -y php7.4-fpm php7.4-imap php7.4-mbstring php7.4-mysql php7.4-json php7.4-curl php7.4-zip php7.4-xml php7.4-bz2 php7.4-intl php7.4-gmp

# Use Strong Password Scheme in PostfixAdmin and Dovecot
cp "${LOCATION_OF_MY_FILES}/%usr%share%postfixadmin%config.local.php" /usr/share/postfixadmin/config.local.php
ln -s /usr/share/postfixadmin/config.local.php /etc/postfixadmin/config.local.php

# Add the web server to the dovecot group.
sudo gpasswd -a www-data dovecot

## Configure Postfix to Use MySQL/MariaDB Database

# First, we need to add MySQL map support for Postfix by installing the postfix-mysql package.
apt-get install -y postfix-mysql

mkdir /etc/postfix/sql/
# all these files should contain password set in postfixadmin installation wizard
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_domains_maps.cf" /etc/postfix/sql/mysql_virtual_domains_maps.cf
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_mailbox_maps.cf" /etc/postfix/sql/mysql_virtual_mailbox_maps.cf
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_alias_domain_mailbox_maps.cf" /etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_alias_maps.cf" /etc/postfix/sql/mysql_virtual_alias_maps.cf
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_alias_domain_maps.cf" /etc/postfix/sql/mysql_virtual_alias_domain_maps.cf
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%sql%/mysql_virtual_alias_domain_catchall_maps.cf" /etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf

# Since the database passwords are stored in plain text so they should be readable
# only by user postfix and root, which is done by executing the following two commands.
chmod 0640 /etc/postfix/sql/*
setfacl -R -m u:postfix:rx /etc/postfix/sql/

# create a user named vmail with ID 2000 and a group with ID 2000. (as set in /etc/postfix/main.cf)
adduser vmail --system --group --uid 2000 --disabled-login --no-create-home

# Create the mail base location.
mkdir /var/vmail/

# Make vmail as the owner.
chown vmail:vmail /var/vmail/ -R

## Configure Dovecot to Use MySQL/MariaDB Database

# We also need to configure the Dovecot IMAP server to query user information from the database.
apt-get install -y dovecot-mysql

# password set in postfixadmin installation wizard
replace_with_my_file "/etc/dovecot/dovecot-sql.conf.ext"

## Add Domain and Mailboxes in PostfixAdmin 

# Login to postfix and do stuff from: Step 12: Add Domain and Mailboxes in PostfixAdmin
# 1. Domain List > New Domain
# 2. Virtual List > Add Mailbox


#################### ADDITIONALY #########################
### ADDITIONALY
#################### ADDITIONALY #########################
echo ""
echo "visit: https://example.com/your-postfix-path/setup.php and configure postfixadmin"
echo "If you are done:"
press_anything_to_continue
echo ""

################################################################################
# 4 
################################################################################

### Configuring SPF Policy Agent

# We need to tell our Postfix SMTP server to check for SPF record of incoming emails. 
# This help with detecting forged incoming emails.
apt-get install -y postfix-policyd-spf-python


### Setting up DKIM

apt-get install -y opendkim opendkim-tools

# Then add postfix user to opendkim group.
gpasswd -a postfix opendkim

# OpenDKIM main configuration file.
replace_with_my_file "/etc/opendkim.conf"

# Below 3 lines are enough for all above section so commented
mv "${LOCATION_OF_MY_FILES}/%etc%opendkim%" /etc/opendkim
# Change the owner from root to opendkim and make sure only opendkim user
# can read and write to the keys directory.
chown -R opendkim:opendkim /etc/opendkim
# Group and others - (minus) read and write
chmod go-rw /etc/opendkim/keys
# And change the permission, so only the opendkim user has read and write access to the file.
chmod 600 /etc/opendkim/keys/example.com/default.private


### Test DKIM Key

# Run on Ubuntu server to test your key.
opendkim-testkey -d example.com -s default -vvv


### Connect Postfix to OpenDKIM

# Create a directory to hold the OpenDKIM socket file and allow only 
# opendkim user and postfix group to access it.
mkdir /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim

replace_with_my_file "/etc/default/opendkim"

systemctl restart opendkim

################################################################################
### 7 Effective Tips to Stop Your Emails Being Marked as Spam
# https://www.linuxbabe.com/mail-server/how-to-stop-your-emails-being-marked-as-spam
################################################################################


################################################################################
# How to Set Up Postfix SMTP Relay on Ubuntu with Sendinblue (optional)
# https://www.linuxbabe.com/mail-server/postfix-smtp-relay-ubuntu-sendinblue
################################################################################

### SMTP Rate Limiting
apt-get install -y policyd-rate-limit
replace_with_my_file "/etc/policyd-rate-limit.yaml"

systemctl restart policyd-rate-limit

################################################################################
# 7 Effective Tips for Blocking Email Spam with Postfix SMTP Server
# https://www.linuxbabe.com/mail-server/block-email-spam-postfix
################################################################################

cp "${LOCATION_OF_MY_FILES}/%etc%postfix%helo_access" /etc/postfix/helo_access


# Then run the following command to create the /etc/postfix/helo_access.db file.
postmap /etc/postfix/helo_access


# Enable Greylisting in Postfix
apt-get install -y postgrey

# Once it’s installed, start it with systemctl.
systemctl start postgrey
# Enable auto-start at boot time.
systemctl enable postgrey

# On Debian and Ubuntu, it listens on TCP port 10023 on localhost (both IPv4 and IPv6).
# TEST: sudo netstat -lnpt | grep postgrey


# Note: You can also see postgrey logs with this command: 
# TEST: sudo journalctl -u postgrey

cp "${LOCATION_OF_MY_FILES}/%etc%postfix%rbl_override" /etc/postfix/rbl_override
# Hash the blacklist
# the file must be converted to a database that Postfix can read. 
# This must be done every time rbl_override is updated.
postmap /etc/postfix/rbl_override

apt-get install -y mutt

apt-get install -y fail2ban

######################### NOT FROM HERE SECTION ################################
### Configure the Sieve Message Filter

# You can create folders in Roundcube webmail and then create rules to filter
# email messages into different folders. In order to do this, you need to install
# the ManageSieve server with the following command.
apt-get install -y dovecot-sieve dovecot-managesieved

# By default, Postfix uses its builtin local delivery agent (LDA) to move inbound emails
# to the message store (inbox, sent, trash, Junk, etc). 
# We can configure it to use Dovecot to deliver emails, via the LMTP protocol, 
# which is a simplified version of SMTP. LMTP allows for a highly scalable 
# and reliable mail system and it is required if you want to use 
# the sieve plugin to filter inbound messages to different folders.
#
# Install the Dovecot LMTP Server.
apt-get install -y dovecot-lmtpd
################################################################################


################################################################################
# 9.
################################################################################

apt-get install -y postfix-pcre

# header_checks
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%header_checks" /etc/postfix/header_checks
postmap /etc/postfix/header_checks 

# body_checks
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%body_checks" /etc/postfix/body_checks
postmap /etc/postfix/body_checks

# Install SpamAssassin
apt-get install -y spamassassin spamc

systemctl enable spamassassin
systemctl start spamassassin

# Integrate SpamAssassin with Postfix SMTP Server as a Milter
apt-get install -y spamass-milter

replace_with_my_file "/etc/default/spamass-milter"

systemctl restart spamass-milter

replace_with_my_file "/etc/default/spamassassin"
replace_with_my_file "/etc/spamassassin/local.cf" # local config  

systemctl restart spamassassin

# Move Spam into the Junk Folder

# This package installs two configuration files under 
# /etc/dovecot/conf.d/ directory: 90-sieve.conf and 90-sieve-extprograms.conf.
apt-get install -y dovecot-sieve

# ADD ALL SIEVE files here
mkdir /var/mail/sieve.d

# All sieve scripts that have to be executed before users scripts should be here
mkdir /var/mail/sieve.d/sieve_before
# Set write permission on vmail:
chown vmail /var/mail/sieve.d/
chmod 755 /var/mail/sieve.d/
chown vmail /var/mail/sieve.d/sieve_before
chmod 755 /var/mail/sieve.d/sieve_before
# OR
chown -R vmail:mail /var/mail/sieve.d/

cp "${LOCATION_OF_MY_FILES}/%etc%dovecot%conf.d%15-lda.conf" /etc/dovecot/conf.d/15-lda.conf
cp "${LOCATION_OF_MY_FILES}/%etc%dovecot%conf.d%20-lmtp.conf" /etc/dovecot/conf.d/20-lmtp.conf

# In: /etc/dovecot/conf.d/90-sieve.conf are specified sieve files to be executed
cp "${LOCATION_OF_MY_FILES}/%etc%dovecot%conf.d%90-sieve.conf" /etc/dovecot/conf.d/90-sieve.conf

# Logging file setting dovecot logs to /var/log/dovecot.log
cp "${LOCATION_OF_MY_FILES}/%etc%dovecot%conf.d%10-logging.conf" /etc/dovecot/conf.d/10-logging.conf

cp "${LOCATION_OF_MY_FILES}/%var%mail%sieve.d%sieve_before%SpamToJunk.sieve" /var/mail/sieve.d/sieve_before/SpamToJunk.sieve
cp "${LOCATION_OF_MY_FILES}/%var%mail%sieve.d%sieve_before%COMPANY_INTERNAL.sieve" /var/mail/sieve.d/sieve_before/COMPANY_INTERNAL.sieve

### Pre-compile .sieve filters
# We can compile this script, so it will run faster.
sievec /var/mail/sieve.d/sieve_before/SpamToJunk.sieve
sievec /var/mail/sieve.d/sieve_before/COMPANY_INTERNAL.sieve

systemctl restart dovecot

# Deleting Email Headers For Outgoing Emails
cp "${LOCATION_OF_MY_FILES}/%etc%postfix%smtp_header_checks" /etc/postfix/smtp_header_checks
#cp /etc/postfix/smtp_header_checks
postmap /etc/postfix/smtp_header_checks
systemctl reload postfix

################################################################################
# 10.
################################################################################
setup_amavis

################################################################################
### ClamAV Automatic Shutdown
################################################################################
#
# I found that the clamav-daemon service has a tendency to stop without clear reason
# even when there’s enough RAM. This will delay emails for 1 minute. 
# We can configure it to automatically restart if it stops via the systemd service unit. 

# Manual
function clamav_auto_restart_manual() {
  # Copy the original service unit file to the /etc/systemd/system/ directory.
  cp /lib/systemd/system/clamav-daemon.service /etc/systemd/system/clamav-daemon.service
  # Then edit the service unit file.
  vim /etc/systemd/system/clamav-daemon.service
  # Add the following two lines in the [service] section.
  Restart=always
  RestartSec=3

  # Like this:
  [Service]
  ExecStart=/usr/sbin/clamd --foreground=true
  # Reload the database
  ExecReload=/bin/kill -USR2 $MAINPID
  StandardOutput=syslog
  Restart=always
  RestartSec=3

  # Save and close the file. Then reload systemd and restart clamav-daemon.service.
  systemctl daemon-reload
  systemctl restart clamav-daemon
}


# Same as above but done by copying already edited file
# NOTE: take care that /etc/systemd/system/clamav-daemon.service differs from
# original: /lib/systemd/system/clamav-daemon.service only with above two lines
cp "${LOCATION_OF_MY_FILES}/%etc%systemd%system%clamav-daemon.service" /etc/systemd/system/clamav-daemon.service
systemctl daemon-reload
systemctl restart clamav-daemon


### Use A Dedicated Port for Email Submissions
# NOTE: Custom settings should be added between the use strict; and 1; line.

replace_with_my_file "/etc/amavis/conf.d/50-user"
systemctl restart amavis

# If you have OpenDKIM running on your mail server, then you can disable DKIM verification in Amavis.
replace_with_my_file "/etc/amavis/conf.d/21-ubuntu_defaults"
systemctl restart amavis


### Improve amavis performance

# After running you should see that there are 4 Amavis processes
#amavisd-nanny #already done in main.cf and master.cf

################################################################################
# 12.
################################################################################

cp "${LOCATION_OF_MY_FILES}/%etc%postfix%postscreen_access.cidr" /etc/postfix/postscreen_access.cidr
#cp /etc/postfix/postscreen_access.cidr
systemctl restart postfix

# Note: Postscreen listens on port 25 only, 
# so authenticated users from port 587 or 465 won’t be affected by Postscreen.

### Step 2: Pregreet Test
# 
# There is a pregreet test in Postscreen to detect spam. 
# As you may already know, in SMTP protocol, the receiving SMTP server should always
# declare its hostname before the sending SMTP server does so. 
# Some spammers violate this rule and declare their hostnames before the receiving SMTP server does.


# The sender will try the first mail server (with priority 0). 
# If mail.yourdomain.com rejects email by greylisting, 
# then the sender would immediately try the second mail server (with priority 5).
# Instead of waiting to retry to same mx record (if would be only one)


## Using Postwhite
cd /usr/local/bin/
apt-get install -y git
# Clone the SPF-Tools and Postwhite Github repository.
git clone https://github.com/spf-tools/spf-tools.git
git clone https://github.com/stevejenkins/postwhite.git

# Copy the postwhite.conf file to /etc/.
cp /usr/local/bin/postwhite/postwhite.conf /etc/

# Run Postwhite.
/usr/local/bin/postwhite/postwhite
# The whitelist will be save as /etc/postfix/postscreen_spf_whitelist.cidr.



################################################################################
# SETTING UP LOCAL DNS RESOLVER
################################################################################

# Returns 0 if service is active and non 0 if not
function is_service_running() {
  systemctl is-active --quiet "$@"
}

### Install Unbound DNS Resolver on Ubuntu 20.04
apt-get update -y
apt-get install -y unbound

# If it’s not running, then start it with:
systemctl start unbound
# And enable auto-start at boot time:
systemctl enable unbound


# If you installed BIND9 resolver before, 
# then you need to run the following command to stop and disable it, 
# so Unbound can listen to the UDP port 53. 
# By default, Unbound listens on 127.0.0.1:53 and [::1]:53
systemctl disable named --now

replace_with_my_file "/etc/unbound/unbound.conf"

# By default, Ubuntu runs the systemd-resolved stub resolver which listens on 127.0.0.53:53. 
# You need to stop it, so unbound can bind to 0.0.0.0:53.
systemctl disable systemd-resolved --now

systemctl restart unbound

# If you have UFW firewall running on the Unbound server, 
# then you need to open port 53 to allow LAN clients to send DNS queries.

# This will open TCP and UDP port 53 to the private network (if you have VPN setup) 10.0.0.0/8.
#ufw allow in from 10.0.0.0/8 to any port 53


### Setting the Default DNS Resolver on Ubuntu 20.04 Server

# We need to make Ubuntu 20.04 server use 127.0.0.1 as DNS resolver, 
# so unbound will answer DNS queries. The unbound package on Ubuntu ships with
# a systemd service unbound-resolvconf.service that is supposed to 
# help us accomplish this. However, I found it won’t work.
#
# Instead, create a custom unbound-resolvconf.service
cp "${LOCATION_OF_MY_FILES}/%etc%systemd%system%unbound-resolvconf.service" /etc/systemd/system/unbound-resolvconf.service
#cp /etc/systemd/system/unbound-resolvconf.service


# Reload systemd
systemctl daemon-reload
# Make sure your system has the resolvconf binary.
apt-get install -y openresolv
# Next, restart this service.
systemctl restart unbound-resolvconf.service


if is_service_running "unbound"; then
  if grep -q 'nameserver 127.0.0.1' /etc/resolv.conf; then
    echo 'success setting up unbound as local DNS resolver'
  else
    echo 'fail setting up unbound as local DNS resolver'
    return 1
  fi
else 
  echo '[error]: unbound not running'
  return 1
fi

apt-get install -y dnsutils


# cp /etc/mailname [mailname example: example.com (so what is after @ in email)]
echo "$POSTFIX_mailname" > /etc/mailname # Equivalent of replacing: /etc/mailname


systemctl daemon-reload
systemctl enable opendkim postfix dovecot policyd-rate-limit spamass-milter spamassassin amavis clamav-freshclam clamav-daemon unbound unbound-resolvconf # | less
systemctl restart opendkim postfix dovecot policyd-rate-limit spamass-milter spamassassin amavis clamav-freshclam clamav-daemon unbound unbound-resolvconf


# Restart all services and check their status to verify if everything is correct
press_anything_to_continue "
Now services and their status will be displayed.
Press any key to check them manually (by scrolling).
(Press 'q' as you finish checking)

--> In short from now click:
1x (Enter)
Check if all services are 'running'
q - when finished
"
systemctl status opendkim postfix dovecot policyd-rate-limit spamass-milter spamassassin amavis clamav-freshclam clamav-daemon unbound unbound-resolvconf # | less

setup_roundcube_webmail

################################################################################
################## ADDITIONAL FILES THAT SHOULD BE COPIED ######################
################################################################################


cp "${LOCATION_OF_MY_FILES}/%etc%postgrey%whitelist_clients" "/etc/postgrey/whitelist_clients"
# This file exists
# -rw-r--r-- 1 root root
chmod 644 /etc/postgrey/whitelist_clients && chown root:root /etc/postgrey/whitelist_clients


cp "${LOCATION_OF_MY_FILES}/%etc%default%postgrey" "/etc/default/postgrey"
# exists too
# -rw-r--r-- 1 root root
chmod 644 /etc/default/postgrey && chown root:root /etc/default/postgrey


cp "${LOCATION_OF_MY_FILES}/%etc%fail2ban%jail.local" "/etc/fail2ban/jail.local"
# -rw-r--r--   1 root root as all files in /etc/fail2ban/
chmod 644 /etc/fail2ban/jail.local && chown root:root /etc/fail2ban/jail.local


cp "${LOCATION_OF_MY_FILES}/%etc%fail2ban%filter.d%postfix-flood-attack.conf" "/etc/fail2ban/filter.d/postfix-flood-attack.conf"
# doesnt exists
# -rw-r--r--   1 root root as all files in /etc/fail2ban/filter.d/
chmod 644 /etc/fail2ban/filter.d/postfix-flood-attack.conf && chown root:root /etc/fail2ban/filter.d/postfix-flood-attack.conf


cp "${LOCATION_OF_MY_FILES}/%var%spool%cron%crontabs%root" "/var/spool/cron/crontabs/root"
# -rw------- 1 root crontab
chmod 600 "/var/spool/cron/crontabs/root" 
chown root:crontab "/var/spool/cron/crontabs/root"

################## Set some cronjob scripts ##################

# Set correct permissions on all of this
mv "${LOCATION_OF_MY_FILES}/%root%scripts%" /root/scripts
chmod 700 /root/scripts -R

### Reloading cron after changing crontab IS NOT REQUIRED
# https://stackoverflow.com/a/10193931
sudo service cron reload

systemctl enable postgrey fail2ban
systemctl restart postgrey fail2ban

press_anything_to_continue "
Now services and their status will be displayed.
Press any key to check them manually (by scrolling).
(Press 'q' as you finish checking)

--> In short from now click:
1x (Enter)
Check if all services are 'running'
q - when finished
"
systemctl status postgrey fail2ban

# Dovecot Automatic Restart
mkdir -p /etc/systemd/system/dovecot.service.d/
cp "${LOCATION_OF_MY_FILES}/%etc%systemd%system%dovecot.service.d%restart.conf" "/etc/systemd/system/dovecot.service.d/restart.conf"

# Reload systemd
systemctl daemon-reload

cat <<EOF


# NOTE: After you created postfixadmin db virtual mailboxes werent created so 
# you need to run below line manually after you will login to an email for the 1st time:
#
# User specific spamassassin rules and points
cp "${LOCATION_OF_MY_FILES}/%var%vmail%example.com%admin%spamassassin%user_pref" "/var/vmail/example.com/admin/spamassassin/user_pref"
# same with user-specific sieve filters:
%var%vmail%example.com%tim%sieve%roundcube.sieve

# Sample sieve filters for email:
https://docs.gandi.net/en/gandimail/sieve/sample_filters.html
EOF



### Removing Sensitive Information from Email Headers

# By default, Roundcube will add a User-Agent email header, 
# indicating that you are using Roundcube webmail and the version number. 
# You can tell Postfix to ignore it so recipient can not see it.
# 
# this is to file to strip headers: /etc/postfix/smtp_header_checks
# after editing always do: postmap /etc/postfix/smtp_header_checks
# and in main.cf  smtp_header_checks  directive regulates it 
# systemctl reload postfix




################################################################################
# Manage mailboxes for admin@
################################################################################

ADMIN_USER='admin@example.com'
MAILBOXES_TO_CREATE=(
  "postmaster"
  "root"
  "dmarc"
  "cron-root"
  "cron-root.pflogsumm"
)

for mailbox in "${MAILBOXES_TO_CREATE[@]}"; do
  # Create a mailbox (will not yet be visible for email user - need to subscribe)

  doveadm mailbox create -u "$ADMIN_USER" "$mailbox"
  doveadm mailbox subscribe -u "$ADMIN_USER" "$mailbox"
done



### Create sieve structure
USER_ROOT_VMAIL='/var/vmail/example.com/admin'

mkdir "${USER_ROOT_VMAIL}/sieve"
mkdir "${USER_ROOT_VMAIL}/sieve/tmp"


### Sieve very nice examples (if else etc.)
#
# https://doc.dovecot.org/configuration_manual/sieve/examples/


# Create ${USER_ROOT_VMAIL}/sieve/roundcube.sieve
cat <<EOF > "${USER_ROOT_VMAIL}/sieve/roundcube.sieve"
require ["fileinto"];

# rule:[postmaster]
if allof (header :is "to" "postmaster@example.com")
{
  fileinto "postmaster";
}

# rule:[root]
if allof (header :is "to" "root@example.com")
{
  fileinto "root";
}

# rule:[dmarc]
if allof (header :is "to" "dmarc@example.com")
{
  fileinto "dmarc";
}

# rule:[cron-root.pflogsumm]
if allof (header :is "to" "cron-root@example.com", header :contains "subject" "pflogsumm")
{
  fileinto "cron-root.pflogsumm";
  stop;
  # Stop/Skip evaluating following rules
}

# rule:[cron-root]
if allof (header :is "to" "cron-root@example.com")
{
  fileinto "cron-root";
}

EOF



chown vmail:vmail "${USER_ROOT_VMAIL}/sieve" -R
chmod 700 "${USER_ROOT_VMAIL}/sieve" -R

chmod 600 "${USER_ROOT_VMAIL}/sieve/roundcube.sieve"


### Create a symlink sieve
#
ln -s "${USER_ROOT_VMAIL}/sieve/roundcube.sieve" "${USER_ROOT_VMAIL}/.dovecot.sieve"
# if you'd like to change ownership of the link itself, you need to use the -h option to chown:
# -h, --no-dereference affect each symbolic link instead of any referenced file 
# (useful only on systems that can change the ownership of a symlink)
chown -h vmail:vmail "${USER_ROOT_VMAIL}/.dovecot.sieve"


### Pre-compile .sieve filter
#
# We can compile this script, so it will run faster.
sievec "${USER_ROOT_VMAIL}/.dovecot.sieve"
chown vmail:vmail "${USER_ROOT_VMAIL}/.dovecot.svbin"
# Now there is a binary file saved as - ${USER_ROOT_VMAIL}/.dovecot.svbin


##### At the end it should look like:
#
### /
# lrwxrwxrwx  1 vmail vmail   21 Dec 11 12:14 .dovecot.sieve -> sieve/roundcube.sieve
# -rw-------  1 vmail vmail  252 Dec 11 12:59 .dovecot.svbin
# drwx------ 11 vmail vmail 4096 Dec 11 12:13 Maildir/
# drwx------  3 vmail vmail 4096 Dec 11 12:14 sieve/
#
### sieve/
# -rw------- 1 vmail vmail   18 Dec 11 12:14 roundcube.sieve
# drwx------ 2 vmail vmail 4096 Dec 11 12:14 tmp/ (empty)


################################################################################
# Roundcube fail2ban
################################################################################
setup_roundcube_fail2ban

################################################################################
# Removing exim4
################################################################################

# Installing postfix will remove exim since there can't be two mail systems.
# So no need to do it and only remove the exim4 logs directory left behind:
rm -rf /var/log/exim4/


# create simple support page as in: $config['support_url'] in WWW/mail/config/config.inc.php
echo "If you have encountered a problem or have a suggestion, please let me know: <a href='mailto:admin@example.com?subject=I would like to ...&body=I am writing because of ...'>admin@example.com</a>" > "${ROUNDCUBE_ROOT_LOCATION}/help.html"


exit 0


