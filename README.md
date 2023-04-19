# Server Setup Scripts

This repository intends to showcase my experience in building automated Bash scripts that set up and configure Linux server.

They cannot be executed because they miss templates of my configuration files `/etc/` that I fetch from other private repository to set them up on a new machine.

After installing Ubuntu on a new machine, all 3 scripts take ~13 min in total to perform the below operations.


## Initial Server Setup
First script you want to run on your fresh machine after installing ubuntu

This script:

- creates Sudo user
- sets up ssh keys for that user
- hardens SSH configuration
- creates separate sntf group and user
- sets up basic firewall rules

## Web Server Setup
This script:

- installs and configures
  - nginx/apache
  - mysql
  - php
  - phpmyadmin

## Mail Server Setup
This script:

- installs
  - pflogsumm
  - spamassasin
  - postfixadmin
  - amavis
- installs and configures
  - postfix
  - dovecot
  - SPF, DKIM
  - clamAV (antivirus)
- creates custom dovecot-sieve filters
- sets up local DNS Resolver
- sets up Roundcube webmail
- sets up Roundcube fail2ban
- sets up SMTP Rate Limiting
