#!/bin/bash


DEBUG='true'

set -euo pipefail

# set -x enables a mode of the shell where all executed commands are printed to the terminal. 
# It's used for debugging, which is a typical use case for set -x: printing every command.
# As it is executed may help you to visualize the control flow of the script if it is not functioning as expected.
# set +x disables it.
[ "$DEBUG" == 'true' ] && set -x


########################
### SCRIPT VARIABLES ###
########################

LOG_FILE="/root/install_web_stack.log"
STACK='LEMP' # LAMP (apache) or LEMP (nginx) regex L(A|E)MP STACK
# Primary domain (without http(s) scheme) name to create a directory structure
PRIMARY_DOMAIN='example.com'
EMAIL=''
# Name of the user to grant privileges and ownership
USERNAME=''
TEMPLATES_DIR='/root/server-setup/web-server-setup/templates'
SQL_USERNAME=''
SQL_PASSWORD=''
GITHUB_USERNAME=''
GITHUB_PASSWORD=''
WWW_ROOT='/var/www/example.com'
WWW_PROD_ROOT="${WWW_ROOT}/prod"
WWW_MAINT_ROOT="${WWW_ROOT}/maint"

################################################################################
########################### HELPER FUNCTIONS ###################################
################################################################################

function command_exists() {
  command -v "$@" >/dev/null 2>&1
}

function apt_install() {
  sudo apt-get install -y "$@"
}

function update_and_upgrade() {
  sudo apt-get update -y && sudo apt-get upgrade -y
}

function mkdir_if_not_exists() {
  local DIRECTORY
  DIRECTORY="$1"
  if [[ ! -d "$DIRECTORY" ]]; then
    mkdir "$DIRECTORY"
  fi
}

#######################################
# Checks if script is being run interactively
# Globals: 
#   INTERACTIVE
# Returns: 
#   0 if script is being run interactively, 1 if not.
#######################################
function running_interactively() {
  if [ "$INTERACTIVE" = true ]; then
    return 0
  else
    return 1
  fi
}

function check_if_running_as_root() {
  ## The main difference between EUID and UID is:
  # UID  refers to the original user and
  # EUID refers to the user you have changed into.

  # This script have to be run as root!
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
  fi
}

# Check release (what OS is installed)
function check_release() {
  if [ -f /etc/redhat-release ]; then
      RELEASE="centos"
  elif grep -Eqi "debian" /etc/issue; then
      RELEASE="debian"
  elif grep -Eqi "ubuntu" /etc/issue; then
      RELEASE="ubuntu"
  elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
      RELEASE="centos"
  elif grep -Eqi "debian" /proc/version; then
      RELEASE="debian"
  elif grep -Eqi "ubuntu" /proc/version; then
      RELEASE="ubuntu"
  elif grep -Eqi "centos|red hat|redhat" /proc/version; then
      RELEASE="centos"
  fi

  # Set what the os is based on
  if [ "$RELEASE" = "centos" ]; then
    RELEASE="redhat" # based
  else
    RELEASE="debian"
  fi
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

function create_dir_if_not_exists() {
  if [[ ! -d "$1" ]]; then 
    mkdir -p "$1"
  fi    
}

function restart_nginx_if_config_successful() {
  echo "Testing nginx configuration for syntax errors..."
  if nginx -t; then
    # 2> "$LOG_FILE"
    # If everything is correct restart Nginx
    systemctl restart nginx
  fi
}

function create_subdomain_specific_web_log_files() {
  local LOG_FILE_PATH
  LOG_FILE_PATH="$1"

  touch "$LOG_FILE_PATH"
  chmod 640 "$LOG_FILE_PATH"
  chown "www-data":"adm" "$LOG_FILE_PATH"
}


# Works but below line returns warning:
# apt list --installed | grep [...]
# WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
function apt_purge_all_packages_containing() {
  local KEYWORD_PACKAGE \
        TEMP_FILE

  KEYWORD_PACKAGE="$1"
  TEMP_FILE="$(mktemp)"

  # Get list of all packages containing keyword and purge it
  # It will return non-zero exit code if no such packages found so handle it
  if apt list --installed | grep -i "$KEYWORD_PACKAGE" > "$TEMP_FILE"; then

    while read line; do
      arrIN=(${line/\// }) # // means global replace
      apt-get purge -y "${arrIN[0]}"
      #echo "${arrIN[0]}"
    done < "$TEMP_FILE"

    rm "$TEMP_FILE"

    # Get rid of other dependencies of unexisting packages
    apt-get autoremove -y

    return 0
  else
    # If there is no packages handle non-zero exit code
    rm "$TEMP_FILE"
    return 0
  fi
  
}


function remove_all_directories_from_whereis_containing() {
  local KEYWORD_PACKAGE \
        TEMP_FILE

  KEYWORD_PACKAGE="$1"
  TEMP_FILE="$(mktemp)"

  # example output of 'whereis apache2': 
  # apache2: /usr/sbin/apache2 /usr/lib/apache2 /etc/apache2 /usr/share/apache2 /usr/share/man/man8/apache2.8.gz
  # cut -b 10- is to strip "apache2: " part
  whereis "$KEYWORD_PACKAGE" | cut -b 10- | sed 's/ /\n/g' > "$TEMP_FILE"

  while read line; do
    rm -rf "$line"
    #echo "$line"
  done < "$TEMP_FILE"

  rm "$TEMP_FILE"

}

function remove_apache_debian() {
  systemctl disable apache2 && systemctl stop apache2

  apt_purge_all_packages_containing "apache2"
  remove_all_directories_from_whereis_containing "apache2"
}

function remove_apache_centos() {
  # On RHEL/CentOS/Oracle/Fedora Linux.
  systemctl disable httpd && systemctl stop httpd

  # Remove the installed httpd packages
  yum remove "httpd*" -y
  # Remove the Document root directory
  #rm -rf /var/www
  # Remove the Configuration Files
  rm -rf /etc/httpd
  # Remove the Supporing files and httpd modules
  rm -rf /usr/lib64/httpd
  # delete the Apache user
  userdel -r apache
}

function install_mysql() {
  apt_install mariadb-server mariadb-client

  ### Below will: 
  # 1. ask for 'VALIDATE PASSWORD PLUGIN'
  # 2. prompt for password 
  # 3. prompt for password (confirmation)
  # 4. remove some anonymous users,
  # 5. remove the test database,
  # 6. disable remote root logins, and
  # 7. load these new rules so that MySQL immediately respects the changes you have made.

  press_anything_to_continue "
Now mysql_secure_installation will be performed.
(Enter) Press any key to continue. 
After that answear with:

--> In short from now click:
3x (Enter)
2x Type new root MySQL password
4x (Enter)
"
  mysql_secure_installation
}


function replace_php_ini() {
  # Make backup of old and replace php.ini

  phpini_main_fpm_config_file_path='/etc/php/7.4/fpm/php.ini'
  date="$(date '+%Y-%m-%d')"
  # Create backup or old php.ini
  mv "$phpini_main_fpm_config_file_path" "${phpini_main_fpm_config_file_path}.${date}.bak"
  # Move new php.ini to the place of old one
  cp "${TEMPLATES_DIR}/php.ini" "$phpini_main_fpm_config_file_path"


  # error_log directive in php.ini
  touch /var/log/php_errors.log
  # The file should be writable by the web server's user (www-data).
  # correct permissions for logfles based on permissions of /var/log/nginx/access.log
  # -rw-r-----   www-data adm
  chown www-data:adm /var/log/php_errors.log
  chmod 640 /var/log/php_errors.log
  # or
  #chown root:www-data /var/log/php_errors.log
  #chmod 660 /var/log/php_errors.log


  # upload_tmp_dir directive in php.ini
  rm -rf /var/lib/php/tmp_upload
  mkdir /var/lib/php/tmp_upload

  # session.save_path directive in php.ini
  rm -rf /var/lib/php/session
  mkdir /var/lib/php/session

  # Set correct permissons should 
  # drwx-wx-wt ( => 1733 ) root root​
  chmod 1733 /var/lib/php/tmp_upload
  chmod 1733 /var/lib/php/session

  systemctl restart php7.4-fpm
  systemctl enable php7.4-fpm
}


function install_php() {
  # Installing PHP
  #
  # While Apache embeds the PHP interpreter in each request, 
  # Nginx requires an external program to handle PHP processing and act
  # as a bridge between the PHP interpreter itself and the web server. 
  # This allows for a better overall performance in most PHP-based websites, 
  # but it requires additional configuration. 
  #
  # You'll need to install php-fpm, which stands for "PHP fastCGI process manager",
  # and tell Nginx to pass PHP requests to this software for processing. 
  # Additionally, you'll need php-mysql, a PHP module that allows PHP
  # to communicate with MySQL-based databases
  
  if [ "$STACK" = 'LEMP' ]; then
    # nginx
    #apt_install php-fpm php-mysql # original
    apt_install php-fpm
  else
    # apache
    #apt_install php libapache2-mod-php php-mysql # original
    apt_install php libapache2-mod-php
  fi

  apt_install php-mysql
  
  # Make backup of old and replace with php.ini from my templates fils
  replace_php_ini
}


######################################
# Glabals: 
#   PRIMARY_DOMAIN
#   EMAIL
######################################
function setup_ssl() {
  local CERT_NAME
  CERT_NAME="$PRIMARY_DOMAIN"

  apt_install certbot python3-certbot-nginx

  certbot --nginx --non-interactive --agree-tos \
    --cert-name "$CERT_NAME" \
    --no-eff-email -m "$EMAIL" \
    -d "${PRIMARY_DOMAIN}" \
    -d "www.${PRIMARY_DOMAIN}" \

  # --hsts: (already added by me in nginx conf)        Add the Strict-Transport-Security header to every HTTP response. Forcing browser to always use TLS for the domain. Defends against SSL/TLS Stripping.
  # --staple-ocsp: Enables OCSP Stapling. A valid OCSP response is stapled to the certificate that the server offers during TLS.
}


function script_initialization() {
  check_if_running_as_root
  update_and_upgrade
}

#######################################
# Remove apache web server and all its files.
# Globals: 
#   RELEASE
#######################################
function remove_apache() {
  check_release

  ### Stop, remove apache2 and all dependencies
  if [[ "$RELEASE" == "redhat" ]]; then
    # On RHEL/CentOS/Oracle/Fedora Linux.
    remove_apache_centos
  else
    # On Debian/Ubuntu
    remove_apache_debian
  fi
}


#######################################
# Globals: 
#   WWW_PROD_ROOT
#######################################
function setup_phpmyadmin() {
  local PHPMYADMIN_ROOT_LOCATION

  ### Changing phpMyAdmin's Default Location
  #
  # One way to protect your phpMyAdmin installation is by making it harder to find. 
  # Bots will scan for common paths, like /phpmyadmin, /pma, /admin, /mysql, and other similar names. 
  # Changing the interface's URL from /phpmyadmin to something non-standard will 
  # make it much harder for automated scripts to find your phpMyAdmin installation
  # and attempt brute-force attacks.
  PHPMYADMIN_ROOT_LOCATION="${WWW_PROD_ROOT}/phpmyadmin-obfuscated-path"

  update_and_upgrade

  press_anything_to_continue "
Installing phpMyAdmin...
(Enter) Press any key to continue and later answear:

1. During the installation process, you will be prompted to choose a web server
   (either Apache or Lighttpd) to configure.
   However, because you are using Nginx as a web server you shouldn't choose either of these options. 
--> Instead press 'TAB' to highlight the '<Ok>' and then press 'ENTER' to continue the installation process.

2. Next, you'll be prompted whether to use dbconfig-common for configuring the application database. 
--> Select <Yes>.
   This will set up the internal database and administrative user for phpMyAdmin. 
   You will be asked to define a new password for the phpmyadmin MySQL user, 
   but because this isn't a password you need to remember you can leave it blank and let phpMyAdmin randomly create a password.
--> (Enter)


--> In short from now click:
4x (Enter)
"

  apt_install phpmyadmin

  # Create a symbolic link from the installation files to Nginx's document root directory
  ln -s /usr/share/phpmyadmin "$PHPMYADMIN_ROOT_LOCATION"


  # Disabling Root Login
  #
  # Because you selected dbconfig-common to configure and store phpMyAdmin settings, 
  # the application's default configuration is currently stored within your MySQL database. 
  # You'll need to create a new config.inc.php file in phpMyAdmin's configuration directory
  # to define your custom settings. Even though phpMyAdmin's PHP scripts are located
  # inside the /usr/share/phpmyadmin directory, the application's 
  # configuration files are located in /etc/phpmyadmin.

  # Create a new custom settings file inside the /etc/phpmyadmin/conf.d directory and name it pma_secure.php:
  cp "${TEMPLATES_DIR}/pma_secure.php" /etc/phpmyadmin/conf.d/pma_secure.php

  # Note: If the passphrase you enter here is shorter than 32 characters in length, 
  # it will result in the encrypted cookies being less secure. 
  # Entering a string longer than 32 characters, though, won't cause any harm.

  # To generate a truly random string of characters, use pwgen
  apt_install pwgen

  # By default, pwgen creates easily pronounceable, though less secure, passwords. 
  # However, by including the -s flag, as in the following command, 
  # you can create a completely random, difficult-to-memorize password.
  random_string="$(pwgen -s 32 1)"

  # Replace
  sed -i "s/CHANGE_THIS_TO_A_STRING_OF_32_RANDOM_CHARACTERS/${random_string}/" /etc/phpmyadmin/conf.d/pma_secure.php 



  echo ""
  echo "Now you can visit and login with your regular MySQL credentials"
  echo "https://${PRIMARY_DOMAIN}/phpmyadmin-obfuscated-path"
  echo ""


  restart_nginx_if_config_successful


  ### TODO To add additional phpMyAdmin security: Set Up Access via Encrypted Tunnels
  # https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-phpmyadmin-with-nginx-on-an-ubuntu-20-04-server#step-5-—-setting-up-access-via-encrypted-tunnels
}

function create_auth_gateway() {
  # CONTENTS OF THIS FUNCTION ARE HIDDEN
}

function handle_sites_available_nginx() {
  rm -r /etc/nginx/sites-available
  mkdir -p /etc/nginx/sites-available/example.com
  #cp -r "${TEMPLATES_DIR}/nginx/sites-available/example.com" "/etc/nginx/sites-available"
  for f in "$TEMPLATES_DIR"/nginx/sites-available/example.com/* ; do 
    cp "$f" /etc/nginx/sites-available/example.com
  done
}

function handle_sites_enabled_nginx() {
  for f in /etc/nginx/sites-available/example.com/* ; do 
    ln -s "$f" /etc/nginx/sites-enabled/
  done
}

#######################################
# Globals: 
#   WWW_ROOT
#   WWW_PROD_ROOT
#   WWW_MAINT_ROOT
#######################################
function create_web_root_dirs_for_subdomains() {
  # CONTENTS OF THIS FUNCTION ARE HIDDEN
}


function create_subdomain_specific_log_files() {
  # CONTENTS OF THIS FUNCTION ARE HIDDEN
}


function handle_nginx_conf_and_webroot_v2() {
  unlink /etc/nginx/sites-enabled/default

  # Replace main nginx.conf with custom one  
  rm /etc/nginx/nginx.conf
  cp "${TEMPLATES_DIR}/nginx/nginx.conf" /etc/nginx/nginx.conf

  ### Creating an Authentication Gateway
  create_auth_gateway

  handle_sites_available_nginx

  # Make symlinks
  handle_sites_enabled_nginx

  ## Create web root dirs
  create_web_root_dirs_for_subdomains

  for f in "$TEMPLATES_DIR"/nginx/snippets/* ; do 
    cp "$f" /etc/nginx/snippets/
  done
  
  ### Create subdomain specific nginx log files
  create_subdomain_specific_log_files

  setup_ssl >> $LOG_FILE
    
  restart_nginx_if_config_successful
}

#######################################
# Install the whole LEMP Stack (nginx, mysql, php).
# Globals: 
#   PRIMARY_DOMAIN
#   EMAIL
#######################################
function install_LEMP() {
  # Installing the Nginx Web Server
  apt_install nginx

  # Install mysql
  if command_exists mysql; then
    :
  else
    install_mysql
  fi

  install_php

  handle_nginx_conf_and_webroot_v2
}


#######################################
# Create main SQL user with all permissions
# Globals: 
#   SQL_USERNAME
#   SQL_PASSWORD
#######################################
function create_main_sql_user() {
  mysql -u root -e "CREATE USER \"$SQL_USERNAME\"@'localhost' IDENTIFIED BY \"$SQL_PASSWORD\";"
  mysql -u root -e "GRANT ALL PRIVILEGES ON * . * TO \"$SQL_USERNAME\"@'localhost' WITH GRANT OPTION;"
  # For changes to take effect immediately flush these privileges by typing:
  mysql -u root -e "FLUSH PRIVILEGES;"
  # Once that is done, your new user account has the same access to the database as the root user.
}


################################################################################
# FOR FURTHER DEVELOPING THE SCRIPT
################################################################################

### Apache
# Ref: https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu-20-04
function install_LAMP() {
  apt_install apache2
  ufw allow 'Apache Full'
  # 'Apache'
  # 'Apache Secure'

  install_mysql
  install_php
  # Creating a Virtual Host for your Website
  # virtual hosts (similar to server blocks in Nginx) 
}

################################################################################
#################### SCRIPT LOGIC ##############################################
################################################################################

# In case of problems with lock file:
# | sudo kill -9 <process_id>
# | sudo killall apt apt-get

function main() {
  # Redirect stdout and stderr to terminal and file
  script_initialization |& tee -a "$LOG_FILE"
  remove_apache |& tee -a "$LOG_FILE"

  # Note that with webuzo is some apps installed
  if [ "$STACK" = 'LEMP' ]; then
    install_LEMP
  else
    install_LAMP
  fi

  setup_phpmyadmin

  create_main_sql_user
}

main
exit 0