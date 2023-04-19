#!/bin/bash

DEBUG='true'

set -euo pipefail

# set -x enables a mode of the shell where all executed commands are printed to the terminal. 
# It's used for debugging, which is a typical use case for set -x: printing every command.
# As it is executed may help you to visualize the control flow of the script if it is not functioning as expected.
# set +x disables it.
[ "$DEBUG" == 'true' ] && set -x


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


########################
### SCRIPT VARIABLES ###
########################
check_release

SSHD_CONFIG='/etc/ssh/sshd_config'

# Weather script have to prompt for passwords or read them from below variables
INTERACTIVE=false

  # Name of the user to create and grant sudo privileges
  USERNAME_FOR_SUDO_USER='username'
  PASSWORD_FOR_SUDO_USER='password'

  USERNAME_FOR_SFTP_USER='username'
  PASSWORD_FOR_SFTP_USER='password'

TIMEZONE='your/timezone'

# Whether to setup a SSH Banner with a message
SETUP_BANNERS=true

# Whether to copy over the root's 'authorized_keys' file to the new sudo user.
COPY_AUTHORIZED_KEYS_FROM_ROOT=false

# Additional public keys to add to the new sudo user
# OTHER_PUBLIC_KEYS_TO_ADD=(
#   "ssh-rsa AAAAB..."
#   "ssh-rsa AAAAB..."
# )

CUSTOM_SSH_PORT=0 # your custom SSH port eg 9999

PORTS_TO_BE_OPEN=(
  "OpenSSH" # Add exception for SSH default port 22
  "$CUSTOM_SSH_PORT"
  "21" # FTP
)


########################
### HELPER FUNCTIONS ###
########################
function install()
{
  if [ "$RELEASE" = "debian" ]; then
    apt-get install -y "$@"
  else
    yum -y install "$@"
  fi
}

function update_and_upgrade()
{
  if [ "$RELEASE" = "debian" ]; then
    apt-get update -y && apt-get upgrade -y
  else
    yum -y update && yum -y upgrade
  fi
}

function command_exists()
{
  command -v "$@" >/dev/null 2>&1
}

function disable_welcome_message()
{
  # Disable welcome message - https://askubuntu.com/a/676381 
  if [ -d "/etc/update-motd.d" ]; then 
    chmod -x /etc/update-motd.d/* 
    echo "--> disabled welcome msg"
  fi
}

function check_if_running_as_root()
{
  ## The main difference between EUID and UID is:
  # UID  refers to the original user and
  # EUID refers to the user you have changed into.

  # This script have to be run as root!
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
  fi
}

function press_anything_to_continue()
{
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

function script_initialization()
{
  check_if_running_as_root

  # Setup the appropriate timezone
  timedatectl set-timezone "$TIMEZONE"
  
  update_and_upgrade

  install ufw

  disable_welcome_message
}

#######################################
# Checks if script is being run in debug mode
# Globals: 
#   DEBUG
# Returns: 
#   0 if script is being run in debug mode, 1 if not.
#######################################
function is_debug_on()
{
  if [ "$DEBUG" = true ]; then
    return 0
  else
    return 1
  fi
}

#######################################
# Checks if script is being run interactively
# Globals: 
#   INTERACTIVE
# Returns: 
#   0 if script is being run interactively, 1 if not.
#######################################
function running_interactively()
{
  if [ "$INTERACTIVE" = true ]; then
    return 0
  else
    return 1
  fi
}

#######################################
# Setting Up a Basic Firewall.
# Globals: 
#   PORTS_TO_BE_OPEN
#######################################
function setup_basic_firewall()
{
  for port in "${PORTS_TO_BE_OPEN[@]}"; do
    ufw allow "$port"
  done

  # start/enable UFW firewall
  ufw --force enable
}

#######################################
# Replaces in file using regular expression.
# Arguments: 
#   Regex pattern
#   Replacement
#   File to make changes in
#######################################
function replace_regex_in_file()
{
  local PATTERN \
        REPL \
        FILE
  PATTERN="$1"
  REPL="$2"
  FILE="$3"
  #sed --in-place -E "s/${PATTERN}/${REPL}/" "$FILE" # it was macos sed
  sed --in-place "s/${PATTERN}/${REPL}/m" "$FILE"
  # -i == --in-place
}

#######################################
# Backup a file in his location with ".<date>.bak" suffix
# Arguments: 
#   File to make backup for
#######################################
function backup_a_file_with_current_date()
{
  local FILE_PATH \
        DATE
  FILE_PATH="$1"
  DATE="$(date '+%Y-%m-%d')"
  cp "$FILE_PATH" "${FILE_PATH}.${DATE}.bak"
}

#######################################
# Sets password for user without prompting.
# Arguments: 
#   User to setup password for
#   Password
#######################################
function set_password_for_user_non_interactively()
{
  local USER_TO_SETUP_PASSWORD_FOR \
        PASSWORD

  USER_TO_SETUP_PASSWORD_FOR="$1"
  PASSWORD="$2"

  passwd --quiet "$USER_TO_SETUP_PASSWORD_FOR" <<EOF
$PASSWORD
$PASSWORD
EOF
}

#######################################
# Sets password for user with prompt for password.
# Arguments: 
#   User to setup password for
#######################################
function set_password_for_user_interactively() {
  local USER_TO_SETUP_PASSWORD_FOR
  USER_TO_SETUP_PASSWORD_FOR="$1"

  # Set a password for this user
  while true; do
    if passwd "$USER_TO_SETUP_PASSWORD_FOR"; then
      # If above command returns 0 exit code (success) -> break
      break
    fi
  done
}

#######################################
# Create .ssh dir with correct permissions and add SSH keys there
# Globals: 
#   COPY_AUTHORIZED_KEYS_FROM_ROOT
#   OTHER_PUBLIC_KEYS_TO_ADD
# Arguments: 
#   Username to setup ssh keys for
#######################################
function setup_ssh_keys_for_given_user()
{
  local USER
  USER="$1"

  HOME_DIRECTORY="$(eval echo "~${USER}")"

  # Create .ssh directory
  mkdir --parents "${HOME_DIRECTORY}/.ssh"

  # Copy `authorized_keys` file from root if requested
  if [ "${COPY_AUTHORIZED_KEYS_FROM_ROOT}" = true ]; then
    cp /root/.ssh/authorized_keys "${HOME_DIRECTORY}/.ssh"
  fi

  # Add additional provided public keys
  for pub_key in "${OTHER_PUBLIC_KEYS_TO_ADD[@]}"; do
    echo "${pub_key}" >> "${HOME_DIRECTORY}/.ssh/authorized_keys"
  done

  # Adjust SSH configuration ownership and permissions
  chmod 0700 "${HOME_DIRECTORY}/.ssh"
  chmod 0600 "${HOME_DIRECTORY}/.ssh/authorized_keys"
  
  chown --recursive "${USER}":"${USER}" "${HOME_DIRECTORY}/.ssh"
}

#######################################
# Create user with sudo privileges
# Globals: 
#   USERNAME_FOR_SUDO_USER
#   PASSWORD_FOR_SUDO_USER
#######################################
function create_sudo_user()
{
  # -g is for primary group and -G for supplementary group
  useradd --create-home --shell "/bin/bash" -G sudo "$USERNAME_FOR_SUDO_USER"

  if running_interactively; then
    set_password_for_user_interactively "$USERNAME_FOR_SUDO_USER"
  else 
    set_password_for_user_non_interactively "$USERNAME_FOR_SUDO_USER" "$PASSWORD_FOR_SUDO_USER"
  fi
}

#######################################
# Create tightly restricted SFTP-only user with jail and SFTP group
# Globals: 
#   USERNAME_FOR_SFTP_USER
#   PASSWORD_FOR_SFTP_USER
# Outputs: 
#   Output to STDOUT or STDERR.
# Returns: 
#   Returned values other than the default exit status of the last command run.
# Examples:
#   Usage examples
# Notes:
#   Notes.
#######################################
function create_sftp_only_group_and_user()
{
  # Great reference: 
  # https://www.thegeekstuff.com/2012/03/chroot-sftp-setup/

  local SFTP_GROUP_NAME \
        SFTP_USER_TO_CREATE \
        SFTP_DIR \
        SFTP_USER_HOME_DIR

  SFTP_GROUP_NAME='sftpusers'
  SFTP_USER_TO_CREATE="$USERNAME_FOR_SFTP_USER"
  SFTP_DIR='/sftp'
  SFTP_USER_HOME_DIR="${SFTP_DIR}/${SFTP_USER_TO_CREATE}"

  # Create sftp Home Directory
  mkdir "$SFTP_DIR"
  # Now, under /sftp, create the individual directories for the users who are 
  # part of the sftpusers group. i.e the users who will be allowed only 
  # to perform sftp and will be in chroot environment.

  # /sftp/guestuser is equivalent to / for the guestuser. 
  # When guestuser sftp to the system, and performs "cd /", they'll be seeing
  # only the content of the directories under "/sftp/guestuser" 
  # (and not the real / of the system). This is the power of the chroot.
  mkdir "$SFTP_USER_HOME_DIR"
  # /sftp == ChrootDirectory

  # So, under this directory /sftp/guestuser, create any subdirectory that you 
  # like user to see. For example, create a incoming directory where users can sftp their files.
  mkdir "${SFTP_USER_HOME_DIR}/incoming"


  # Create a New Group
  groupadd "$SFTP_GROUP_NAME"

  # Create User
  # make his Home directory as /incoming
  # -g is for primary group and -G for supplementary group

  # --create-home
  useradd  --home-dir "$SFTP_USER_HOME_DIR" -G "$SFTP_GROUP_NAME" --shell "/usr/sbin/nologin" "$SFTP_USER_TO_CREATE"

  if running_interactively; then
    set_password_for_user_interactively "$SFTP_USER_TO_CREATE"
  else 
    set_password_for_user_non_interactively "$SFTP_USER_TO_CREATE" "$PASSWORD_FOR_SFTP_USER"
  fi


  # This in sshd_config will help create a tightly restricted SFTP-only user account
  cat <<EOF >> "$SSHD_CONFIG"
Match Group $SFTP_GROUP_NAME
  ForceCommand internal-sftp
  ChrootDirectory $SFTP_DIR/%u
EOF
# Above 'ChrootDirectory' specifies jail for 'Match'ed


  # Setup Appropriate Permission
  chown "$SFTP_USER_TO_CREATE":"$SFTP_GROUP_NAME" "${SFTP_USER_HOME_DIR}/incoming"


  ### OPTIONALY: you can logicaly separate the dir for IN and OUT files
  mkdir "${SFTP_USER_HOME_DIR}/outgoing"
  chown "$SFTP_USER_TO_CREATE":"$SFTP_GROUP_NAME" "${SFTP_USER_HOME_DIR}/outgoing"

  ### NOTE: Everything at the end should be like this
  # 755 guestuser sftpusers /sftp/guestuser/incoming
  # 755 root root /sftp/guestuser
  # 755 root root /sftp
  
  setup_ssh_keys_for_given_user "$SFTP_USER_TO_CREATE"
}


################################################################################
# SSHD_CONFIG
################################################################################

#######################################
# Wrapper for replace_regex_in_file function
#######################################
function edit_sshd_config()
{
  local PATTERN \
        REPL
  PATTERN="$1"
  REPL="$2"

  # Edit ssh config - $SSHD_CONFIG
  replace_regex_in_file "$1" "$2" "$SSHD_CONFIG"
}

# Create backup of current (old because it will be replaced) $SSHD_CONFIG
function make_backup_of_sshd_config()
{
  backup_a_file_with_current_date "$SSHD_CONFIG"
}

function change_default_ssh_port_for_security_reasons()
{
  # If variable not null change server SSH port
  if [ -n "$CUSTOM_SSH_PORT" ]; then
    # Set non default port
    edit_sshd_config "^Port.*$" "Port ${CUSTOM_SSH_PORT}" # change: 'Port N'
    edit_sshd_config "GatewayPort.*$" "GatewayPort ${CUSTOM_SSH_PORT}" # change: 'GatewayPort N'
  fi
}

function change_some_ssh_directives()
{
  # Read about sshd_config directives:
  # Ref: https://man7.org/linux/man-pages/man5/sshd_config.5.html

  # Ref: https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-18-04

  ### PasswordAuthentication - Disable password authentication for all users
  edit_sshd_config "^#PasswordAuthentication.*$" "PasswordAuthentication no"

  ### PermitEmptyPasswords - 
  # When password authentication is allowed, it specifies whether the server 
  # allows login to accounts with empty password strings. The default is no.
  edit_sshd_config "^#PermitEmptyPasswords.*$" "PermitEmptyPasswords no"

  ### PermitRootLogin
  edit_sshd_config "^PermitRootLogin.*$" "PermitRootLogin no" 
  # alternative: PermitRootLogin without-password or prohibit-password


  ### ClientAliveInterval
  # Set SSH Connection Timeout Idle Value
  edit_sshd_config "^#ClientAliveInterval.*$" "ClientAliveInterval 600"


  ### ClientAliveCountMax
  # Total number of checkalive message sent by the ssh server 
  # without getting any response from the ssh client
  edit_sshd_config "^#ClientAliveCountMax.*$" "ClientAliveCountMax 0"


  ### MaxAuthTries
  # Configure a Limit for Password Attempts
  edit_sshd_config "^#MaxAuthTries.*$" "MaxAuthTries 3"

  ### LoginGraceTime
  # Allow 20 sec to login, if not disconnect
  edit_sshd_config "^#LoginGraceTime.*$" "LoginGraceTime 20"


  ### Protocol 2
  # Use more cryptographicaly secure protocol
  echo "Protocol 2" >> "$SSHD_CONFIG"
  # To test if SSH protocol 1 is supported any more, run the command:
  # ssh -1 user@remote-IP
  #
  # ssh -2 user@remote-IP # for Protocol 2


  ### AllowUsers
  # Limit SSH Access to Certain Users
  #echo "AllowUsers user1 user2" >> "$SSHD_CONFIG" # after space add other users
  # AllowGroups sysadmin dba

  
  # (style): Consider using { cmd1; cmd2; } >> file instead of individual redirects.
  echo "ChallengeResponseAuthentication no" >> "$SSHD_CONFIG"
  echo "KerberosAuthentication no" >> "$SSHD_CONFIG"
  echo "GSSAPIAuthentication no" >> "$SSHD_CONFIG"
  echo "X11Forwarding no" >> "$SSHD_CONFIG"
  echo "PermitUserEnvironment no" >> "$SSHD_CONFIG" # If you add this, comment also 'AcceptEnv'
  edit_sshd_config "^AcceptEnv.*$" "#AcceptEnv LANG LC_*" 
  echo "DebianBanner no" >> "$SSHD_CONFIG"
  

  ### Additional configurations from reference
  # OpenSSH server configuration
  # Ref: https://www.ssh.com/academy/ssh/sshd_config
  #
  # Setting persistent encryption
  echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> "$SSHD_CONFIG"
  echo "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss" >> "$SSHD_CONFIG"
  echo "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256" >> "$SSHD_CONFIG"
  echo "MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1" >> "$SSHD_CONFIG"
  # Managing port tunneling and forwarding
  echo "AllowTcpForwarding no" >> "$SSHD_CONFIG"
  echo "AllowStreamLocalForwarding no" >> "$SSHD_CONFIG"
  echo "AllowAgentForwarding no" >> "$SSHD_CONFIG"
  echo "GatewayPorts no" >> "$SSHD_CONFIG"
  echo "PermitTunnel no" >> "$SSHD_CONFIG"


  # You need to create separate sftp user cuz normal user with my .zshrc and stuff will produce: 
  # Received message too long 1530015802 \n Ensure the remote shell produces no output for non-interactive sessions.
  # Or you set in sshd_config:

  # Subsystem
  # Ref: https://unix.stackexchange.com/a/327284
  edit_sshd_config "^Subsystem.*$" "Subsystem sftp internal-sftp" 

  # Change LogLevel INFO to VERBOSE to have SSH log even attempts
  edit_sshd_config "^#LogLevel.*$" "LogLevel VERBOSE" 

}

# If /etc/ssh/sshd_config is correct restart SSH
function test_and_restart_ssh()
{
  if sshd -t -q; then
    ### Confused about how to restart ssh (ssh or sshd):
    # Ref: https://www.cyberciti.biz/faq/how-do-i-restart-sshd-daemon-on-linux-or-unix/
    # Ref: https://serverfault.com/a/143365
    # Ref: https://askubuntu.com/a/462971
    # Ref: https://askubuntu.com/a/1070148 # THIS IS VERY NICE ONE!
    
    systemctl restart sshd

    ### Yes it is called ssh although the process is called sshd which might be confusing.
    #
    # Does not matter because for example running:
    # 'systemctl status mysql' will run: 'systemctl status mysqld'
    # because it is restarting the service (deamon)
  fi
}

################################################################################
# Legal Notices for Login/MOTD unix banners
# Ref: https://gist.github.com/hvmonteiro/7f897cd8ae3993195855040056f87dc6
################################################################################

#######################################
# Display message BEFORE SSH Login
#######################################
function create_ssh_banner()
{
  local SSH_BANNER
  # Banner directive in: /etc/ssh/sshd_config regulates the path to file
  # that will be printed after trying to SSH to a server
  #
  # The SSH warning messages are commonly located in the files '/etc/issue' and '/etc/issue.net'
  SSH_BANNER='/etc/ssh/sshd-banner'

  echo "Banner $SSH_BANNER" >> /etc/ssh/sshd_config
  test_and_restart_ssh

  cat <<EOF > "$SSH_BANNER"
###############################################################
#                  This is a private server!                  #
#       All connections are monitored and recorded.           #
#  Disconnect IMMEDIATELY if you are not an authorized user!  #
###############################################################
EOF
}

#######################################
# Display message AFTER SSH Login
#######################################
function create_motd()
{
  # The /etc/motd is a file on Unix-like CLI systems that 
  # contains a "message of the day", used to send a common message to all users
  # in a more efficient manner than sending them all an e-mail message.

cat <<EOF > /etc/motd

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.


EOF
}


####################
### SCRIPT LOGIC ###
####################

function main()
{
  echo ""
  echo "1) Initialization"
  echo ""
  script_initialization
  
  echo ""
  echo ""
  echo "--> Creating new user '${USERNAME_FOR_SUDO_USER}' with sudo privileges"
  echo ""
  create_sudo_user

  echo ""
  echo ""
  echo "2) Managing SSH Keys"
  echo ""
  setup_ssh_keys_for_given_user "$USERNAME_FOR_SUDO_USER"

  echo ""
  echo ""
  echo "3) Changing ${SSHD_CONFIG} Directives"
  echo ""
  make_backup_of_sshd_config
  change_default_ssh_port_for_security_reasons
  change_some_ssh_directives

  echo ""
  echo ""
  echo "--> Creating new SFTP-ONLY user restricted to home directory using chroot Jail"
  echo ""
  create_sftp_only_group_and_user
  
  echo ""
  echo ""
  echo "4) Testing ${SSHD_CONFIG} and restarting"
  echo ""
  test_and_restart_ssh

  echo ""
  echo ""
  echo "5) Setting basic firewall rules"
  echo ""
  setup_basic_firewall
  echo ""

  # OPTIONAL
  if [ "${SETUP_BANNERS}" = true ]; then
    create_ssh_banner
    create_motd
  fi
  
  echo "--> DONE!"
}


main
