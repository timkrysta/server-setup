#!/bin/bash

DEBUG='true'

set -euo pipefail

# set -x enables a mode of the shell where all executed commands are printed to the terminal. 
# It's used for debugging, which is a typical use case for set -x: printing every command.
# As it is executed may help you to visualize the control flow of the script if it is not functioning as expected.
# set +x disables it.
[ "$DEBUG" == 'true' ] && set -x


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

function main()
{
  bash ./initial_server_setup.sh

  press_anything_to_continue "
  Finished initial_server_setup.
  Press any key to continue with setting up Web Server
  "

  bash ./web_server_setup.sh

  press_anything_to_continue "
  Finished web_server_setup.
  Press any key to continue with setting up Mail Server
  "

  bash ./mail_server_setup.sh

  apt-get update

  echo ""
  echo "Finished mail_server_setup."
  echo ""
  echo "YOUR SERVER IS READY!"
  echo ""
}


main
