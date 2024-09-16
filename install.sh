	#!/bin/bash
CHROMIA_PAT="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"
USER_HOME="/home/$USER_NAME"
# Define color codes
#!/bin/bash

# Define color codes
COLOR_RESET="\033[0m"
COLOR_BLUE="\033[34m"
COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_RED="\033[31m"
TEXT_BOLD="\033[1m"
# Clear the terminal
clear

# Display ASCII art for Chromia with each line in a different color
echo -e "${COLOR_BLUE}"
echo -e " _______           _______  _______  _______ _________ _______ 
(  ____ \|\     /|(  ____ )(  ___  )(       )\__   __/(  ___  ) ${COLOR_GREEN}"

echo -e "| (    \/| )   ( || (    )|| (   ) || () () |   ) (   | (   ) |
| |      | (___) || (____)|| |   | || || || |   | |   | (___) |${COLOR_CYAN}"

echo -e "| |      |  ___  ||     __)| |   | || |(_)| |   | |   |  ___  |
| |      | (   ) || (\ (   | |   | || |   | |   | |   | (   ) |    ${COLOR_RED}"

echo "| (____/\| )   ( || ) \ \__| (___) || )   ( |___) (___| )   ( |
(_______/|/     \||/   \__/(_______)|/     \|\_______/|/     \|"

echo -e "${COLOR_GREEN}"

cat << EOF

Chromia IDS Software
Version: 1.0.0
Authors: Jane Doe, John Smith

Chromia is an Intrusion Detection System designed to protect your network from malicious activity.
It provides real-time monitoring and alerts to help you maintain security.

EOF
echo -e "${COLOR_RED} ${TEXT_BOLD} Chromia must be run as sudo, it may not function properly without this!"
echo -e "${COLOR_RESET}"
# Update and Upgrade the System
echo "Updating and upgrading system..."
sudo apt-get update && apt-get upgrade -y

# Install Rust
echo "Installing Rust... But, first we need to install curl"
sudo  apt install -y curl build-essential

# Install rustup (Rust's official installer)
echo "Please select 1 as this is the basic install and is what is required for the deployment of this application"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Set up environment
source $HOME/.cargo/env

# Check if Rust is installed correctly
rustc --version
cargo --version

echo "Rust has been installed successfully."

#Cargo install B3Sum
echo "Installing B3Sum..."
cargo install b3sum

#Install git 
echo "Installing git..."
sudo apt install -y git

#git clone Chromia
git clone https://erikkvietelaitis:$CHROMIA_PAT@github.com/erikkvietelaitis/COS40005-Intrusion-Detection-System.git

#build Chromia
cd ./COS40005-Intrusion-Detection-System
cargo build --release

#move Chromia build to /bin
cd ./target/release
mkdir -p ~/bin
mv Chromia ~/bin/

#remove Chromia files
ls
cd ../../../
ls
rm -rf ./COS40005-Intrusion-Detection-System

#run Chromia
cd ~/bin
./Chromia

