#!/bin/bash
CHROMIA_PAT="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"
USER_HOME="/home/$USER_NAME"
CHROMIA_TPM_PAT="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"


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
Authors: Ben, Lachlan, Erik, Sean, Simon and Sam

Chromia is a Host based Intrusion Detection System designed to protect your network from malicious activity.
It provides real-time monitoring and alerts to help you maintain security.

EOF
sleep 2
echo -e "${COLOR_RED} ${TEXT_BOLD} Chromia must be run as sudo, it may not function properly without this!"
echo -e "${COLOR_RESET}"
# Update and Upgrade the System
sleep 5
echo "Enter password to begin, Updating and upgrading system..."
sudo apt-get update && apt-get upgrade -y

# Install Rust
# Check if curl is installed
echo "Checking if curl is installed..."
if ! dpkg -l | grep -q '^ii  curl'; then
    echo "curl is not installed. Installing..."
    sudo apt install -y curl
else
    echo "curl is already installed."
fi

# Check if build-essential is installed
if ! dpkg -l | grep -q '^ii  build-essential'; then
    echo "build-essential is not installed. Installing..."
    sudo apt install -y build-essential
else
    echo "build-essential is already installed."
fi

# Install rustup (Rust's official installer)
if command -v rustc &> /dev/null
then
    echo "Rust is already installed."
else
	echo "Please select 1 as this is the basic install and is what is required for the deployment of this application"
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

	# Set up environment
	source $HOME/.cargo/env

	# Check if Rust is installed correctly
	rustc --version
	cargo --version

	echo "Rust has been installed successfully."
fi

	if command -v b3sum &> /dev/null; then
    	echo "b3sum is already installed. Skipping installation."
	else
    	echo "b3sum is not installed. Installing..."
    	cargo install b3sum
	fi

#Install git 
if command -v git >/dev/null 2>&1; then
    echo "Git is already installed."
else
    # Install Git
    sudo apt install -y git

    # Verify installation
    if command -v git >/dev/null 2>&1; then
        echo "Git has been successfully installed."
    else
        echo "Failed to install Git."
        exit 1
    fi
fi

#git clone Chromia
git clone https://erikkvietelaitis:$CHROMIA_PAT@github.com/erikkvietelaitis/COS40005-Intrusion-Detection-System.git /tmp/Chromia

#build Chromia
cd /tmp/Chromia
cargo build --release

#move Chromia build to /bin
cd /tmp/Chromia/target/release
sudo mkdir -p /bin/Chromia
sudo mv Chromia /bin/Chromia

#remove Chromia files
rm -rf /tmp/Chromia



#Copy B3sum to /bin
sudo mkdir -p /bin/Chromia/Data
sudo cp ~/.cargo/bin/b3sum /bin/Chromia/Data

# Git clone CTPB IDS
#git clone https://brokenpip:$CHROMIA_TPM_PAT@github.com/brokenpip/ctpb_ids.git /tmp/ChromiaTPM

# Build CTPB IDS
cd /tmp/ChromiaTPM
cargo build --release

# Move CTPB IDS build to /bin
cd /tmp/ChromiaTPM/target/release
sudo mv ctpb_tpm /bin/Chromia

#remove CTPB IDS files
#rm -rf /tmp/Tpm

#run Chromia
sleep 5
echo "Chromia has been installed successfully."
echo "Chromia is installed in /bin/Chromia"
cd /bin/Chromia
sleep 5
sudo ./Chromia #sudo is required to run the program due to wanting the files to be in /bin

