#!/bin/bash
CHROMIA_PAT="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"



# Update and Upgrade the System
echo "Updating and upgrading system..."
sudo apt-get update && apt-get upgrade -y

# Creating a user named Chromia, as to access certain files
USER_NAME="Chromia"
# PASSWORD="Password12345:)"
USER_HOME="/home/$USER_NAME"
GROUP_NAME="Chromia_Group"

if id "$USER_NAME" &>/dev/null; then
    echo "User $USER_NAME already exists."
else
    echo "Creating user $USER_NAME..."
    sudo useradd -m $USER_NAME
    echo "User $USER_NAME created."
    echo $USER_NAME:$PASSWORD | sudo chpasswd
    sudo chage -d 0 "$USER_NAME"
    echo "User $USER_NAME created and password set."
fi

# Chromia user access to /var/log/btmp as so the user does not need  sudo access to view the logs
echo "Allowing $USER_NAME access to /var/log/btmp without sudo..."
sudo groupadd $GROUP_NAME
sudo usermod -aG $GROUP_NAME $USER_NAME
sudo chown root:$GROUP_NAME /var/log/btmp
sudo chmod 0640 /var/log/btmp
newgrp $GROUP_NAME

#Chaning to the Chromia user
sudo -i -u $USER_NAME


# Install Rust
echo "Installing Rust... But, first we need to install curl"
sudo apt install -y curl build-essential

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
git clone https://erikkvietelaitis:$CHROMIA_PAT@github.com/erikkvietelaitis/COS40005-Intrusion-Detection-System.git -v

#build Chromia
cd $HOME/Downloads/COS40005-Intrusion-Detection-System
cargo build --release

#move Chromia build to /bin
cd $HOME/Downloads/COS40005-Intrusion-Detection-System/target/release
mkdir -p ~/bin
mv Chromia ~/bin/

#run Chromia
#cargo run --release

#remove Chromia files
rm -rf ~/Downloads/COS40005-Intrusion-Detection-System
