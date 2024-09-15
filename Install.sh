#!/bin/bash
CHROMIA_PAT="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"



# Update and Upgrade the System
echo "Updating and upgrading system..."
sudo apt-get update && apt-get upgrade -y

# Creating a user named Chromia, as to access certain files
USER_NAME="Chromia"
PASSWORD="Password12345:)"
USER_HOME="/home/$USER_NAME"
GROUP_NAME="Chromia_Group"

    echo "Creating user $USER_NAME..."
    sudo groupadd $GROUP_NAME
    sudo useradd -m -g $GROUP_NAME $USER_NAME
    echo $USER_NAME:$PASSWORD | sudo chpasswd
    echo "Allowing $USER_NAME access to /var/log/btmp without sudo..."
    sudo usermod -aG $GROUP_NAME $USER_NAME
    sudo chown root:$GROUP_NAME /var/log/btmp
    sudo chmod 0640 /var/log/btmp



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
