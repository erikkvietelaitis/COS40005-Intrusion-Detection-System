# COS40005-Intrusion-Detection-System

<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->

<a name="readme-top"></a>

<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/github_username/repo_name">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Chromia Host-based IDS</h3>

  <p align="center">
    A host-based intrusion detection system that can detect, monitor and alert on malicious activity or attacks on a linux-based webserver.
    <br />
    <a href="https://github.com/github_username/repo_name"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/github_username/repo_name">View Demo</a>
    ·
    <a href="https://github.com/github_username/repo_name/issues">Report Bug</a>
    ·
    <a href="https://github.com/github_username/repo_name/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

Students where asked by BadSecurity Inc to develop a Host-based Intrustion Detection System. We where tasked to do the required reasurch and determine the best means of development.
Chromia was created by student attending at Swinburne University as part of their final year project:
Students include:
<br>
[![GitHub username](https://img.shields.io/badge/GitHub-Ben-blue?style=for-the-badge&logo=github)](https://github.com/brokenpip)
[![GitHub username](https://img.shields.io/badge/GitHub-Lachlan-blue?style=for-the-badge&logo=github)](https://github.com/DoctorLock)
[![GitHub username](https://img.shields.io/badge/GitHub-Erik-blue?style=for-the-badge&logo=github)](https://github.com/erikkvietelaitis)
[![GitHub username](https://img.shields.io/badge/GitHub-Sam-blue?style=for-the-badge&logo=github)](https://github.com/samsharma12)
[![GitHub username](https://img.shields.io/badge/GitHub-Simon-blue?style=for-the-badge&logo=github)](https://github.com/SimonPH2)
[![GitHub username](https://img.shields.io/badge/GitHub-Sean-blue?style=for-the-badge&logo=github)](https://github.com/stackingheaps)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

- [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
- [![Shell](https://img.shields.io/badge/shell-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

Chromia has a limited install distribution[^1] and has had limited testing, please submit report bugs related to the Github Repo for further assessment, but at this time development has no plans for expanding to other distros.

### Prerequisites

Users that want to try Chromia Host-based IDS will have to download via GitHub the install.sh script. This script will work to install all required dependences as well as create the required software.
This can be completed via downlaoding the script via:
Chromia will install 3rd party depndecies as part of the install process as so it can function this can include:

- git
- net-tools
- curl
- rust
- rust packages
- B3Sum

The install script will also have to create directories and service files for installation[^2]. as to ensure that the service runs to the best that we can provide.
<br>
<a href="https://raw.githubusercontent.com/erikkvietelaitis/COS40005-Intrusion-Detection-System/readme/install.sh" download="install.sh">
<img src="https://img.shields.io/badge/Download%20Install%20Script-blue?style=for-the-badge" alt="Download Install Script">
</a>
<br>
This will open a "raw" view of the install.sh script allowing you to audit it.
Once happy right click on the raw install.sh code and Save As.
Save the install.sh in any directory. We recommend the Downloads directory.

### Installation

Once the install script is saved and downloaded, in to the directory (Downloads)
Installation can be completed via changing to the directory where the install.sh script was saved to and then running in the terminal:

```
chmod +x install.sh   #Making the script exacutable
sudo ./install.sh     #Installing the excutable script
```

In the installation process you maybe asked to install rust we recommend to selcet option 1 as this is the simplest install path that is known not to break the rust install process

You maybe prompted in the install process to enter your password, this is to build, start, and reload the systemd services[^2]. This prompt will occur 4 to 5 times and is normal and expected. If you dont enter your passowrd it could cause the system to not install properly or have complications in the installation process.

#### AFTER INSTALLATION: IT IS IMPORTANT TO REFER TO THE CONFIG.INI FILE[^3]

Please refer to

```
/etc/config.ini
```

The config.ini has all relevent settings options for the function of Chromia

#### Logs and Understaing the Logs

The log file will be located at

```
/var/log/Chromia.log
```

This is the location of the outputed logs of the Chromia Host Based IDS. All the logs are collated together in to a single .log file.

```
[2024-09-29 13:46:25]=[Networking]=[Serious]:Alert: Expected blocked port 631 is open.
```

Fig 1: Example of a Network related concern

```
CPU usage is high: 3.30% (20% above average of 0.77%). Run 'top' command to identify resource-intensive processes'.
```

Fig 2: Example of a general Anomaly related concern

```
Permission change on non-protected file: /home/user/Desktop/RENAME/RENAME/test.txt (old: 100664, new: 100777) by user user. Run 'ls -l /home/user/Desktop/RENAME/RENAME/test.txt' to view current permissions.
```
Fig 3: A File persmission change 

```
Suspicious command executed by user on :    pts/4    telnet example.com
```
Fig 4: A Suspicious command
<br>
These examples provided, demonstrate what the log file printout should look like.


### Troubleshooting

1. We recommend saving the install.sh to the Downloads file.
2. If having commplications we suggest to run the install.sh as root, as suggested in the installion heading.
3. Install, all the required dependences separately, as the install script should, skip currently installed versions

- git
- net-tools
- curl
- rust
- rust packages
- B3Sum

4. Its possible, but unlikely the Github weblinks have changed and you may need to pull, Chromia Host IDS and the TPM models this can be done via clicking the green code button and coping the HTTPS link,
   this will mean you are going to have to clone and make the files yourself

```
git clone --branch readme https://github.com/erikkvietelaitis/COS40005-Intrusion-Detection-System.git #Chromia Host Based IDS
git clone --branch prodhttps://github.com/brokenpip/ctpb_ids #Required TPM model
```

If you are having to build your own version, please complete the previous steps 1-4, first, as the cloned repos use the outlined dependnces in step 3. for the installation and general running process
<br>
locate the cargo toml files of the seperate systems and:
eg:

```
$HOME/Downloads/COS40005-Intrusion-Detection-System
```

and then run in the terminal

```
cargo build --release
```

Copy the built executables which should be located for example at:

```
$HOME/Downloads/COS40005-Intrusion-Detection-System/target/release
```

into a newly created file located at

```
/bin/Chromia
```

5. If all else fails, please reach out and contact one of the tagged developers and or make a bug request log

NOTES:
[^1]: Chromia has only been tested and currently designed for Ubuntu 24.04 LTS, it maybe possible to run on other Debian based systems, but your mileage may very.
[^2]: For Chromia to work we have to make two .service files as part of the install script. these are to help insure that Chromia remains active when closed as well as also restart after the Host device has been reset.
[^3]: Chromia may run and print logs but may not work properly as all files may not be properly configured
