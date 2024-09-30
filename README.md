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

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/github_username/repo_name">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Chromia Hostbased IDS</h3>

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
Students where asked by BadSecurity Inc to develop a Host Based Intrustion Detection System. We where tasked to do the reuqired reasurch and determine the best means of development.
Chromia was created by student attedning at Swinburne University as part of there final year project:
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
### Prerequisites
Users that want to try Chromia Host Based IDS will have to download via GitHub the install.sh script. This script will work to install all required dependences as well as create the required software.
This can be completed via downlaoding the script via:
<br>
<a href="https://raw.githubusercontent.com/erikkvietelaitis/COS40005-Intrusion-Detection-System/readme/install.sh" download="install.sh">
  <img src="https://img.shields.io/badge/Download%20Install%20Script-blue?style=for-the-badge" alt="Download Install Script">
</a>


Once the install script is download 

<!--INSTALLING CHROMIA HOST BASED IDS -->
You will need to install Chromia via the install.sh scripte
Chromia has a limited install distrubtion[^1] and has limited testing, please submit report bugs realted to the Guthub Repo for further assesment, but at this time development has no plans for expanding to other distros.

Installation can be completed via changing to the directory where Chromia was installed and then run:
chmod +x install.sh Making the script exacutable
./install.sh Installing the excutable script

Chromia will install 3rd party depndecies as part of the install process as so it can function this can include:
git
net-tools
curl
rust
rust packages
-B3Sum

The install script will also have to create directries for installation[^2]. as to ensure that the service runs to the best that we can provide.

AFTER INSTALLATION: IT IS IMPORTANT TO REFER TO THE CONFIG.INI FILE[^3]
Please refer to:
Please refer to
/etc/config.ini
The config.ini has all relevent setting/ options for the function of Chromia

NOTES:
[^1]: Chromia has only been tested and currently designed for Ubuntu 24.04 LTS, it maybe possible to run on other Debian based systems, but your mileage may very.

[^2]: For Chromia to work we have to make two .service files as part of the install script. these are to help insure that Chromia remains active when closed as well as also restart after the Host device has been reset.

[^3]: Chromia may run and print logs but may not work properly as all files may not be properly configured




Once cloned from GitHub using
git clone and the Github link















This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

This is an example of how to list things you need to use the software and how to install them.

- npm
  ```sh
  npm install npm@latest -g
  ```

### Installation

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/github_username/repo_name.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```js
   const API_KEY = "ENTER YOUR API";
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->

## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->

## Roadmap

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3
  - [ ] Nested Feature

See the [open issues](https://github.com/github_username/repo_name/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->

## Contact

Your Name - [@twitter_handle](https://twitter.com/twitter_handle) - email@email_client.com

Project Link: [https://github.com/github_username/repo_name](https://github.com/github_username/repo_name)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

- []()
- []()
- []()

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/github_username/repo_name.svg?style=for-the-badge
[contributors-url]: https://github.com/github_username/repo_name/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/github_username/repo_name.svg?style=for-the-badge
[forks-url]: https://github.com/github_username/repo_name/network/members
[stars-shield]: https://img.shields.io/github/stars/github_username/repo_name.svg?style=for-the-badge
[stars-url]: https://github.com/github_username/repo_name/stargazers
[issues-shield]: https://img.shields.io/github/issues/github_username/repo_name.svg?style=for-the-badge
[issues-url]: https://github.com/github_username/repo_name/issues
[license-shield]: https://img.shields.io/github/license/github_username/repo_name.svg?style=for-the-badge
[license-url]: https://github.com/github_username/repo_name/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com
