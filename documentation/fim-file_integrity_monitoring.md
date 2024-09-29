# FIM - File Integrity Monitoring

This file fulfils the following requirements
- Monitor: File system changes
- Anomalous activities: File additions to a secure and protected folder
- Know When and Who Accessed & Changed Critical Files with File Integrity Monitoring (FIM)
----
## Operation Overview
This module will use the principles of cryptographic hashes to detect changes to the codebase, key system files, and user-defined protected folders

## Configuration
The FIM module will monitor the config file and codebase folder by default.
To add other files or folders; you can modify the config.ini file and then restart the IDS.
### Files
files[]=/home/ids/Documents/GitHub/COS40005-Intrusion-Detection-System/test
### Folders
folders[]=/var/chromia
