# Chromia Release Notes
This document details the features added to Chromia between major releases. This documents aim to help fill in team members about the current state of the project and any changes they should be aware of. Version notes will be ordered newest to oldest. This document is not a conclusive list of changes, more just a summary of most important ones

**Bold text is information that you MUST read to keep your code up to date and running on that version**.

----

## ALPHA - 0.3.0 - August 30th 2024
### Additions:
- Added config file system 
    - you can now add inputs for your module with function `fn build_config_fields(&self) -> Vec<ConfigField>`
    - User inputs will be gathered by your module in the new function `fn insert_config_data(&self, data: HashMap<String, Vec<String>>) -> bool`
        - While datatype validation will occur, you should validate the inputs further yourself in this function. (eg: if a user is entering a filetype you should ensure that the file exists and is accessible). If validation fails; use `panic!()` to kill the system. 
    - System execution order for modules is now like so: `default()->build_config_fields()->insert_config_data-> CORE LOOP{get_data-> perform_analysis()}*infinity`
    - **THESE FUNCTIONS MUST BE IMPLEMENTED FOR YOUR CODE TO RUN**
    - Following features will be coming in future updates to the config file system:
        - Checking data types of values entered by user
### To Do:
- Lachlan:
    - Fix incorrectly formatted names of objects and crates in repo
    - Remove references to LARA
    - Move startup of Chromia to seperate function outside main
### Known issues:
None currently 
### Improvements:
    - new functions added to linux bridge including ability to read binaries and create/write files
    - example module has been updated to utilize new architecture features.
## ALPHA - 0.2.0 - August 22nd 2024
### Additions:
- Added the linux bridge. Functions can be accessed through `linux_bridge::<linux bridge Module>::<function name>`. 
    - Current linux bridge modules added:
        - auth module (empty)
        - network module (empty)
        - system module
            - Reading Files
            - Getting system info
- Added new startup messages with system and package information
### Improvements:
- Rebuilt core loop to be fully dynamic and Object oriented. **See main for how to add analysis modules to new core loop**
    - This introduces `tick_intervals`. This defines how long in milliseconds, how long the system will wait between running another check of all modules (AKA ticks). Increasing this reduces performance impact, but means less timely logs
- Analysis modules now must have the module_name key in their struts and a new function in their trait `get_name` that should return the name. **Analysis Modules MUST implement this new trait to run**
-
### To Do:
- Lachlan:
    - Fix incorrectly formatted names of objects and crates in repo
    - Remove references to LARA
    - Move startup of Chromia to seperate function outside main
### Known issues:
none at this stage

--
