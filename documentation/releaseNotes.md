# Chromia Release Notes
This document details the features added to Chromia between major releases. This documents aim to help fill in team members about the current state of the project and any changes they should be aware of. Version notes will be ordered newest to oldest. This document is not a conclusive list of changes, more just a summary of most important ones

**Bold text is information that you MUST read to keep your code up to date and running on that version**.

----

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
