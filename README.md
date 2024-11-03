# Access Control Logging System

## Authors

- **Valsamos Fotios** - 2018030074
- **Chatzianagnostou Christina** - 2018030132

## Main Description

This is an access control logging system developed in C, designed to track all file accesses and modifications triggered by a user's program. Each file operation generates an entry in a log file, which facilitates in-depth analysis by a privileged process. The log file, created in the same directory, captures key details for enhanced security monitoring, providing a concise yet effective solution for comprehensive file activity tracking.

### Modules

- **logger.c**: Creates log files and overrides standard `fopen` and `fwrite` functions. This module collects data such as the user ID, date/time of the action, user permissions, and generates an MD5 hash of the file content after each `fwrite` call, logging all information into `file_logging.log`.
- **acmonitor.c**: Implements the monitoring tools that utilize the logged data to identify potential security breaches, including detecting malicious users—those attempting to access a file without the necessary permissions.
- **test_aclog.c**: Contains tests to verify the functionalities of the logging and monitoring system, simulating various file operations to create scenarios for the tools to capture and analyze.

## Running the System

- **Build the system:** `make all`
- **Update LogFile:** `make run`
- **Identify & Print Information for Malicious Users:** `./acmonitor -m`
- **Identify & Print Information for Users Accessing a Specified File:** `./acmonitor -i [path to filename]`
- **Clear LogFile & Erase Executable Files:** `make clean`
