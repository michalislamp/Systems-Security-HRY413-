# Access Control Logging System

## Authors

- **Lamprakis Michalis** - 2020030077
- **Dimas Christos** - 2021030183

## Main Description

This is an access control logging system developed in C, designed to track all file accesses and modifications triggered by a user's program. Each file operation generates an entry in a log file, which facilitates in-depth analysis by a privileged process. The log file, created in the same directory, captures key details for enhanced security monitoring, providing a concise yet effective solution for comprehensive file activity tracking.


## Modules Description

## Modules

- **logger.c**: Creates log files and overrides standard `fopen` and `fwrite` functions. This module collects data such as the user ID, date/time of the action, user permissions, and generates an SHA256 hash of the file content after each `fwrite` call, logging all information into `file_logging.log`.
- **acmonitor.c**: Implements the monitoring tools that utilize the logged data to identify potential security breaches, including detecting malicious users—those attempting to access a file without the necessary permissions.
- **test_aclog.c**: Contains tests to verify the functionalities of the logging and monitoring system, simulating various file operations to create scenarios for the tools to capture and analyze.

## Testing Logger

### Test 1: Basic File Operations
- **Objective**: Open and write names to `file_0` to `file_9`.
- **Expected Logs**: 20 lines (2 per file).
  - First line with access type flag 0 and an empty file hash.
  - Second line with access type flag 2 and the resulting file hash.

### Test 2: Permission Changes
- **Objective**: Create, modify, and change permissions of 2 junk files, then attempt to open them.
- **Expected Logs**: 8 lines.
  - Initial 4 lines with opening flags and hashes.
  - Following 4 lines showing access denied after permission changes.

### Test 3: Read Operation
- **Objective**: Open `file_4` for reading.
- **Expected Logs**: 1 line matching the hash from Test 1.

### Test 4: Append Operation
- **Objective**: Append to `file_2`.
- **Expected Logs**: 2 lines.
  - First line with an unchanged hash and access type 1.
  - Second line with a new hash and access type 2.

## Testing the Monitor

### Test 1: Malicious Users Detection
- **Objective**: Simulate denied access for 10 users over multiple files.
- **Expected Output**: Monitor flags these users as malicious when run with `-m`.

### Test 2: File Modification Tracking
- **Objective**: Simulate multiple modifications to `file_8` by 10 users.
- **Expected Output**: Monitor reports modifications by 10 users plus one additional from earlier tests when provided `file_8` as an argument.

## Makefile Commands

- `make`: Builds the project.
- `make run`: Runs the tester with the shared library preloaded.
- `make clean`: Cleans object files, removes test files, and deletes the log file.

## Running the System

- **Build the system:** `make all`
- **Update LogFile:** `make run`
- **Identify & Print Information for Malicious Users:** `./acmonitor -m`
- **Identify & Print Information for Users Accessing a Specified File:** `./acmonitor -i [path to filename]`
- **Clear LogFile & Erase Executable Files:** `make clean`


