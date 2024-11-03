# Access Control Logging System

## Authors

- **Lamprakis Michalis** - 2020030077
- **Dimas Christos** - 2021030183

## Main Description

Developed in C, this system logs file access and modifications initiated by user programs. Each operation is logged, allowing for security analysis and monitoring of file activities.

## Modules Description

- **logger.c**: Handles logging of all file operations by overriding `fopen` and `fwrite`, logging user actions, file hashes, and more.
- **acmonitor.c**: Monitors log data to detect security breaches and unauthorized access attempts.
- **test_aclog.c**: Tests the logging functionalities by simulating various file operations.

## Testing the logger.so Shared Library

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

