# GemOS

This project implements enhancements in memory management and adds tracing functionalities to GemOS operating system.

## Implemented Features

- **Copy-on-Write (CoW) Fork**: Delays physical memory and new page table allocations until memory is accessed.
- **Memory Mapping Functions**: Adds `mmap`, `munmap`, and `mprotect` for dynamic memory management and permission setting.
- **System and Function Call Tracing**: Introduces a tracing mechanism with a custom buffer to track and log system and function calls, similar to `strace` and `ftrace`.
