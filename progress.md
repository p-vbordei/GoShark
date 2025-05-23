# GoShark Development Progress

This document outlines the development progress of the GoShark project.

## Step 1: Initial Analysis of pyshark
- Identified `pyshark`'s reliance on `tshark` as a subprocess for packet parsing.
- Understood the key functionalities of `pyshark`: `tshark` execution, output parsing, and error handling.

## Step 2: Project Setup
- Created the basic Go project structure with `go_shark/tshark`, `go_shark/capture`, and `go_shark/packet` directories.

## Step 3: `tshark` Package Implementation
- Implemented `getTSharkPath` function to locate the `tshark` executable across different operating systems.
- Implemented `GetTSharkVersion` function to retrieve and parse the `tshark` version string.

## Next Steps:
- Implement `RunTSharkCommand` in the `tshark` package to execute `tshark` and stream its output.
- Begin implementing capture logic in the `capture` package.
- Define packet structures in the `packet` package.
- Develop output parsers in a new `parser` package.
