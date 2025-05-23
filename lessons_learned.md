# Lessons Learned

This document will track key learnings, challenges, and insights gained during the development of GoShark.

## Initial Analysis of pyshark:
- `pyshark` is a Python wrapper for `tshark`, not a packet parser itself. It relies on `tshark`'s ability to export packet data in various formats (XML, JSON, PDML).
- The core interaction with `tshark` involves executing `tshark` as a subprocess and parsing its `stdout`.
- `pyshark` handles `tshark` path discovery, version checking, and error handling (monitoring `stderr`).

## Go Implementation Approach:
- The Go project will mirror `pyshark`'s modularity, with separate packages for `tshark` interaction, capture logic, packet structures, and output parsing.
- Initial focus is on building a robust `tshark` command wrapper in Go.

## Challenges:
- Ensuring cross-platform compatibility for `tshark` path discovery.
- Accurately parsing `tshark`'s version output.
- Handling `tshark` subprocess `stdout` and `stderr` streams efficiently in Go.
