# GoShark

This project aims to duplicate `pyshark`'s functionality in Golang. It will leverage `tshark` for packet capture and analysis, similar to how `pyshark` operates.

## Project Structure

- `go_shark/tshark`: Contains Go functions for interacting with the `tshark` executable (finding path, getting version, executing commands).
- `go_shark/capture`: Will contain logic for different packet capture methods (live, file).
- `go_shark/packet`: Will define Go structs for parsed packet data.
- `go_shark/parser`: Will handle parsing `tshark`'s output (e.g., JSON, PDML).

## Current Progress

See `progress.md` for detailed updates.

## Lessons Learned

See `lessons_learned.md` for insights and challenges encountered during development.
