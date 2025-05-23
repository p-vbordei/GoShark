# GoShark

This project aims to duplicate `pyshark`'s functionality in Golang. It will leverage `tshark` for packet capture and analysis, similar to how `pyshark` operates.

## Running the Application

To run the application, ensure you have TShark installed and available in your system's PATH.

```bash
go run main.go
```

**Note**: For testing purposes, `main.go` is configured to capture a limited number of packets (currently 10) to prevent an infinite capture loop. You can modify this limit in `main.go` or extend the `capture` package to support other capture termination conditions.

## Project Structure

- `go_shark/tshark`: Contains Go functions for interacting with the `tshark` executable (finding path, getting version, executing commands).
- `go_shark/capture`: Will contain logic for different packet capture methods (live, file).
- `go_shark/packet`: Will define Go structs for parsed packet data.
- `go_shark/parser`: Will handle parsing `tshark`'s output (e.g., JSON, PDML).

## Current Progress

See `progress.md` for detailed updates.

## Lessons Learned

See `lessons_learned.md` for insights and challenges encountered during development.
