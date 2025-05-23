# GoShark Development Plan: Mirroring Pyshark Functionality

This document outlines the step-by-step plan to translate the core functionalities of Pyshark into the GoShark project, aiming for a comprehensive and robust packet analysis library in Go.

## Phase 1: Core Capture Mechanisms (Enhancement & Completion)

## Phase 2: Module Restructuring and Pyshark Mirroring

**Objective:** Reorganize the GoShark project to mirror the module structure of Pyshark and identify corresponding Go components for Pyshark's Python files.

1.  **Duplicate Pyshark Module Structure:**
    *   Create `goshark/capture`, `goshark/packet`, and `goshark/tshark` directories.
    *   **Status:** Complete.
    *   **Tasks (Low Complexity):**
        *   [x] Create `goshark` base directory.
        *   [x] Create `goshark/capture` directory.
        *   [x] Create `goshark/packet` directory.
        *   [x] Create `goshark/tshark` directory.

2.  **Move Existing Go Files to New Structure:**
    *   Relocate `capture/*.go`, `packet/*.go`, and `tshark/*.go` to their respective `goshark` subdirectories.
    *   **Status:** Complete.
    *   **Tasks (Low Complexity):
        *   [x] Move `capture/capture.go` to `goshark/capture/capture.go`.
        *   [x] Move `capture/file_capture.go` to `goshark/capture/file_capture.go`.
        *   [x] Move `capture/live_capture.go` to `goshark/capture/live_capture.go`.
        *   [x] Move `packet/packet.go` to `goshark/packet/packet.go`.
        *   [x] Move `tshark/tshark.go` to `goshark/tshark/tshark.go`.

3.  **Update Go Import Paths:**
    *   Adjust import statements in all Go files to reflect the new `GoShark/goshark` module path.
    *   **Status:** In Progress.
    *   **Tasks (Low Complexity):**
        *   [x] Update `main.go` import paths.
        *   [ ] Update `goshark/capture/capture.go` import paths.
        *   [ ] Update `goshark/capture/file_capture.go` import paths.
        *   [ ] Update `goshark/capture/live_capture.go` import paths.
        *   [ ] Update `goshark/packet/packet.go` import paths.

4.  **Mirror Pyshark Python Files in Go:**
    *   Identify and plan for Go equivalents of key Pyshark Python files.
    *   **Status:** Not Started.
    *   **Tasks (Medium Complexity):**
        *   [x] Plan for `pyshark/src/pyshark/__init__.py` (Go module initialization).
        *   [x] Plan for `pyshark/src/pyshark/capture/capture.py` (Go `Capture` struct and methods).
        *   [x] Plan for `pyshark/src/pyshark/capture/file_capture.py` (Go `FileCapture` struct and methods).
        *   [x] Plan for `pyshark/src/pyshark/capture/live_capture.py` (Go `LiveCapture` struct and methods).
        *   [x] Plan for `pyshark/src/pyshark/capture/pipe_capture.py` (Go equivalent for pipe capture).
        *   [x] Plan for `pyshark/src/pyshark/capture/remote_capture.py` (Go equivalent for remote capture).
        *   [x] Plan for `pyshark/src/pyshark/capture/inmem_capture.py` (Go equivalent for in-memory capture).
        *   [x] Plan for `pyshark/src/pyshark/packet/packet.py` (Go `Packet` struct and parsing).
        *   [x] Plan for `pyshark/src/pyshark/packet/layers/base.py` (Go base layer definitions).
        *   [x] Plan for `pyshark/src/pyshark/packet/layers/json_layer.py` (Go JSON layer handling).
        *   [x] Plan for `pyshark/src/pyshark/packet/layers/xml_layer.py` (Go XML layer handling).
        *   [x] Plan for `pyshark/src/pyshark/tshark/tshark.py` (Go `TShark` command execution and versioning).
        *   [x] Plan for `pyshark/src/pyshark/tshark/tshark_json.py` (Go JSON output parsing).
        *   [x] Plan for `pyshark/src/pyshark/tshark/tshark_xml.py` (Go XML output parsing).
        *   [ ] Plan for `pyshark/src/pyshark/tshark/tshark_ek.py` (Go `tshark -T ek` parsing).
        *   [ ] Plan for `pyshark/src/pyshark/config.py` (Go configuration management).
        *   [ ] Plan for `pyshark/src/pyshark/exceptions.py` (Go custom error types).
        *   [ ] Plan for `pyshark/src/pyshark/utils.py` (Go utility functions).



**Objective:** Solidify the packet capture and basic filtering capabilities, ensuring robustness and mirroring Pyshark's capture options.

1.  **Refine `Capture` Struct and Options:**
    *   Review and finalize `capture/capture.go` to ensure all `tshark` command-line options relevant to capture are exposed via `With` functions (e.g., `promiscuous mode`, `snaplen`, `interface selection`).
    *   **Status:** Mostly complete. `Snaplen`, `Promiscuous`, `MonitorMode` are implemented. Interface selection is implicit via `NewLiveCapture`.
    *   **Tasks (Low Complexity):**
        *   [x] Verify all relevant `tshark` capture options are exposed via `With` functions in `capture/capture.go`.
        *   [x] Add comments to `capture/capture.go` explaining each `With` option.

2.  **Implement File Capture (`tshark -r`):**
    *   Ensure robust reading from PCAP files, including handling of various file formats and potential errors.
    *   **Status:** Complete and tested.
    *   **Tasks (Low Complexity):**
        *   [x] Add a simple example in `main.go` demonstrating file capture.
        *   [x] Ensure error handling for file not found or corrupted PCAP is clear.

3.  **Implement Live Capture (`tshark -i`):**
    *   Ensure stable live packet capture from network interfaces.
    *   **Status:** Complete and tested.
    *   **Tasks (Low Complexity):**
        *   [x] Add a simple example in `main.go` demonstrating live capture.
        *   [x] Verify `tshark` process is properly terminated on program exit.

4.  **BPF Capture Filters (`tshark -f`):**
    *   Verify correct application of BPF filters during packet capture.
    *   **Status:** Complete and tested.
    *   **Tasks (Low Complexity):**
        *   [x] Add an example in `main.go` showing BPF filter usage.
        *   [x] Document common BPF filter syntax.

5.  **Wireshark Display Filters (`tshark -Y`):**
    *   Verify correct application of display filters post-capture.
    *   **Status:** Complete and tested.
    *   **Tasks (Low Complexity):**
        *   [x] Add an example in `main.go` showing display filter usage.
        *   [x] Document common display filter syntax.

6.  **Error Handling and Robustness:**
    *   Improve error propagation and handling across capture functions.
    *   Address the `exec: Wait was already called` issue (already fixed).
    *   Implement graceful shutdown of `tshark` processes.
    *   **Status:** Ongoing, `Wait` error fixed.
    *   **Tasks (Low Complexity):**
        *   [ ] Review all `capture/*.go` files for consistent error returns.
        *   [ ] Add `defer cmd.Process.Kill()` or similar for `tshark` process cleanup on unexpected exits.

## Phase 2: Packet Structure and Layer Parsing

**Objective:** Create a flexible and extensible packet and layer structure in Go that can dynamically parse and expose packet fields, similar to Pyshark's `JsonLayer`.

1.  **Dynamic Layer Structure (`packet/packet.go`):**
    *   Refactor `Packet` and `Layer` types to dynamically handle arbitrary fields using `map[string]interface{}`.
    *   **Status:** Complete and tested.
    *   **Tasks (Low Complexity):**
        *   [ ] Add comments to `packet/packet.go` explaining the dynamic layer structure.
        *   [ ] Ensure JSON tags are correctly handled for nested fields.

2.  **Accessing Layer Fields:**
    *   Develop helper functions or methods to easily access fields within layers, including nested fields and fields with special characters (e.g., `ip.src`, `tcp.dstport`).
    *   Consider type-safe accessors for common fields while maintaining dynamic access for others.
    *   **Status:** Basic access implemented in `main.go`. Further helpers needed.
    *   **Tasks (Low Complexity):**
        *   [ ] Create a helper function in `packet/packet.go` to get a string field value from a `Layer` map with type assertion.
        *   [ ] Create a helper function to get a numeric field value (e.g., `int`, `float64`).

3.  **Support for More Layers:**
    *   Automatically parse and expose all layers available in `tshark`'s JSON output, not just `frame`, `ip`, `tcp`.
    *   **Status:** `packet/packet.go` now supports all layers dynamically.
    *   **Tasks (Low Complexity):**
        *   [ ] Verify that `tshark`'s JSON output for various protocols (e.g., UDP, HTTP, DNS) is correctly unmarshaled into the `Layer` map.
        *   [ ] Add a test case with a packet containing multiple diverse layers.

## Phase 3: Pyshark-like API Design and Usability

**Objective:** Design a user-friendly Go API that mirrors Pyshark's ease of use for iterating, filtering, and analyzing packets.

1.  **`GoShark` Main Struct/Interface:**
    *   Introduce a central `GoShark` struct or interface that encapsulates capture logic (live/file) and provides a unified entry point for users.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Define a `GoShark` struct in a new file (e.g., `goshark/goshark.go`).
        *   [ ] Move `NewLiveCapture` and `NewFileCapture` into methods of the `GoShark` struct, or make them return a `GoShark` instance.

2.  **Packet Iteration:**
    *   Implement methods for iterating over captured packets (e.g., `ForEachPacket`, `GetNextPacket`), allowing users to process packets one by one.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Add a `Packets()` method to `GoShark` that returns a channel of `*packet.Packet`.
        *   [ ] Modify `capture/capture.go` to send parsed packets to this channel.

3.  **Packet Filtering (Post-Capture):**
    *   Provide methods to apply additional filters on already captured packets in Go, beyond `tshark`'s display filters.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Define a `FilterFunc` type (e.g., `func(*packet.Packet) bool`).
        *   [ ] Add a `Filter` method to `GoShark` or an iterator that takes a `FilterFunc`.

4.  **Packet Export/Output:**
    *   Implement functionality to write captured packets to PCAP files.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Investigate `tshark` options for writing to PCAP (`-w`).
        *   [ ] Add a `WithOutputFile` option to `Capture` struct.

## Phase 4: Advanced Features and Utilities

**Objective:** Add more advanced Pyshark features and utility functions to enhance GoShark's capabilities.

1.  **Packet Dissection Details:**
    *   Expose more detailed dissection information (e.g., raw bytes, field offsets, values in different bases).
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Explore `tshark` JSON output for raw packet data.
        *   [ ] Add a method to `Packet` to retrieve raw packet bytes.

2.  **Session/Conversation Tracking:**
    *   Implement logic to track network sessions or conversations.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Define a `Session` struct.
        *   [ ] Identify key fields for session tracking (e.g., IP, ports, protocol).

3.  **Protocol-Specific Parsers:**
    *   For highly used protocols (e.g., HTTP, DNS), consider creating dedicated Go structs for easier access to common fields.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Create a `HTTP` struct with common HTTP fields.
        *   [ ] Add a method to `Packet` to return an `*HTTP` struct if HTTP layer exists.

4.  **Documentation and Examples:**
    *   Create comprehensive documentation and example usage for all functionalities.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Create a `README.md` for the project.
        *   [ ] Add GoDoc comments to all public functions and types.
