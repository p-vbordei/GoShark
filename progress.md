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
        *   [x] Update `goshark/capture/capture.go` import paths.
        *   [x] Update `goshark/capture/file_capture.go` import paths.
        *   [x] Update `goshark/capture/live_capture.go` import paths.
        *   [x] Update `goshark/packet/packet.go` import paths.
        *   [x] Update `goshark/tshark/tshark.go` import paths.

4.  **Mirror Pyshark Python Files to Go:**
    *   For each significant Python file in Pyshark, create a corresponding Go file or integrate its functionality into existing Go structures.
    *   **Status:** In Progress.
    *   **Implementation Tracking:**

        **Capture Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/capture/capture.py` | `capture/capture.go` | Complete | Base capture functionality implemented |
        | `pyshark/src/pyshark/capture/file_capture.py` | `capture/file_capture.go` | Complete | PCAP file reading implemented |
        | `pyshark/src/pyshark/capture/live_capture.py` | `capture/live_capture.go` | Complete | Interface capture with BPF filtering |
        | `pyshark/src/pyshark/capture/live_ring_capture.py` | `capture/live_ring_capture.go` | Complete | Ring buffer functionality |
        | `pyshark/src/pyshark/capture/remote_capture.py` | `capture/remote_capture.go` | Complete | Remote rpcapd capture |
        | `pyshark/src/pyshark/capture/pipe_capture.py` | `capture/pipe_capture.go` | Complete | Pipe-based capture |
        | `pyshark/src/pyshark/capture/inmem_capture.py` | `capture/inmem_capture.go` | Partial | Missing streaming functionality |
        | `pyshark/src/pyshark/capture/keytap_capture.py` | N/A | Planned | Not started, low priority |

        **Packet Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/packet/packet.py` | `packet/packet.go` | Complete | Core packet structure and methods |
        | `pyshark/src/pyshark/packet/layers/base.py` | `packet/layer.go` | Partial | Basic layer functionality, missing some methods |
        | `pyshark/src/pyshark/packet/layers/json_layer.py` | `packet/json_layer.go` | Planned | Not started |
        | `pyshark/src/pyshark/packet/layers/xml_layer.py` | `packet/xml_layer.go` | Planned | Not started |

        **TShark Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/tshark/tshark.py` | `tshark/tshark.go` | Complete | Process management, interface detection, and version handling |
        | `pyshark/src/pyshark/tshark/tshark_json.py` | `tshark/parser_json.go` | Complete | JSON parsing with nested layer support |
        | `pyshark/src/pyshark/tshark/tshark_xml.py` | `tshark/parser_xml.go` | Planned | Not started |
        | `pyshark/src/pyshark/tshark/tshark_ek.py` | `tshark/parser_ek.go` | Planned | Not started |

        **Core Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/config.py` | `config/config.go` | Partial | Basic config structure, missing some options |
        | `pyshark/src/pyshark/exceptions.py` | `errors/errors.go` | Planned | Not started |
        | `pyshark/src/pyshark/utils.py` | `utils/utils.go` | Planned | Not started |

    *   **Next Implementation Priorities:**
        1. Create XML parser in `tshark/parser_xml.go`
        2. Implement EK parser in `tshark/parser_ek.go`
        3. Add protocol-specific layer handling in `packet/layer.go`
        4. Integrate filters into TShark command arguments

## Phase 3: Core Functionality Implementation

**Objective:** Implement the core packet capture, parsing, and filtering functionalities.

1.  **Packet Capture:**
    *   Implement functions to start and stop packet captures using TShark.
    *   **Status:** Complete.
    *   **Tasks (Low Complexity):**
        *   [x] Implement `StartCapture` and `StopCapture` methods in `goshark/capture/capture.go`.
        *   [x] Handle TShark process management (start, stop, error handling).

2.  **Packet Parsing:**
    *   Parse TShark's JSON output into `Packet` and `Layer` structs.
    *   **Status:** Complete.
    *   **Tasks (Low Complexity):**
        *   [x] Implement `UnmarshalJSON` for `Packet` struct.
        *   [x] Implement `UnmarshalJSON` for `Layer` struct.
        *   [x] Handle nested layers and fields.

3.  **Basic Filtering:**
    *   Implement display and capture filters.
    *   **Status:** In Progress.
    *   **Tasks (Low Complexity):**
        *   [x] Add `DisplayFilter` and `CaptureFilter` fields to `Capture` struct.
        *   [ ] Integrate filters into TShark command arguments.

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
