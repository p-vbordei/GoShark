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
        | `pyshark/src/pyshark/capture/inmem_capture.py` | `capture/inmem_capture.go` | Complete | Batch processing, sniff times, and PCAP header generation implemented |
        | `pyshark/src/pyshark/capture/keytap_capture.py` | N/A | Planned | Not started, low priority |

        **Packet Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/packet/packet.py` | `packet/packet.go` | Complete | Core packet structure and methods |
        | `pyshark/src/pyshark/packet/layers/base.py` | `packet/layers/base.go` | Complete | Base layer interface and common functionality |
        | `pyshark/src/pyshark/packet/layers/json_layer.py` | `packet/layers/json_layer.go` | Complete | JSON layer implementation |
        | `pyshark/src/pyshark/packet/layers/xml_layer.py` | `packet/layers/xml_layer.go` | Complete | XML layer implementation |
        | `pyshark/src/pyshark/packet/layers/ek_layer.py` | `packet/layers/ek_layer.go` | Complete | Elastic Common Schema layer implementation |
        | `pyshark/src/pyshark/packet/fields.py` | `packet/fields.go` | Complete | Field containers and utilities |
        | `pyshark/src/pyshark/packet/common.py` | `packet/common.go` | Complete | Common utilities for packet handling |
        | `pyshark/src/pyshark/packet/packet_summary.py` | `packet/packet_summary.go` | Complete | Packet summary functionality |
        | `pyshark/src/pyshark/packet/consts.py` | `packet/consts/consts.go` | Complete | Protocol constants and helpers |

        **TShark Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/tshark/tshark.py` | `tshark/tshark.go` | Complete | Process management, interface detection, and version handling |
        | `pyshark/src/pyshark/tshark/tshark_json.py` | `tshark/parser_json.go` | Complete | JSON parsing with nested layer support |
        | `pyshark/src/pyshark/tshark/tshark_xml.py` | `tshark/parser_xml.go` | Complete | PDML (XML) parsing with field hierarchy support |
        | `pyshark/src/pyshark/tshark/tshark_ek.py` | `tshark/parser_ek.go` | Complete | Elastic Common Schema parsing |
        | `pyshark/src/pyshark/tshark/filter.py` | `tshark/filter.go` | Complete | Display and capture filter handling |
        | `pyshark/src/pyshark/tshark/ek_field_mapping.py` | `tshark/ek_field_mapping/ek_field_mapping.go` | Complete | EK field type mapping and conversion |

        **Core Module:**
        | Python File | Go File | Status | Notes |
        |------------|---------|--------|-------|
        | `pyshark/src/pyshark/config.py` | `config/config.go` | Complete | Configuration management with JSON support |
        | `pyshark/src/pyshark/exceptions.py` | `errors/errors.go` | Complete | Custom error types with proper error interface implementation |
        | `pyshark/src/pyshark/utils.py` | `utils/utils.go` | Complete | Common utility functions |
        | `pyshark/src/pyshark/cache.py` | `cache/cache.go` | Complete | Cache management for TShark output |
        | `pyshark/src/pyshark/packet/consts.py` | `packet/consts/consts.go` | Complete | Protocol constants and helper functions |

    *   **Next Implementation Priorities:**
        1. Complete in-memory capture functionality in `capture/inmem_capture.go` ✅
        2. Implement packet export/output functionality ✅
        3. Add packet dissection details (raw bytes, field offsets) ✅
        4. Implement session/conversation tracking ✅
        5. Implement test structure and functionality ✅

## Phase 5: Test Implementation

**Objective:** Mirror the test structure and functionality from the Python repository to ensure proper testing of the Go implementation.

1.  **Test Structure:**
    *   Create a test directory structure that mirrors the Python repository's test organization.
    *   **Status:** Planned.
    *   **Tasks (Medium Complexity):**
        *   [ ] Create `tests/` directory with subdirectories for each module:
            * `tests/capture/`
            * `tests/packet/`
            * `tests/tshark/`
        *   [ ] Set up test fixtures and helper functions in `tests/conftest.go`

2.  **Capture Tests:**
    *   Implement tests for the various capture types.
    *   **Status:** Planned.
    *   **Tests to Implement:**
        *   [ ] `tests/capture/test_capture.go`: Base capture functionality tests
        *   [ ] `tests/capture/test_inmem_capture.go`: In-memory capture tests
        *   [ ] `tests/capture/test_live_capture.go`: Live capture tests

3.  **Packet Tests:**
    *   Implement tests for packet parsing and field access.
    *   **Status:** Planned.
    *   **Tests to Implement:**
        *   [ ] `tests/packet/test_fields.go`: Field container and access tests
        *   [ ] `tests/test_packet_operations.go`: Packet operations tests

4.  **TShark Tests:**
    *   Implement tests for TShark interaction and output parsing.
    *   **Status:** Planned.
    *   **Tests to Implement:**
        *   [ ] `tests/tshark/test_tshark.go`: TShark executable interaction tests
        *   [ ] `tests/tshark/test_tshark_json.go`: JSON output parsing tests
        *   [ ] `tests/tshark/test_tshark_xml.go`: XML output parsing tests
        *   [ ] `tests/tshark/test_tshark_ek.go`: EK output parsing tests

5.  **Integration Tests:**
    *   Implement end-to-end tests for the entire library.
    *   **Status:** Planned.
    *   **Tests to Implement:**
        *   [ ] `tests/test_basic_parsing.go`: Basic packet parsing tests
        *   [ ] `tests/test_cap_operations.go`: Capture operations tests
        *   [ ] `tests/test_ek_field_mapping.go`: EK field mapping tests

6.  **Test Data:**
    *   Create or copy test data files for consistent test execution.
    *   **Status:** Planned.
    *   **Tasks (Low Complexity):**
        *   [ ] Create `tests/data/` directory
        *   [ ] Add sample PCAP files for testing
        *   [ ] Add sample JSON, XML, and EK output files
