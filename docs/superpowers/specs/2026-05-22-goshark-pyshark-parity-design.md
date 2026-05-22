# GoShark → pyshark parity: design

**Date:** 2026-05-22
**Goal:** Make GoShark a correct, complete Go port of the Python `pyshark` library — a wrapper around tshark/Wireshark.

## Problem statement

GoShark builds and all unit tests pass, but the test suite validates a **fabricated JSON format that real tshark never emits**. Against real tshark output the library is broken:

1. `GetTSharkVersion("")` never calls `FindTShark()` on an empty path — every sibling function does. `go run .` crashes with `exec: no command`.
2. `Packet.UnmarshalJSON` expects `"frame.number": [{"value":"1"}]`. Real `tshark -T json` emits `"frame.number": "1"`. Result: `FrameNumber`, `FrameLen`, `FrameCapLen`, `FrameTimeEpoch`, `FrameTime` all decode to empty strings.
3. Layers are decoded into an unordered `map[string]json.RawMessage`, then `sort.Strings()` orders them alphabetically. Real protocol order (`frame,null,ip,tcp,data`) is destroyed, so `HighestLayer()` returns the wrong layer.
4. `SniffTime()` returns the zero time — it depends on the empty `FrameTimeEpoch` from #2, and parses only float epochs while tshark 4.6 here emits `frame.time_epoch` as an ISO-8601 string.
5. The XML/PDML path emits a bogus `fake-field-wrapper` layer (a tshark PDML artifact pyshark explicitly filters) and leaves frame number empty.

Plus missing pyshark API surface: capture indexing/`len`, `load_packets`/`keep_packets`, `Packet.pretty_print`, attribute-style field access, `set_debug`, `interface_captured`, and an EK output path that is parsed but never wired into the capture stream.

## Scope

Full parity overhaul. Verification uses **real tshark against the bundled `test.pcap`** for File/InMem/Pipe captures; Live/Remote/LiveRing are covered by argument-construction + build-only tests (they need root/network).

## Key technical decisions

### Ordered layer parsing

Replace `map[string]json.RawMessage` with ordered decoding. In `Packet.UnmarshalJSON`, decode `_source.layers` with `json.Decoder.Token()`, walking object keys in document order into an ordered `[]Layer`. This fixes layer order, `HighestLayer()`, and `TransportLayer()` in one change.

- `--no-duplicate-keys` is kept. When tshark merges repeated layers it produces an array value (`"ip": [ {...}, {...} ]`); the decoder expands each array element into its own `Layer`, preserving `GetMultipleLayers`.
- `_raw` sibling keys (`frame_raw`, `ip_raw`, …) are matched to their base layer by name for offset/raw-bytes extraction.

### Frame metadata extraction

`layer.Fields` (a generic `map[string]interface{}`) already decodes real tshark output correctly — only the typed `frameLayer` struct was wrong. Derive `FrameNumber` etc. with a `coerceFieldString` helper that accepts: a plain string (`"1"`), a one-element array (`["1"]`), or a nested object with a `value`/`show` key. Drop the fictional `[{"value":...}]` struct.

### SniffTime robustness

Parse `frame.time_epoch` as a float epoch first; on failure parse as RFC3339/ISO-8601 (tshark renders absolute-time fields per the Wireshark time-format preference). Fall back to `frame.time`. Add `SniffTimestamp()` returning the raw string, matching pyshark.

### Attribute-style field access

Go has no `__getattr__`. Port via prefix-aware getters: `layer.Field("srcport")` resolves `tcp.srcport` by adding/stripping the layer prefix; `packet.Layer("tcp")` for layer access. Type-safe, no reflection.

### EK output path

`-T ek` emits newline-delimited JSON (an index line then a packet line per record). Add an EK branch to `sniffStream` and a `WithUseEK` option so the existing `EKParser` becomes reachable.

## Architecture

No package restructuring. Changes are localized:

- `tshark/tshark.go` — `GetTSharkVersion` path resolution.
- `packet/packet.go` — ordered `UnmarshalJSON`, frame metadata, `SniffTime`/`SniffTimestamp`, `InterfaceCaptured`, `String`/`PrettyPrint`, prefix-aware `Layer`/`Field` accessors.
- `tshark/parser_xml.go` — drop `fake-field-wrapper`, populate frame number.
- `capture/capture.go` — `KeepPackets`, `LoadPackets`, `Packets`, `Len`, `Get`, `Next`, `Close`, `SetDebug`, EK branch in `sniffStream`, `packet_count`/`timeout` honored in `ApplyOnPackets`.
- `main.go` — replace the `non_existent.pcap` demo with a working `test.pcap` example.
- Test files — rewrite fabricated fixtures; add real-tshark integration tests.

## Build sequence (phases)

**Phase 1 — Correctness foundation.** `GetTSharkVersion` fix; ordered `UnmarshalJSON`; frame metadata; `SniffTime`/`SniffTimestamp`; XML `fake-field-wrapper` filter. Verify: a temporary harness over `test.pcap` shows correct layer order, frame number/length, and non-zero sniff time for both JSON and XML paths.

**Phase 2 — Test realignment.** Rewrite the `[{"value":...}]` fixtures in `tshark/parser_test.go` and `packet/*_test.go` to real tshark JSON/PDML. Add integration tests invoking real tshark on `test.pcap` for File/InMem/Pipe, asserting layer order, frame metadata, sniff time. Tests skip gracefully (`t.Skip`) if tshark is absent. Verify: `go test ./...` passes and the integration tests genuinely exercise tshark.

**Phase 3 — pyshark API parity.** `Capture` indexing/`Len`/`LoadPackets`/`KeepPackets`/`Next`/`Close`/`SetDebug`; `ApplyOnPackets` honors `packet_count`/`timeout`; `Packet.String`/`PrettyPrint`/`InterfaceCaptured`; prefix-aware field access; `PrettyPrint` parity across Json/Xml/Ek layers; EK path wired into `sniffStream` with `WithUseEK`. Verify: unit + integration tests cover each new method.

**Phase 4 — Capture-type validation & polish.** End-to-end verify File/InMem/Pipe on `test.pcap`; assert Live/Remote/LiveRing build correct tshark/dumpcap arg vectors. Fix `main.go`. Verify: `go build ./...`, `go vet ./...`, `go test ./...` all clean; `go run .` works.

## Error handling

- Missing tshark → existing `TSharkNotFoundException` surfaces unchanged.
- Malformed packet JSON → `UnmarshalJSON` returns a wrapped error; `sniffStream` already stops the stream on decode error.
- Integration tests detect tshark via `FindTShark()` and `t.Skip` when unavailable, so CI without Wireshark stays green.

## Testing strategy

- Unit tests use **corrected** fixtures matching real tshark JSON/PDML/EK.
- Integration tests run real tshark on the committed `test.pcap` (5 packets, TCP/IP/loopback) for File/InMem/Pipe.
- Live/Remote/LiveRing: assert generated argument vectors; no live capture in the suite.
- Regression bar: every bug in the problem statement gets a test that fails before the fix and passes after.

## Out of scope

- Code-generated per-protocol typed structs.
- New tshark features beyond pyshark's surface.
- Windows-specific live-capture validation (arg construction only).
