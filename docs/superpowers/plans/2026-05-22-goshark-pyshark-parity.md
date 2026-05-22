# GoShark pyshark-parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix GoShark's broken-against-real-tshark parsing and add the missing pyshark API surface so it is a correct, complete Go port of pyshark.

**Architecture:** Localized changes — no package restructuring. The central fix is replacing unordered `map`-based layer decoding with ordered `json.Decoder.Token()` parsing. Tests are realigned to real tshark output and backed by integration tests over the bundled `test.pcap`.

**Tech Stack:** Go 1.24, `encoding/json`, `encoding/xml`, `os/exec`, tshark 4.x, testify.

---

## Phase 1 — Correctness foundation

### Task 1: Fix GetTSharkVersion path resolution

**Files:**
- Modify: `tshark/tshark.go:83-86` (`GetTSharkVersion`)
- Test: `tshark/tshark_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestGetTSharkVersionEmptyPath(t *testing.T) {
	v, err := GetTSharkVersion("")
	require.NoError(t, err)
	require.Regexp(t, `^v\d+\.\d+\.\d+$`, v)
}
```

- [ ] **Step 2: Run** `go test ./tshark/ -run TestGetTSharkVersionEmptyPath -v` → FAIL (`exec: no command`).

- [ ] **Step 3: Implement** — at the top of `GetTSharkVersion`, before `exec.Command`, resolve an empty path the same way every sibling does:

```go
func GetTSharkVersion(tsharkPath string) (string, error) {
	if tsharkPath == "" {
		var err error
		tsharkPath, err = FindTShark()
		if err != nil {
			return "", err
		}
	}
	cmd := exec.Command(tsharkPath, "-v")
	...
```

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `fix(tshark): resolve tshark path in GetTSharkVersion when empty`.

---

### Task 2: Ordered JSON layer parsing + correct frame metadata

This is the core fix. Real `tshark -T json` emits `_source.layers` as an ordered object whose values are either a field-object (`{"frame.number":"1",...}`) or — when `--no-duplicate-keys` merges repeated layers — an array of such objects. Field values are plain strings, one-element arrays, or nested objects. The current code decodes into `map[string]json.RawMessage` and `sort.Strings()`, destroying order.

**Files:**
- Modify: `packet/packet.go` (`UnmarshalJSON` lines 215-348; add helpers)
- Test: `packet/packet_test.go`

- [ ] **Step 1: Write failing test** using real tshark JSON shape:

```go
func TestPacketJSONLayerOrderAndFrame(t *testing.T) {
	data := []byte(`[{"_index":"packets-x","_type":"doc","_source":{"layers":{
"frame":{"frame.number":"1","frame.len":"119","frame.cap_len":"119","frame.time_epoch":"1747997000.123456"},
"null":{"null.type":"2"},
"ip":{"ip.src":"127.0.0.1","ip.dst":"127.0.0.1"},
"tcp":{"tcp.srcport":"58894","tcp.dstport":"58968"},
"data":{"data.data":"00:01:02"}}}}]`)
	p, err := packet.NewPacketFromJSON(data)
	require.NoError(t, err)
	names := []string{}
	for _, l := range p.Layers { names = append(names, l.Name) }
	require.Equal(t, []string{"frame", "null", "ip", "tcp", "data"}, names)
	require.Equal(t, "1", p.FrameNumber)
	require.Equal(t, "119", p.FrameLen)
	require.Equal(t, "data", p.HighestLayer())
	require.Equal(t, "tcp", p.TransportLayer())
}
```

- [ ] **Step 2: Run** `go test ./packet/ -run TestPacketJSONLayerOrderAndFrame -v` → FAIL (order is alphabetical, frame fields empty).

- [ ] **Step 3: Implement.** Add an ordered-layers parser and a field-string coercer; rewrite `UnmarshalJSON` to use them.

Add helpers to `packet/packet.go`:

```go
// orderedLayer is one entry from the _source.layers object, in document order.
type orderedLayer struct {
	name string
	raw  json.RawMessage
}

// decodeOrderedLayers walks a JSON object preserving key order. When a key's
// value is an array (tshark merges duplicate layer keys under --no-duplicate-keys),
// each element becomes its own entry so GetMultipleLayers keeps working.
func decodeOrderedLayers(raw json.RawMessage) ([]orderedLayer, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("layers: expected object")
	}
	var out []orderedLayer
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := keyTok.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(val)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(trimmed, &arr); err == nil {
				for _, el := range arr {
					out = append(out, orderedLayer{name: key, raw: el})
				}
				continue
			}
		}
		out = append(out, orderedLayer{name: key, raw: val})
	}
	return out, nil
}

// coerceFieldString turns a tshark JSON field value into its string form.
// Accepts a plain string, a one-element array, or an object with value/show.
func coerceFieldString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []interface{}:
		if len(x) > 0 {
			return coerceFieldString(x[0])
		}
	case map[string]interface{}:
		for _, k := range []string{"value", "show"} {
			if s, ok := x[k]; ok {
				return coerceFieldString(s)
			}
		}
	}
	return ""
}
```

Rewrite `UnmarshalJSON` so it: (a) unmarshals only `_index` and the raw `_source.layers` bytes; (b) calls `decodeOrderedLayers`; (c) for each entry skips `_raw`-suffixed keys (handled separately for offsets), unmarshals the layer object into `Fields map[string]interface{}`, runs `extractOffsets`, matches a `<name>_raw` sibling for `Pos`/`Len`, and appends in order; (d) for the `frame` layer, sets `FrameNumber/FrameLen/FrameCapLen/FrameTimeEpoch/FrameTime` from `coerceFieldString(Fields["frame.number"])` etc.

Replace the body of `UnmarshalJSON` with:

```go
func (p *Packet) UnmarshalJSON(data []byte) error {
	aux := struct {
		Index  json.RawMessage `json:"_index"`
		Source struct {
			Layers json.RawMessage `json:"layers"`
		} `json:"_source"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var indexStr string
	if err := json.Unmarshal(aux.Index, &indexStr); err == nil {
		p.Index.ProtocolID = indexStr
	} else {
		_ = json.Unmarshal(aux.Index, &p.Index)
	}

	ordered, err := decodeOrderedLayers(aux.Source.Layers)
	if err != nil {
		return fmt.Errorf("failed to decode layers: %w", err)
	}

	// Index raw siblings by base name for offset/raw-bytes extraction.
	rawByBase := map[string]json.RawMessage{}
	for _, ol := range ordered {
		if strings.HasSuffix(ol.name, "_raw") {
			rawByBase[strings.TrimSuffix(ol.name, "_raw")] = ol.raw
		}
	}
	if fr, ok := rawByBase["frame"]; ok {
		if hexStr, err := extractHexFromFrameRaw(fr); err == nil {
			hexStr = strings.ReplaceAll(hexStr, ":", "")
			if rawData, err := hex.DecodeString(hexStr); err == nil {
				p.RawData = rawData
			}
		}
	}

	p.Layers = make([]Layer, 0, len(ordered))
	for _, ol := range ordered {
		if strings.HasSuffix(ol.name, "_raw") {
			continue
		}
		layer := Layer{Name: ol.name, Offsets: make(map[string]*FieldOffset)}
		if err := json.Unmarshal(ol.raw, &layer.Fields); err != nil {
			return fmt.Errorf("failed to unmarshal %s layer: %w", ol.name, err)
		}
		if rawBytes, ok := rawByBase[ol.name]; ok {
			var rawArr []interface{}
			if err := json.Unmarshal(rawBytes, &rawArr); err == nil && len(rawArr) >= 3 {
				if pos, ok1 := parseInt(rawArr[1]); ok1 {
					layer.Pos = pos
				}
				if length, ok2 := parseInt(rawArr[2]); ok2 {
					layer.Len = length
				}
			}
		}
		extractOffsets(layer.Fields, layer.Offsets)
		if ol.name == "frame" {
			p.FrameNumber = coerceFieldString(layer.Fields["frame.number"])
			p.FrameLen = coerceFieldString(layer.Fields["frame.len"])
			p.FrameCapLen = coerceFieldString(layer.Fields["frame.cap_len"])
			p.FrameTimeEpoch = coerceFieldString(layer.Fields["frame.time_epoch"])
			p.FrameTime = coerceFieldString(layer.Fields["frame.time"])
		}
		p.Layers = append(p.Layers, layer)
	}
	return nil
}
```

Add `"bytes"` to the import block. Remove the now-unused `sort` import if no other reference remains (check with `go build`).

- [ ] **Step 4: Run** `go test ./packet/ -run TestPacketJSONLayerOrderAndFrame -v` → PASS.
- [ ] **Step 5: Commit** `fix(packet): preserve layer order and parse real tshark JSON frame metadata`.

---

### Task 3: SniffTime / SniffTimestamp robustness

`frame.time_epoch` may render as a float (`1747997000.123`) or, depending on the Wireshark time-format preference, as ISO-8601 (`2025-05-23T10:43:13.726858000Z`).

**Files:**
- Modify: `packet/packet.go` (`SniffTime` lines 351-362; add `SniffTimestamp`)
- Test: `packet/packet_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestSniffTimeFormats(t *testing.T) {
	pf := &packet.Packet{FrameTimeEpoch: "1747997000.123456"}
	tf, err := pf.SniffTime()
	require.NoError(t, err)
	require.Equal(t, int64(1747997000), tf.Unix())

	pi := &packet.Packet{FrameTimeEpoch: "2025-05-23T10:43:13.726858000Z"}
	ti, err := pi.SniffTime()
	require.NoError(t, err)
	require.Equal(t, 2025, ti.UTC().Year())

	require.Equal(t, "1747997000.123456", pf.SniffTimestamp())
}
```

- [ ] **Step 2: Run** `go test ./packet/ -run TestSniffTimeFormats -v` → FAIL.

- [ ] **Step 3: Implement** — replace `SniffTime`, add `SniffTimestamp`:

```go
// SniffTimestamp returns the raw capture timestamp string (frame.time_epoch).
func (p *Packet) SniffTimestamp() string { return p.FrameTimeEpoch }

// SniffTime returns the packet's capture time, accepting either a float epoch
// or an ISO-8601 timestamp (tshark renders absolute times per the time-format pref).
func (p *Packet) SniffTime() (time.Time, error) {
	s := p.FrameTimeEpoch
	if s == "" {
		s = p.FrameTime
	}
	if s == "" {
		return time.Time{}, fmt.Errorf("sniff time not available")
	}
	if epoch, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(epoch)
		nsec := int64((epoch - float64(sec)) * 1e9)
		return time.Unix(sec, nsec), nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse sniff time %q", s)
}
```

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `fix(packet): accept float and ISO-8601 sniff timestamps`.

---

### Task 4: XML parser — drop fake-field-wrapper, populate frame number

tshark PDML wraps anonymous fields in `<proto name="fake-field-wrapper">`. pyshark filters these. The XML path also already sets `FrameNumber` from the packet attr (correct) — verify it survives.

**Files:**
- Modify: `tshark/parser_xml.go` (`ConvertPDMLPacket` lines 98-121)
- Test: `tshark/parser_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestXMLDropsFakeFieldWrapper(t *testing.T) {
	xmlData := `<pdml><packet num="1">
<proto name="frame"><field name="frame.number" show="1"/><field name="frame.len" show="119"/></proto>
<proto name="ip"><field name="ip.src" show="127.0.0.1"/></proto>
<proto name="tcp"><field name="tcp.srcport" show="58894"/></proto>
<proto name="fake-field-wrapper"><field name="text" show="junk"/></proto>
</packet></pdml>`
	parser := NewXMLParser()
	pkts, err := parser.ParsePackets(strings.NewReader(xmlData))
	require.NoError(t, err)
	require.Len(t, pkts, 1)
	for _, l := range pkts[0].Layers {
		require.NotEqual(t, "fake-field-wrapper", l.Name)
	}
	require.Equal(t, "1", pkts[0].FrameNumber)
	require.Equal(t, "tcp", pkts[0].HighestLayer())
}
```

- [ ] **Step 2: Run** `go test ./tshark/ -run TestXMLDropsFakeFieldWrapper -v` → FAIL.

- [ ] **Step 3: Implement** — in `ConvertPDMLPacket`, skip wrapper protos inside the layer loop:

```go
	for _, pdmlProto := range pdmlPacket.Layers {
		if pdmlProto.Name == "fake-field-wrapper" || pdmlProto.Name == "" {
			continue
		}
		layer, err := p.convertPDMLProto(&pdmlProto)
		...
```

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `fix(tshark): drop PDML fake-field-wrapper layers`.

---

### Task 5: Phase-1 sanity over real test.pcap

- [ ] **Step 1:** Create `_debugcmd/main.go` (temporary) running `FileCapture` over `test.pcap` for both JSON and XML, printing `FrameNumber`, `HighestLayer()`, layer names, `SniffTime()`.
- [ ] **Step 2: Run** `go run ./_debugcmd/`. Expected: non-empty frame numbers, layer order `frame null ip tcp [data]`, highest layer `tcp`/`data` (not `fake-field-wrapper`), non-zero sniff time.
- [ ] **Step 3:** `rm -rf _debugcmd`. No commit (throwaway).

---

## Phase 2 — Test realignment

### Task 6: Rewrite fabricated JSON fixtures in parser_test.go

`tshark/parser_test.go:20` uses `"frame.number": [{"value": "1"}]` — a format tshark never emits.

**Files:**
- Modify: `tshark/parser_test.go` (JSON test fixtures)

- [ ] **Step 1:** Replace every `[{"value": "X"}]` field literal with the real form `"X"` (plain string). For nested field trees use `{"sub.field":"X", ...}`. Keep test assertions; adjust expected values if the fabricated format implied wrong nesting.
- [ ] **Step 2: Run** `go test ./tshark/ -v` → all PASS.
- [ ] **Step 3: Commit** `test(tshark): replace fabricated JSON fixtures with real tshark format`.

---

### Task 7: Rewrite fabricated fixtures in packet tests

**Files:**
- Modify: `packet/packet_test.go`, `tests/packet/packet_test.go` (any `[{"value":...}]` fixtures)

- [ ] **Step 1:** `grep -rn '"value"' packet/ tests/packet/` — replace fabricated fixtures with real tshark JSON shape (plain-string field values, ordered layers object).
- [ ] **Step 2: Run** `go test ./packet/... ./tests/packet/... -v` → all PASS.
- [ ] **Step 3: Commit** `test(packet): align packet fixtures with real tshark JSON`.

---

### Task 8: Real-tshark integration tests over test.pcap

**Files:**
- Create: `capture/integration_test.go`

- [ ] **Step 1: Write the tests.** Use a helper that skips when tshark is absent:

```go
package capture

import (
	"context"
	"testing"
	"GoShark/packet"
	"GoShark/tshark"
	"github.com/stretchr/testify/require"
)

func requireTShark(t *testing.T) {
	t.Helper()
	if _, err := tshark.FindTShark(); err != nil {
		t.Skip("tshark not installed; skipping integration test")
	}
}

func TestFileCaptureIntegrationJSON(t *testing.T) {
	requireTShark(t)
	fc, err := NewFileCapture("../test.pcap")
	require.NoError(t, err)
	var pkts []*packet.Packet
	require.NoError(t, fc.ApplyOnPackets(func(p *packet.Packet) bool {
		pkts = append(pkts, p); return false
	}, context.Background()))
	require.Equal(t, 5, len(pkts))
	require.Equal(t, "1", pkts[0].FrameNumber)
	require.NotEmpty(t, pkts[0].FrameLen)
	require.Equal(t, "frame", pkts[0].Layers[0].Name)
	require.Equal(t, "tcp", pkts[0].TransportLayer())
	st, err := pkts[0].SniffTime()
	require.NoError(t, err)
	require.False(t, st.IsZero())
}

func TestFileCaptureIntegrationXML(t *testing.T) {
	requireTShark(t)
	fc, err := NewFileCapture("../test.pcap", WithUseJSON(false))
	require.NoError(t, err)
	var pkts []*packet.Packet
	require.NoError(t, fc.ApplyOnPackets(func(p *packet.Packet) bool {
		pkts = append(pkts, p); return false
	}, context.Background()))
	require.Equal(t, 5, len(pkts))
	require.Equal(t, "1", pkts[0].FrameNumber)
	for _, l := range pkts[0].Layers {
		require.NotEqual(t, "fake-field-wrapper", l.Name)
	}
}
```

Add a `TestInMemCaptureIntegration` feeding raw bytes of one packet from `test.pcap` (read via `tshark -r test.pcap -c1 -w - -F pcap` is overkill — instead extract one frame's raw bytes with the existing `GetRawPacket()` from a JSON capture and round-trip through `FeedPacket`). Add a `TestPipeCaptureIntegration` opening `test.pcap` as an `io.Reader`.

- [ ] **Step 2: Run** `go test ./capture/ -run Integration -v` → all PASS (or SKIP without tshark).
- [ ] **Step 3: Commit** `test(capture): add real-tshark integration tests over test.pcap`.

---

## Phase 3 — pyshark API parity

### Task 9: Capture packet buffering — KeepPackets, LoadPackets, Packets, Len, Get, Next, Close

pyshark's `Capture` keeps packets in a list (`keep_packets=True`) and supports `len()`, indexing, `load_packets()`, `next()`, `close()`.

**Files:**
- Modify: `capture/capture.go` (add fields to `Capture`; add methods)
- Modify: `capture/capture.go` `WithUseJSON` area — add `WithKeepPackets`
- Test: `capture/capture_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestCaptureLoadPackets(t *testing.T) {
	if _, err := tshark.FindTShark(); err != nil { t.Skip("no tshark") }
	fc, err := NewFileCapture("../test.pcap")
	require.NoError(t, err)
	pkts, err := fc.LoadPackets(context.Background(), 3)
	require.NoError(t, err)
	require.Len(t, pkts, 3)
	require.Equal(t, 3, fc.Len())
	require.Equal(t, "2", fc.Get(1).FrameNumber)
}
```

(`LoadPackets`/`Len`/`Get` live on the base `Capture`; `FileCapture` embeds it, so `fc.LoadPackets` resolves. `LoadPackets` needs the capture's `Start` — pass it the same `startFunc` pattern `ApplyOnPackets` uses. For `FileCapture` add a thin `LoadPackets` wrapper mirroring its `ApplyOnPackets` wrapper.)

- [ ] **Step 2: Run** → FAIL (undefined).

- [ ] **Step 3: Implement.** Add to the `Capture` struct: `KeepPackets bool` (default true), `packets []*packet.Packet`, `debug bool`. Add `WithKeepPackets(bool) Option`. Add base methods:

```go
// LoadPackets eagerly captures up to count packets (0 = all) and buffers them.
func (c *Capture) LoadPackets(ctx context.Context, count int,
	startFunc func() (io.ReadCloser, io.ReadCloser, error)) ([]*packet.Packet, error) {
	c.packets = nil
	n := 0
	err := c.ApplyOnPackets(func(p *packet.Packet) bool {
		if c.KeepPackets {
			c.packets = append(c.packets, p)
		}
		n++
		return count > 0 && n >= count
	}, ctx, startFunc)
	return c.packets, err
}

// Len returns the number of buffered packets.
func (c *Capture) Len() int { return len(c.packets) }

// Get returns the i-th buffered packet, or nil if out of range.
func (c *Capture) Get(i int) *packet.Packet {
	if i < 0 || i >= len(c.packets) { return nil }
	return c.packets[i]
}

// Packets returns all buffered packets.
func (c *Capture) Packets() []*packet.Packet { return c.packets }

// SetDebug toggles debug logging of tshark stderr.
func (c *Capture) SetDebug(on bool) { c.debug = on }

// Close stops the tshark process if running.
func (c *Capture) Close() error { return c.Stop() }
```

`NewCapture` sets `KeepPackets: true`. Add a `FileCapture.LoadPackets(ctx, count)` wrapper calling `c.Capture.LoadPackets(ctx, count, c.Start)`. Make `Capture.Stop()` tolerate a nil process by returning nil instead of an error (so `Close()` is safe pre-start) — change `return fmt.Errorf(...)` to `return nil` in the nil-process branch.

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `feat(capture): add packet buffering — LoadPackets/Len/Get/Packets/Close`.

---

### Task 10: ApplyOnPackets honors packet_count and timeout

pyshark's `apply_on_packets` accepts `packet_count` and `timeout`.

**Files:**
- Modify: `capture/capture.go` (`ApplyOnPackets` lines 421-447)
- Test: `capture/sniff_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestApplyOnPacketsCount(t *testing.T) {
	if _, err := tshark.FindTShark(); err != nil { t.Skip("no tshark") }
	fc, _ := NewFileCapture("../test.pcap")
	n := 0
	err := fc.ApplyOnPacketsWithLimit(func(p *packet.Packet) bool { n++; return false },
		context.Background(), 2, 0)
	require.NoError(t, err)
	require.Equal(t, 2, n)
}
```

- [ ] **Step 2: Run** → FAIL (undefined).

- [ ] **Step 3: Implement.** Add a base `ApplyOnPacketsWithLimit(callback, ctx, packetCount int, timeout time.Duration, startFunc)` that wraps `ApplyOnPackets`: derive a child context with `context.WithTimeout` when `timeout > 0`, and stop after `packetCount` callbacks. Add a `FileCapture.ApplyOnPacketsWithLimit(callback, ctx, packetCount, timeout)` wrapper passing `c.Start`. Keep the existing `ApplyOnPackets` signature unchanged for back-compat.

```go
func (c *Capture) ApplyOnPacketsWithLimit(callback func(*packet.Packet) bool,
	ctx context.Context, packetCount int, timeout time.Duration,
	startFunc func() (io.ReadCloser, io.ReadCloser, error)) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	n := 0
	err := c.ApplyOnPackets(func(p *packet.Packet) bool {
		n++
		stop := callback(p)
		return stop || (packetCount > 0 && n >= packetCount)
	}, ctx, startFunc)
	if err == context.DeadlineExceeded {
		return nil // timeout is a normal stop condition
	}
	return err
}
```

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `feat(capture): packet_count and timeout limits for ApplyOnPackets`.

---

### Task 11: Packet.String / PrettyPrint, InterfaceCaptured, prefix-aware accessors

**Files:**
- Modify: `packet/packet.go` (add methods)
- Modify: `packet/layer.go` (add prefix-aware `Field`)
- Test: `packet/packet_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestPacketPrettyAndAccessors(t *testing.T) {
	data := []byte(`[{"_source":{"layers":{
"frame":{"frame.number":"1","frame.interface_name":"lo0"},
"tcp":{"tcp.srcport":"58894"}}}}]`)
	p, _ := packet.NewPacketFromJSON(data)
	require.Contains(t, p.String(), "Layer TCP")
	require.Equal(t, "lo0", p.InterfaceCaptured())
	require.Equal(t, "58894", p.Layer("tcp").Field("srcport"))
	require.Equal(t, "58894", p.Layer("tcp").Field("tcp.srcport"))
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.**

In `packet/packet.go`:
```go
// Layer is an alias for GetLayer (pyshark-style accessor).
func (p *Packet) Layer(name string) *Layer { return p.GetLayer(name) }

// InterfaceCaptured returns the capture interface name/id from the frame layer.
func (p *Packet) InterfaceCaptured() string {
	f := p.GetLayer("frame")
	if f == nil { return "" }
	for _, k := range []string{"frame.interface_name", "frame.interface_id", "frame.interface_description"} {
		if v, ok := f.Fields[k]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// String renders the packet layer-by-layer (pyshark pretty_print equivalent).
func (p *Packet) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Packet (frame %s)\n", p.FrameNumber)
	for i := range p.Layers {
		b.WriteString(p.Layers[i].PrettyPrint())
	}
	return b.String()
}

// PrettyPrint is an alias for String.
func (p *Packet) PrettyPrint() string { return p.String() }
```

In `packet/layer.go`, make `PrettyPrint` upper-case the layer name in its header (`Layer TCP:`), and add a prefix-aware getter:
```go
// Field looks up a field by short or fully-qualified name. "srcport" on a
// "tcp" layer resolves "tcp.srcport"; a name already containing "." is used as-is.
func (l *Layer) Field(name string) interface{} {
	if v, ok := l.Fields[name]; ok { return v }
	if !strings.Contains(name, ".") {
		if v, ok := l.Fields[l.Name+"."+name]; ok { return v }
	}
	return nil
}
```

Update `Layer.PrettyPrint` header line to `fmt.Sprintf("Layer %s:\n", strings.ToUpper(l.Name))`. Add `"strings"` import to `layer.go` if missing.

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `feat(packet): String/PrettyPrint, InterfaceCaptured, prefix-aware field access`.

---

### Task 12: Wire the EK output path into the capture stream

`-T ek` emits newline-delimited JSON: alternating index lines (`{"index":{...}}`) and packet lines (`{"timestamp":"...","layers":{...}}`). `EKParser` exists but `sniffStream` only handles JSON and XML.

**Files:**
- Modify: `capture/capture.go` (`Capture` struct: add `UseEK`; `getTSharkArgs`; `sniffStream`)
- Modify: `capture/capture.go` (add `WithUseEK` option)
- Test: `capture/sniff_test.go`

- [ ] **Step 1: Write failing test** — `TestSniffStreamEK` feeding the EK stream of `test.pcap` (`tshark -r test.pcap -T ek`) through a capture configured with `WithUseEK(true)`, asserting 5 packets with non-empty layers. Skip without tshark.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.**
- Add `UseEK bool` to the `Capture` struct and a `WithUseEK(bool) Option` mirroring `WithUseJSON`.
- In `getTSharkArgs`, branch first on `c.UseEK` → `args = append(args, "-T", "ek")`, else the existing JSON/PDML branches.
- In `sniffStream`, add a leading `if c.UseEK { ... }` branch: read stdout line-by-line with `bufio.Scanner`, skip blank lines and lines whose JSON has a top-level `"index"` key, and for packet lines call the existing EK parse path (`tshark.NewEKParser().ParseSinglePacket(line)` or equivalent — check `parser_ek.go` for the exact single-record entry point) and send to `outChan`, honoring `ctx`.

- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `feat(capture): wire EK (-T ek) output into the streaming parser`.

---

### Task 13: Layer PrettyPrint parity across Json/Xml/Ek concrete layers

**Files:**
- Modify: `packet/layers/json_layer.go`, `xml_layer.go`, `ek_layer.go` as needed
- Test: `packet/layers/layers_test.go`

- [ ] **Step 1:** Check each concrete layer exposes a working `PrettyPrint()`/`String()` and `FieldNames()`. Write a test asserting `NewJSONLayer(...).PrettyPrint()` and the XML/EK equivalents return a non-empty, field-listing string.
- [ ] **Step 2: Run** → FAIL for any gap.
- [ ] **Step 3:** Implement the missing `PrettyPrint`/`String` on whichever concrete layer lacks it, matching the pattern of the one that has it. Do not touch the `base.go` panics — they are abstract-method guards by design.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(layers): PrettyPrint parity across JSON/XML/EK layers`.

---

## Phase 4 — Capture-type validation & polish

### Task 14: Argument-construction tests for Live/Remote/LiveRing

**Files:**
- Modify: `capture/capture_test.go` (or a new `capture/args_test.go`)

- [ ] **Step 1: Write tests** asserting generated argument vectors:
  - `LiveCapture` with `WithBPFFilter("tcp")` → dumpcap params include `-f tcp` (call `getDumpcapParameters()`).
  - `RemoteCapture("host","eth0", WithRemotePort(2002))` → interface is `rpcap://host:2002/eth0` (inspect via `String()`).
  - `LiveRingCapture` with `WithRingFileSize(1024)`, `WithNumRingFiles(3)` → dumpcap params include `-b filesize:1024` and `-b files:3` (match the exact strings produced in `live_ring_capture.go`).
- [ ] **Step 2: Run** `go test ./capture/ -run Args -v` → PASS (adjust expected strings to match actual code).
- [ ] **Step 3: Commit** `test(capture): argument-construction coverage for Live/Remote/LiveRing`.

---

### Task 15: Fix the main.go demo

`main.go` opens `non_existent.pcap` and so always fails.

**Files:**
- Modify: `main.go`

- [ ] **Step 1:** Replace `non_existent.pcap` with `test.pcap`. Simplify the hand-rolled goroutine soup to use `FileCapture.ApplyOnPackets` (the supported API). Print per packet: frame number, length, highest layer, transport layer, sniff time, and `tcp.srcport`/`tcp.dstport` via the new prefix-aware `Layer("tcp").Field("srcport")`.
- [ ] **Step 2: Run** `go run .` → prints `TShark Version: vX.Y.Z` then 5 packets, exit 0.
- [ ] **Step 3: Commit** `fix(main): working test.pcap demo using the supported capture API`.

---

### Task 16: Final verification

- [ ] **Step 1: Run** `go build ./...` → no output.
- [ ] **Step 2: Run** `go vet ./...` → no output.
- [ ] **Step 3: Run** `gofmt -l .` → no files listed (format any that are).
- [ ] **Step 4: Run** `go test ./...` → all packages `ok` (integration tests run, not skipped, since tshark is present).
- [ ] **Step 5: Run** `go run .` → succeeds.
- [ ] **Step 6: Commit** any formatting fixes; `chore: final verification — build, vet, fmt, tests clean`.

---

## Self-review notes

- **Spec coverage:** bug #1 → Task 1; #2 (frame metadata) → Task 2; #3 (layer order) → Task 2; #4 (SniffTime) → Task 3; #5 (fake-field-wrapper) → Task 4. Test realignment → Tasks 6–8. API parity: indexing/len/load_packets → Task 9; packet_count/timeout → Task 10; pretty_print/attribute access/interface_captured → Task 11; EK path → Task 12; layer parity → Task 13. Capture-type validation → Tasks 8 & 14. `main.go` → Task 15. Final gate → Task 16. All spec sections covered.
- **Type consistency:** `LoadPackets`, `Len`, `Get`, `Packets`, `Close`, `SetDebug`, `ApplyOnPacketsWithLimit`, `Layer`, `Field`, `InterfaceCaptured`, `String`, `PrettyPrint`, `SniffTimestamp`, `WithKeepPackets`, `WithUseEK` are each defined once and referenced consistently.
- **tshark dependency:** integration tests skip cleanly via `requireTShark`/`FindTShark` when tshark is absent.
