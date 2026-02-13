package cluster

import (
	"fmt"
	"io"

	"unflutter/internal/dartfmt"
)

// TraceEntry records one read operation with its byte offset range and value.
type TraceEntry struct {
	Frame    string
	Label    string
	StartOff int
	EndOff   int
	Value    int64
}

// TracingStream wraps a dartfmt.Stream with offset tracking and frame context.
type TracingStream struct {
	*dartfmt.Stream
	entries []TraceEntry
	frames  []string
	marks   [16]int
	markIdx int
	enabled bool
}

// NewTracingStream wraps a stream with tracing. If enabled is false,
// read methods delegate directly with no overhead.
func NewTracingStream(s *dartfmt.Stream, enabled bool) *TracingStream {
	return &TracingStream{Stream: s, enabled: enabled}
}

// PushFrame pushes a logical context frame (e.g. "cluster[3]/String/alloc").
func (ts *TracingStream) PushFrame(label string) {
	if !ts.enabled {
		return
	}
	ts.frames = append(ts.frames, label)
}

// PopFrame removes the top frame.
func (ts *TracingStream) PopFrame() {
	if !ts.enabled || len(ts.frames) == 0 {
		return
	}
	ts.frames = ts.frames[:len(ts.frames)-1]
}

// Mark records the current position in a ring buffer for debugging.
func (ts *TracingStream) Mark() {
	if !ts.enabled {
		return
	}
	ts.marks[ts.markIdx%len(ts.marks)] = ts.Position()
	ts.markIdx++
}

func (ts *TracingStream) frame() string {
	if len(ts.frames) == 0 {
		return ""
	}
	return ts.frames[len(ts.frames)-1]
}

// ReadUnsignedT reads an unsigned value and records a trace entry.
func (ts *TracingStream) ReadUnsignedT(label string) (int64, error) {
	if !ts.enabled {
		return ts.Stream.ReadUnsigned()
	}
	start := ts.Position()
	v, err := ts.Stream.ReadUnsigned()
	if err != nil {
		return v, err
	}
	ts.entries = append(ts.entries, TraceEntry{
		Frame:    ts.frame(),
		Label:    label,
		StartOff: start,
		EndOff:   ts.Position(),
		Value:    v,
	})
	return v, nil
}

// ReadTagged32T reads a tagged uint32 and records a trace entry.
func (ts *TracingStream) ReadTagged32T(label string) (uint32, error) {
	if !ts.enabled {
		return ts.Stream.ReadTagged32()
	}
	start := ts.Position()
	v, err := ts.Stream.ReadTagged32()
	if err != nil {
		return v, err
	}
	ts.entries = append(ts.entries, TraceEntry{
		Frame:    ts.frame(),
		Label:    label,
		StartOff: start,
		EndOff:   ts.Position(),
		Value:    int64(v),
	})
	return v, nil
}

// ReadTagged64T reads a tagged int64 and records a trace entry.
func (ts *TracingStream) ReadTagged64T(label string) (int64, error) {
	if !ts.enabled {
		return ts.Stream.ReadTagged64()
	}
	start := ts.Position()
	v, err := ts.Stream.ReadTagged64()
	if err != nil {
		return v, err
	}
	ts.entries = append(ts.entries, TraceEntry{
		Frame:    ts.frame(),
		Label:    label,
		StartOff: start,
		EndOff:   ts.Position(),
		Value:    v,
	})
	return v, nil
}

// Entries returns all recorded trace entries.
func (ts *TracingStream) Entries() []TraceEntry {
	return ts.entries
}

// RecentMarks returns the most recent mark positions (up to 16).
func (ts *TracingStream) RecentMarks() []int {
	n := ts.markIdx
	if n > len(ts.marks) {
		n = len(ts.marks)
	}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		idx := (ts.markIdx - n + i) % len(ts.marks)
		out[i] = ts.marks[idx]
	}
	return out
}

// DumpTrace writes all entries to w in a human-readable format.
func (ts *TracingStream) DumpTrace(w io.Writer) {
	for _, e := range ts.entries {
		frame := e.Frame
		if frame != "" {
			frame += "/"
		}
		fmt.Fprintf(w, "  0x%06x..0x%06x  %s%s = %d (0x%x)\n",
			e.StartOff, e.EndOff, frame, e.Label, e.Value, e.Value)
	}
}
