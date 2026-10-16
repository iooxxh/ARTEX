package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) activityHistory(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	q := r.URL.Query()
	sess := q.Get("session")
	filter, ok := parseActivitySession(sess)
	if !ok {
		writeErr(w, 400, "bad session")
		return
	}
	if filter.Main && filter.MainSeg == nil { // bare "main" → the current segment
		seg, err := t.Store.CurrentMainSeg()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		filter.MainSeg = &seg
	}
	before := int64(atoiDefault(q.Get("before"), 0))
	limit := min(atoiDefault(q.Get("limit"), 200), 500) // cap so one request can't pull an unbounded slice
	store, sourceTaskID, err := activitySessionStore(t, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if store == nil {
		writeErr(w, 404, "session not found")
		return
	}
	// The browser tails only this task's broadcaster. Keep the SSE join cursor
	// local even when the opened worker transcript comes from a related task.
	snapshot, err := t.Store.ActivityMaxID()
	if err != nil {
		log.Printf("[activity/history] task=%s session=%s snapshot: %v", t.ID, sess, err)
		writeErr(w, 500, err.Error())
		return
	}
	var items []db.Activity
	var hasMore bool
	if sourceTaskID > 0 {
		// Source sessions are readable only while the intent remains terminal. The
		// DB query also removes model reasoning/accounting rows from inherited data.
		items, hasMore, err = store.ActivityPageForTerminalIntent(*filter.NodeID, before, limit)
	} else {
		items, hasMore, err = store.ActivityPage(filter, before, limit)
	}
	if err != nil {
		log.Printf("[activity/history] task=%s session=%s before=%d limit=%d: %v", t.ID, sess, before, limit, err)
		writeErr(w, 500, err.Error())
		return
	}
	if sourceTaskID > 0 {
		for i := range items {
			items[i].SourceTaskID = sourceTaskID
			items[i].Inherited = true
		}
	}
	earliest := before
	if len(items) > 0 {
		earliest = items[0].ID
	}
	writeJSON(w, 200, map[string]any{
		"items":           activityDTOs(items),
		"snapshot_cursor": snapshot,
		"earliest_cursor": earliest,
		"has_more":        hasMore,
	})
}

// tokenStats returns per-worker token usage (input/output/cache read/write) for a
// task — main agent, planner, and each work#N.
func (s *Server) streamActivity(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	var intentPtr *int64
	if iv := r.URL.Query().Get("intent"); iv != "" {
		if n, err := strconv.ParseInt(iv, 10, 64); err == nil {
			intentPtr = &n
		}
	}
	// Cursor precedence: the browser's automatic reconnect sends Last-Event-ID (the
	// last id it received) — trust it over the query so an auto-reconnect resumes
	// exactly where it dropped. A fresh/manual connect has no header and passes
	// since=<snapshot_cursor> from the history page instead.
	since := int64(atoiDefault(r.URL.Query().Get("since"), 0))
	if le := r.Header.Get("Last-Event-ID"); le != "" {
		if n, err := strconv.ParseInt(le, 10, 64); err == nil {
			since = n
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering

	// Subscribe BEFORE replaying history so events in between aren't lost; dedup the
	// overlap by skipping channel events whose id was already replayed.
	ch, unsub := s.engine.Broadcaster().Subscribe(t.ID)
	defer unsub()

	// Emit a standard SSE id: line so the browser echoes it as Last-Event-ID on
	// auto-reconnect (see cursor precedence above).
	sendSSE := func(a db.Activity) {
		b, _ := json.Marshal(activityDTO(a))
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", a.ID, b)
		flusher.Flush()
	}

	// Compensate the DB backlog after `since` in batches until caught up. This is the
	// gap between the history snapshot and the live tail — NOT the first-page history
	// (that's the /activity/history endpoint). A long task can have far more than one
	// batch, so loop instead of a single fixed read; on a query error log it and close
	// so the client reconnects and retries from its last id (broadcast is lossy — the
	// DB is the source of truth). The Broadcaster keeps buffering live events meanwhile;
	// the id<=since skip below drops any that this replay already covered.
	const replayBatch = 500
	for {
		items, cursor, err := t.Store.ActivityList(intentPtr, since, replayBatch)
		if err != nil {
			log.Printf("[activity/stream] task=%s replay since=%d: %v", t.ID, since, err)
			return
		}
		for _, a := range items {
			sendSSE(a)
		}
		if cursor > since {
			since = cursor
		}
		if len(items) < replayBatch {
			break
		}
	}
	flusher.Flush()

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-ch:
			if !ok {
				return
			}
			if a.ID <= since {
				continue // already replayed
			}
			if intentPtr != nil && (a.NodeID == nil || *a.NodeID != *intentPtr) {
				continue // scoped session: only this intent's steps
			}
			since = a.ID
			sendSSE(a)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// activityDetail lazily returns the full detail blob for one step.
