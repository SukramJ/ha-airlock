// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package changes_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/changes"
)

var start = time.Unix(1_800_000_000, 0).UTC()

func open(t *testing.T, path string) *changes.Journal {
	t.Helper()
	tick := 0
	j, err := changes.Open(path, func() time.Time {
		tick++
		return start.Add(time.Duration(tick) * time.Second)
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return j
}

func update(object string) changes.Change {
	return changes.Change{
		Client: "https://client.test/metadata.json", Tool: "input_boolean_update", Kind: "input_boolean", Object: object,
		Before: json.RawMessage(`{"name":"Old"}`), After: json.RawMessage(`{"name":"New"}`),
	}
}

func TestRecordedChangeIsOnDiskWithBothStatesWhenRecordReturns(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "changes.json")
	recorded, err := open(t, path).Record(context.Background(), update("guest_mode"))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if recorded.ID == "" || recorded.Time.IsZero() {
		t.Fatalf("recorded change has no id or time: %+v", recorded)
	}

	// A second journal over the same file sees what the first one wrote.
	got, ok := open(t, path).Get(recorded.ID)
	if !ok || string(got.Before) != `{"name":"Old"}` || string(got.After) != `{"name":"New"}` ||
		got.Kind != "input_boolean" || got.Object != "guest_mode" || !got.Time.Equal(recorded.Time) {
		t.Fatalf("after reopening: found = %t, %+v", ok, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v, want 0600: it holds unredacted configuration", info.Mode().Perm())
	}
}

func TestChangeThatCannotBeWrittenIsNotRecorded(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	j := open(t, filepath.Join(dir, "changes.json"))
	if _, err := j.Record(context.Background(), update("kept")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := j.Record(context.Background(), update("lost")); err == nil {
		t.Fatal("a change was recorded although the journal could not be written")
	}
	if got := j.List(); len(got) != 1 || got[0].Object != "kept" {
		t.Fatalf("journal after the failed record = %+v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.Record(ctx, update("late")); !errors.Is(err, context.Canceled) {
		t.Fatalf("record with a cancelled context: %v", err)
	}
}

func TestChangeWithoutAnyStateIsRefused(t *testing.T) {
	t.Parallel()
	j := open(t, filepath.Join(t.TempDir(), "changes.json"))
	c := update("nothing")
	c.Before, c.After = nil, nil
	if _, err := j.Record(context.Background(), c); !errors.Is(err, changes.ErrEmpty) {
		t.Fatalf("err = %v, want ErrEmpty", err)
	}
	// A creation has no state before, a deletion none after.
	creation := update("created")
	creation.Before = nil
	deletion := update("deleted")
	deletion.After = nil
	for _, c := range []changes.Change{creation, deletion} {
		if _, err := j.Record(context.Background(), c); err != nil {
			t.Fatalf("record %s: %v", c.Object, err)
		}
	}
}

func TestJournalKeepsTheNewestChangesNewestFirst(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "changes.json")
	j := open(t, path)
	for i := range changes.Keep + 3 {
		if _, err := j.Record(context.Background(), update(fmt.Sprintf("helper_%03d", i))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	for name, list := range map[string][]changes.Change{"in memory": j.List(), "on disk": open(t, path).List()} {
		if len(list) != changes.Keep {
			t.Fatalf("%s: %d changes, want %d", name, len(list), changes.Keep)
		}
		if first, last := list[0].Object, list[len(list)-1].Object; first != fmt.Sprintf("helper_%03d", changes.Keep+2) || last != "helper_003" {
			t.Fatalf("%s: newest %s, oldest %s", name, first, last)
		}
	}
}

func TestUndoIsNotedOnceAndSurvivesReopening(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "changes.json")
	j := open(t, path)
	recorded, err := j.Record(context.Background(), update("guest_mode"))
	if err != nil {
		t.Fatal(err)
	}

	if err := j.MarkUndone(context.Background(), "no-such-id", "admin"); !errors.Is(err, changes.ErrUnknown) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := j.MarkUndone(context.Background(), recorded.ID, "admin-user-id"); err != nil {
		t.Fatalf("mark undone: %v", err)
	}
	if err := j.MarkUndone(context.Background(), recorded.ID, "someone-else"); !errors.Is(err, changes.ErrUndone) {
		t.Fatalf("second undo: %v", err)
	}
	got, ok := open(t, path).Get(recorded.ID)
	if !ok || got.Undone == nil || got.Undone.By != "admin-user-id" || got.Undone.Time.IsZero() {
		t.Fatalf("after reopening: %+v", got)
	}
}

func TestWhatTheJournalHandsOutCannotChangeWhatItHolds(t *testing.T) {
	t.Parallel()
	j := open(t, filepath.Join(t.TempDir(), "changes.json"))
	given := update("guest_mode")
	recorded, err := j.Record(context.Background(), given)
	if err != nil {
		t.Fatal(err)
	}
	given.Before[2] = 'X'
	recorded.After[2] = 'X'
	j.List()[0].Before[3] = 'X'

	got, _ := j.Get(recorded.ID)
	if string(got.Before) != `{"name":"Old"}` || string(got.After) != `{"name":"New"}` {
		t.Fatalf("the journal's states were changed from outside: %s / %s", got.Before, got.After)
	}
}

func TestJournalThatCannotBeReadIsAnErrorNotAnEmptyJournal(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "changes.json")
	if err := os.WriteFile(path, []byte(`[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := changes.Open(path, time.Now); err == nil {
		t.Fatal("a torn journal was opened as if it were empty")
	}
}

func TestHashIsOfTheJSONValueNotOfItsSpelling(t *testing.T) {
	t.Parallel()
	hash := func(s string) string {
		t.Helper()
		h, err := changes.Hash(json.RawMessage(s))
		if err != nil {
			t.Fatalf("hash %s: %v", s, err)
		}
		return h
	}
	if hash(`{"a":1,"b":[true,null]}`) != hash(` { "b" : [ true , null ], "a" : 1 } `) {
		t.Fatal("key order or spacing changed the hash")
	}
	for _, other := range []string{`{"a":1.0,"b":[true,null]}`, `{"a":1,"b":[null,true]}`, `{"a":"1","b":[true,null]}`, `{"a":1}`} {
		if hash(other) == hash(`{"a":1,"b":[true,null]}`) {
			t.Errorf("%s has the hash of a different value", other)
		}
	}
	if hash("") != changes.Absent || hash("  ") != changes.Absent || hash("null") == changes.Absent {
		t.Fatal("an absent state and the value null are not told apart")
	}
	for _, bad := range []string{`{"a":`, `{} {}`} {
		if _, err := changes.Hash(json.RawMessage(bad)); err == nil {
			t.Errorf("%s was hashed", bad)
		}
	}
}

// How a write ended is noted on its change: a creation learns the object's
// identifier, a failed write says why.
func TestSettleNotesTheObjectOrTheFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "changes.json")
	j := open(t, path)
	creation := update("")
	creation.Before = nil
	created, err := j.Record(context.Background(), creation)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := j.Record(context.Background(), update("input_boolean.guest"))
	if err != nil {
		t.Fatal(err)
	}

	if err := j.Settle(context.Background(), created.ID, "input_boolean.new", "", json.RawMessage(`{"name":"New","step":1}`)); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if err := j.Settle(context.Background(), failed.ID, "", "home assistant refused", nil); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if err := j.Settle(context.Background(), "no-such-id", "x", "", nil); !errors.Is(err, changes.ErrUnknown) {
		t.Fatalf("unknown id: %v", err)
	}

	reopened := open(t, path)
	if got, _ := reopened.Get(created.ID); got.Object != "input_boolean.new" || got.Failed != "" {
		t.Fatalf("creation after settling: %+v", got)
	}
	if got, _ := reopened.Get(created.ID); string(got.Left) != `{"name":"New","step":1}` || string(got.Held()) != string(got.Left) {
		t.Fatalf("state read back after the creation: %+v", got)
	}
	if got, _ := reopened.Get(failed.ID); got.Left != nil || string(got.Held()) != string(got.After) {
		t.Fatalf("state of the failed change: %+v", got)
	}
	if got, _ := reopened.Get(failed.ID); got.Object != "input_boolean.guest" || got.Failed != "home assistant refused" {
		t.Fatalf("failed change after settling: %+v", got)
	}
}
