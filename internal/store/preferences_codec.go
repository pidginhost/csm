package store

import "encoding/json"

func encodeUndoEntry(e UndoEntry) ([]byte, error) {
	return json.Marshal(e)
}

func decodeUndoEntry(raw []byte) (UndoEntry, error) {
	var e UndoEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return UndoEntry{}, err
	}
	return e, nil
}
