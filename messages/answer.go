// Defines messages and related methods for WPIR protocol
package messages

import (
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir/settings"
)

// Defines an answer from the server
type PIRAnswer struct {
	FetchContext bool                 `json:"fetchContext"`       //flag if this was a reply to a fetch context request
	Answer       []*rlwe.Ciphertext   `json:"answer,omitempty"`   //answer
	Context      *settings.PirContext `json:"context, omitempty"` //current context used at the server for syncing
	Error        string               `json:"status"`             //to be read if !ok
	Ok           bool                 `json:"ok"`                 //if not true then error
}
