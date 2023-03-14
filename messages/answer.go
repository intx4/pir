// Defines messages and related methods for WPIR protocol
package messages

import (
	"encoding/json"
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

func (A *PIRAnswer) MarshalBinary() ([]byte, error) {
	s := struct {
		FetchContext bool                 `json:"fetchContext"`       //flag if this was a reply to a fetch context request
		Answer       [][]byte             `json:"answer,omitempty"`   //answer
		Context      *settings.PirContext `json:"context, omitempty"` //current context used at the server for syncing
		Error        string               `json:"status"`             //to be read if !ok
		Ok           bool                 `json:"ok"`                 //if not true then error
	}{
		FetchContext: A.FetchContext,
		Answer:       nil,
		Context:      A.Context,
		Error:        A.Error,
		Ok:           A.Ok,
	}
	if s.Answer != nil {
		s.Answer = make([][]byte, len(A.Answer))
		for i, a := range A.Answer {
			s.Answer[i], _ = a.MarshalBinary()
		}
	}
	return json.Marshal(s)
}
func (A *PIRAnswer) UnMarshalBinary(b []byte) error {
	s := struct {
		FetchContext bool                 `json:"fetchContext"`       //flag if this was a reply to a fetch context request
		Answer       [][]byte             `json:"answer,omitempty"`   //answer
		Context      *settings.PirContext `json:"context, omitempty"` //current context used at the server for syncing
		Error        string               `json:"status"`             //to be read if !ok
		Ok           bool                 `json:"ok"`                 //if not true then error
	}{
		FetchContext: false,
		Answer:       nil,
		Context:      nil,
		Error:        "",
		Ok:           false,
	}
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	if s.Answer != nil {
		A.Answer = make([]*rlwe.Ciphertext, len(s.Answer))
		for i, a := range s.Answer {
			A.Answer[i] = new(rlwe.Ciphertext)
			err = A.Answer[i].UnmarshalBinary(a)
			if err != nil {
				return err
			}
		}
	}
	A.Error, A.Ok, A.Context, A.FetchContext = s.Error, s.Ok, s.Context, s.FetchContext
	return nil
}
