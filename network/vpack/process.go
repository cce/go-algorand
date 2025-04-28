package vpack

import "fmt"

type voteMapType uint8

const (
	mapUnauthenticatedVote voteMapType = iota
	mapUnauthenticatedCredential
	mapRawVote
	mapProposalValue
	mapOneTimeSignature
)

type voteProcessor interface {
	beginMap(voteMapType) error
	has(string) (bool, error)

	varuint(voteValueType) error
	bin32(voteValueType) error
	bin64(voteValueType) error
	bin80(voteValueType) error

	done() error
}

func processVote(src []byte, c compressWriter) error {
	p := newVoteParser(src, c)
	var present bool
	var err error

	// Parse unauthenticatedVote
	if err := p.beginMap(mapUnauthenticatedVote); err != nil {
		return fmt.Errorf("reading map for unauthenticatedVote: %w", err)
	}
	// Required field for unauthenticatedVote: cred
	if present, err = p.has("cred"); err != nil || !present {
		return fmt.Errorf("missing required field cred")
	}

	// Parse UnauthenticatedCredential
	if err := p.beginMap(mapUnauthenticatedCredential); err != nil {
		return fmt.Errorf("reading map for UnauthenticatedCredential: %w", err)
	}
	// Required field for UnauthenticatedCredential: pf
	if present, err = p.has("pf"); err != nil || !present {
		return fmt.Errorf("missing required field pf")
	}
	if err := p.bin80(credPfVoteValue); err != nil {
		return fmt.Errorf("reading pf for UnauthenticatedCredential: %w", err)
	}

	// Required field for unauthenticatedVote: r
	if present, err = p.has("r"); err != nil || !present {
		return fmt.Errorf("missing required field r")
	}

	// Parse rawVote
	if err := p.beginMap(mapRawVote); err != nil {
		return fmt.Errorf("reading map for rawVote: %w", err)
	}
	present, err = p.has("per")
	if err != nil {
		return fmt.Errorf("reading per for rawVote: %w", err)
	}
	if present { // optional field
		if err := p.varuint(rPerVoteValue); err != nil {
			return fmt.Errorf("reading per for rawVote: %w", err)
		}
	}
	present, err = p.has("prop")
	if err != nil {
		return fmt.Errorf("reading prop for rawVote: %w", err)
	}
	if present { // optional field
		// Parse proposalValue
		if err := p.beginMap(mapProposalValue); err != nil {
			return fmt.Errorf("reading map for proposalValue: %w", err)
		}
		present, err = p.has("dig")
		if err != nil {
			return fmt.Errorf("reading dig for proposalValue: %w", err)
		}
		if present { // optional field
			if err := p.bin32(rPropDigVoteValue); err != nil {
				return fmt.Errorf("reading dig for proposalValue: %w", err)
			}
		}
		present, err = p.has("encdig")
		if err != nil {
			return fmt.Errorf("reading encdig for proposalValue: %w", err)
		}
		if present { // optional field
			if err := p.bin32(rPropEncdigVoteValue); err != nil {
				return fmt.Errorf("reading encdig for proposalValue: %w", err)
			}
		}

		present, err = p.has("oper")
		if err != nil {
			return fmt.Errorf("reading oper for proposalValue: %w", err)
		}
		if present { // optional field
			if err := p.varuint(rPropOperVoteValue); err != nil {
				return fmt.Errorf("reading oper for proposalValue: %w", err)
			}
		}

		present, err = p.has("oprop")
		if err != nil {
			return fmt.Errorf("reading oprop for proposalValue: %w", err)
		}
		if present { // optional field
			if err := p.bin32(rPropOpropVoteValue); err != nil {
				return fmt.Errorf("reading oprop for proposalValue: %w", err)
			}
		}
	}

	if present, err = p.has("rnd"); err != nil || !present {
		return fmt.Errorf("missing required field rnd")
	}
	if err := p.varuint(rRndVoteValue); err != nil {
		return fmt.Errorf("reading rnd for rawVote: %w", err)
	}

	if present, err = p.has("snd"); err != nil || !present {
		return fmt.Errorf("missing required field snd")
	}
	if err := p.bin32(rSndVoteValue); err != nil {
		return fmt.Errorf("reading snd for rawVote: %w", err)
	}

	present, err = p.has("step")
	if err != nil {
		return fmt.Errorf("reading step for rawVote: %w", err)
	}
	if present { // optional field
		if err := p.varuint(rStepVoteValue); err != nil {
			return fmt.Errorf("reading step for rawVote: %w", err)
		}
	}

	// Required field for unauthenticatedVote: sig
	if present, err = p.has("sig"); err != nil || !present {
		return fmt.Errorf("missing required field sig")
	}

	// Parse OneTimeSignature
	if err := p.beginMap(mapOneTimeSignature); err != nil {
		return fmt.Errorf("reading map for OneTimeSignature: %w", err)
	}
	// Required field for OneTimeSignature: p
	if present, err = p.has("p"); err != nil || !present {
		return fmt.Errorf("missing required field p")
	}
	if err := p.bin32(sigPVoteValue); err != nil {
		return fmt.Errorf("reading p for OneTimeSignature: %w", err)
	}

	// Required field for OneTimeSignature: p1s
	if present, err = p.has("p1s"); err != nil || !present {
		return fmt.Errorf("missing required field p1s")
	}
	if err := p.bin64(sigP1sVoteValue); err != nil {
		return fmt.Errorf("reading p1s for OneTimeSignature: %w", err)
	}

	// Required field for OneTimeSignature: p2
	if present, err = p.has("p2"); err != nil || !present {
		return fmt.Errorf("missing required field p2")
	}
	if err := p.bin32(sigP2VoteValue); err != nil {
		return fmt.Errorf("reading p2 for OneTimeSignature: %w", err)
	}

	// Required field for OneTimeSignature: p2s
	if present, err = p.has("p2s"); err != nil || !present {
		return fmt.Errorf("missing required field p2s")
	}
	if err := p.bin64(sigP2sVoteValue); err != nil {
		return fmt.Errorf("reading p2s for OneTimeSignature: %w", err)
	}

	// Required field for OneTimeSignature: ps
	if present, err = p.has("ps"); err != nil || !present {
		return fmt.Errorf("missing required field ps")
	}
	if err := p.bin64(sigPsVoteValue); err != nil {
		return fmt.Errorf("reading ps for OneTimeSignature: %w", err)
	}

	// Required field for OneTimeSignature: s
	if present, err = p.has("s"); err != nil || !present {
		return fmt.Errorf("missing required field s")
	}
	if err := p.bin64(sigSVoteValue); err != nil {
		return fmt.Errorf("reading s for OneTimeSignature: %w", err)
	}

	if err = p.done(); err != nil {
		return err
	}
	return nil
}
