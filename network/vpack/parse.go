package vpack

import "fmt"

type voteValueType uint8

//go:generate stringer -type voteValueType
const (
	credPfVoteValue voteValueType = iota
	rPerVoteValue
	rPropDigVoteValue
	rPropEncdigVoteValue
	rPropOperVoteValue
	rPropOpropVoteValue
	rRndVoteValue
	rSndVoteValue
	rStepVoteValue
	sigP1sVoteValue
	sigP2VoteValue
	sigP2sVoteValue
	sigPVoteValue
	sigPsVoteValue
	sigSVoteValue
)

const (
	msgpFixstrCred   = "\xa4cred"
	msgpFixstrDig    = "\xa3dig"
	msgpFixstrEncdig = "\xa6encdig"
	msgpFixstrOper   = "\xa4oper"
	msgpFixstrOprop  = "\xa5oprop"
	msgpFixstrP      = "\xa1p"
	msgpFixstrP1s    = "\xa3p1s"
	msgpFixstrP2     = "\xa2p2"
	msgpFixstrP2s    = "\xa3p2s"
	msgpFixstrPer    = "\xa3per"
	msgpFixstrPf     = "\xa2pf"
	msgpFixstrProp   = "\xa4prop"
	msgpFixstrPs     = "\xa2ps"
	msgpFixstrR      = "\xa1r"
	msgpFixstrRnd    = "\xa3rnd"
	msgpFixstrS      = "\xa1s"
	msgpFixstrSig    = "\xa3sig"
	msgpFixstrSnd    = "\xa3snd"
	msgpFixstrStep   = "\xa4step"
)

type voteParser struct {
	p parser
	c compressWriter
}

func newVoteParser(voteBuf []byte, c compressWriter) *voteParser {
	return &voteParser{
		p: parser{data: voteBuf},
		c: c,
	}
}

func (p *voteParser) beginMap(mt voteMapType) error {
	cnt, err := p.p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for %d: %w", mt, err)
	}
	switch mt {
	case mapUnauthenticatedVote:
		if cnt != 3 {
			return fmt.Errorf("expected fixed map size 3 for unauthenticatedVote, got %d", cnt)
		}
	case mapUnauthenticatedCredential:
		if cnt != 1 {
			return fmt.Errorf("expected fixed map size 1 for unauthenticatedCredential, got %d", cnt)
		}
	case mapRawVote:
		if cnt < 1 || cnt > 5 {
			return fmt.Errorf("expected fixmap size for rawVote 1 <= cnt <= 5, got %d", cnt)
		}
	case mapProposalValue:
		if cnt < 1 || cnt > 4 {
			return fmt.Errorf("expected fixmap size for proposalValue 1 <= cnt <= 4, got %d", cnt)
		}
	case mapOneTimeSignature:
		if cnt != 6 {
			return fmt.Errorf("expected fixed map size 6 for OneTimeSignature, got %d", cnt)
		}
	}
	return nil
}

func (p *voteParser) has(field string) (bool, error) {
	// keep old position to "peek" for optional fields
	oldPos := p.p.pos
	key, err := p.p.readString()
	if err != nil {
		return false, fmt.Errorf("reading key: %w", err)
	}
	if string(key) == field {
		return true, nil
	}
	// no field found, unpeek
	p.p.pos = oldPos
	return false, nil
}

func (p *voteParser) varuint(v voteValueType) error {
	val, err := p.p.readUintBytes()
	if err != nil {
		return fmt.Errorf("reading varuint for %d: %w", v, err)
	}
	p.c.writeVaruint(v, val)
	return nil
}

func (p *voteParser) bin32(v voteValueType) error {
	val, err := p.p.readBin32()
	if err != nil {
		return fmt.Errorf("reading bin32 for %d: %w", v, err)
	}
	p.c.writeBin32(v, val)
	return nil
}

func (p *voteParser) bin64(v voteValueType) error {
	val, err := p.p.readBin64()
	if err != nil {
		return fmt.Errorf("reading bin64 for %d: %w", v, err)
	}
	if v == sigPsVoteValue {
		if val == [64]byte{} {
			return nil
		}
		return fmt.Errorf("expected zero ps")
	}
	p.c.writeBin64(v, val)
	return nil
}

func (p *voteParser) bin80(v voteValueType) error {
	val, err := p.p.readBin80()
	if err != nil {
		return fmt.Errorf("reading bin80 for %d: %w", v, err)
	}
	p.c.writeBin80(v, val)
	return nil
}

func (p *voteParser) done() error {
	if p.p.pos != len(p.p.data) {
		return fmt.Errorf("expected end of buffer, got %d, len %d", p.p.pos, len(p.p.data))
	}
	return nil
}

func parseVote(data []byte, c compressWriter) error {
	p := newParser(data)

	var err error
	var cnt uint8

	// Parse unauthenticatedVote
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for unauthenticatedVote: %w", err)
	}
	// Assert unauthenticatedVote struct has 3 fields
	if cnt != 3 {
		return fmt.Errorf("expected fixed map size 3 for unauthenticatedVote, got %d", cnt)
	}
	// Required field for unauthenticatedVote: cred
	if s, rErr := p.readString(); rErr != nil || string(s) != "cred" {
		return fmt.Errorf("expected string \"cred\", got %s: %w", s, rErr)
	}

	// Parse UnauthenticatedCredential
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for UnauthenticatedCredential: %w", err)
	}
	// Assert UnauthenticatedCredential struct has 1 fields
	if cnt != 1 {
		return fmt.Errorf("expected fixed map size 1 for UnauthenticatedCredential, got %d", cnt)
	}
	// Required field for UnauthenticatedCredential: pf
	if s, rErr := p.readString(); rErr != nil || string(s) != "pf" {
		return fmt.Errorf("expected string \"pf\", got %s: %w", s, rErr)
	}
	val, err := p.readBin80()
	if err != nil {
		return fmt.Errorf("reading pf: %w", err)
	}
	c.writeBin80(credPfVoteValue, val)

	// Required field for unauthenticatedVote: r
	if s, rErr := p.readString(); rErr != nil || string(s) != "r" {
		return fmt.Errorf("expected string \"r\", got %s: %w", s, rErr)
	}

	// Parse rawVote
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for rawVote: %w", err)
	}
	if cnt < 1 || cnt > 5 {
		return fmt.Errorf("expected fixmap size for rawVote 1 <= cnt <= 5, got %d", cnt)
	}
	for range cnt {
		key, err := p.readString()
		if err != nil {
			return fmt.Errorf("reading key for rawVote: %w", err)
		}
		switch string(key) {
		case "per":
			val, err := p.readUintBytes()
			if err != nil {
				return fmt.Errorf("reading per: %w", err)
			}
			c.writeVaruint(rPerVoteValue, val)
		case "prop":

			// Parse proposalValue
			cnt, err := p.readFixMap()
			if err != nil {
				return fmt.Errorf("reading map for proposalValue: %w", err)
			}
			if cnt < 1 || cnt > 4 {
				return fmt.Errorf("expected fixmap size for proposalValue 1 <= cnt <= 4, got %d", cnt)
			}
			for range cnt {
				key, err := p.readString()
				if err != nil {
					return fmt.Errorf("reading key for proposalValue: %w", err)
				}
				switch string(key) {
				case "dig":
					val, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading dig: %w", err)
					}
					c.writeBin32(rPropDigVoteValue, val)

				case "encdig":
					val, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading encdig: %w", err)
					}
					c.writeBin32(rPropEncdigVoteValue, val)

				case "oper":
					val, err := p.readUintBytes()
					if err != nil {
						return fmt.Errorf("reading oper: %w", err)
					}
					c.writeVaruint(rPropOperVoteValue, val)
				case "oprop":
					val, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading oprop: %w", err)
					}
					c.writeBin32(rPropOpropVoteValue, val)

				default:
					return fmt.Errorf("unexpected field in proposalValue: %q", key)
				}
			}

		case "rnd":
			val, err := p.readUintBytes()
			if err != nil {
				return fmt.Errorf("reading rnd: %w", err)
			}
			c.writeVaruint(rRndVoteValue, val)
		case "snd":
			val, err := p.readBin32()
			if err != nil {
				return fmt.Errorf("reading snd: %w", err)
			}
			c.writeBin32(rSndVoteValue, val)

		case "step":
			val, err := p.readUintBytes()
			if err != nil {
				return fmt.Errorf("reading step: %w", err)
			}
			c.writeVaruint(rStepVoteValue, val)
		default:
			return fmt.Errorf("unexpected field in rawVote: %q", key)
		}
	}

	// Required field for unauthenticatedVote: sig
	if s, rErr := p.readString(); rErr != nil || string(s) != "sig" {
		return fmt.Errorf("expected string \"sig\", got %s: %w", s, rErr)
	}

	// Parse OneTimeSignature
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for OneTimeSignature: %w", err)
	}
	// Assert OneTimeSignature struct has 6 fields
	if cnt != 6 {
		return fmt.Errorf("expected fixed map size 6 for OneTimeSignature, got %d", cnt)
	}
	// Required field for OneTimeSignature: p
	if s, rErr := p.readString(); rErr != nil || string(s) != "p" {
		return fmt.Errorf("expected string \"p\", got %s: %w", s, rErr)
	}
	val32, err := p.readBin32()
	if err != nil {
		return fmt.Errorf("reading p: %w", err)
	}
	c.writeBin32(sigPVoteValue, val32)

	// Required field for OneTimeSignature: p1s
	if s, rErr := p.readString(); rErr != nil || string(s) != "p1s" {
		return fmt.Errorf("expected string \"p1s\", got %s: %w", s, rErr)
	}
	val2, err := p.readBin64()
	if err != nil {
		return fmt.Errorf("reading p1s: %w", err)
	}
	c.writeBin64(sigP1sVoteValue, val2)

	// Required field for OneTimeSignature: p2
	if s, rErr := p.readString(); rErr != nil || string(s) != "p2" {
		return fmt.Errorf("expected string \"p2\", got %s: %w", s, rErr)
	}
	val32, err = p.readBin32()
	if err != nil {
		return fmt.Errorf("reading p2: %w", err)
	}
	c.writeBin32(sigP2VoteValue, val32)

	// Required field for OneTimeSignature: p2s
	if s, rErr := p.readString(); rErr != nil || string(s) != "p2s" {
		return fmt.Errorf("expected string \"p2s\", got %s: %w", s, rErr)
	}
	val2, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading p2s: %w", err)
	}
	c.writeBin64(sigP2sVoteValue, val2)

	// Required field for OneTimeSignature: ps
	if s, rErr := p.readString(); rErr != nil || string(s) != "ps" {
		return fmt.Errorf("expected string \"ps\", got %s: %w", s, rErr)
	}
	val2, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading ps: %w", err)
	}
	if val2 != [64]byte{} {
		return fmt.Errorf("expected empty array for ps, got %v", val)
	}

	// Required field for OneTimeSignature: s
	if s, rErr := p.readString(); rErr != nil || string(s) != "s" {
		return fmt.Errorf("expected string \"s\", got %s: %w", s, rErr)
	}
	val2, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading s: %w", err)
	}
	c.writeBin64(sigSVoteValue, val2)

	// Check for trailing bytes
	if p.pos < len(p.data) {
		return fmt.Errorf("unexpected trailing data: %d bytes remain unprocessed", len(p.data)-p.pos)
	}
	return nil
}
