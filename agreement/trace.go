// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package agreement

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

//msgp:ignore traceLevel
type traceLevel int

const (
	disabled = iota
	top
	key
	all
)

type tracerMetadata struct {
	Round  round
	Period period
	Step   step
}

type tracer struct {
	seq   int
	tag   string
	level traceLevel

	cadaver

	log serviceLogger

	w io.Writer

	// Tracer is now a little stateful (for ad-hoc logging)
	// parent state machines/routers are responsible for making sure tracer
	// picks up the right state. Optional.
	playerInfo tracerMetadata

	// Please use accessors to update timing info, since they may be nil
	tR      *timingInfoGenerator
	tRPlus1 *timingInfoGenerator // pipelining

	// Logs Config
	// if verboseReports is true, telemtrize new period entries
	verboseReports bool
	// if timingReports is true, telemetrize more fine-grained agreement timing data
	timingReports bool
}

const cadaverSizeMinimum = 100 * 1024 // 100 KB

func makeTracer(log serviceLogger, cadaverFilename string, cadaverSizeTarget uint64, verboseReportFlag bool, timingReportFlag bool) *tracer {
	t := new(tracer)
	t.log = log
	t.verboseReports = verboseReportFlag
	t.timingReports = timingReportFlag
	t.w = os.Stdout

	fileSizeTarget := int64(cadaverSizeTarget)
	if fileSizeTarget == 0 {
		// disabled
	} else if fileSizeTarget < 0 {
		log.Errorf("agreement: cadaver filesize too large: int64(%v) < 0", cadaverSizeTarget)
	} else if fileSizeTarget < cadaverSizeMinimum {
		log.Errorf("agreement: cadaver filesize too small: %v < %v", fileSizeTarget, cadaverSizeMinimum)
	} else if fileSizeTarget > 0 {
		t.cadaver.baseFilename = cadaverFilename
		t.cadaver.fileSizeTarget = fileSizeTarget
		log.Infof("agreement: cadaver set to %v", cadaverFilename)
	}
	return t
}

// call this method to setup timing generators before entering target round, pipelining properly.
func (t *tracer) resetTimingWithPipeline(target round) {
	if t.tRPlus1 != nil && t.tRPlus1.i.Round == uint64(target) {
		t.tR = t.tRPlus1
	} else {
		t.tR = nil
	}
	t.tRPlus1 = nil
}

// tR and tRPlus1 may be accessed before timing is "initialized" (e.g.
// on crash recovery). Instead of trying to initialize timing info every time (even
// when unrecoverable) just make a new timinginfogen when not already set.
func (t *tracer) timeR() *timingInfoGenerator {
	if t.tR == nil {
		t.tR = makeTimingInfoGen(t.timingReports, t.log)
	}
	return t.tR
}

func (t *tracer) timeRPlus1() *timingInfoGenerator {
	if t.tRPlus1 == nil {
		t.tRPlus1 = makeTimingInfoGen(t.timingReports, t.log)
	}
	return t.tRPlus1
}

// setMetadata configures tracer to print round/period/step information.
// optional.
func (t *tracer) setMetadata(metadata tracerMetadata) {
	t.playerInfo = metadata
}

func (t *tracer) ein(ctx context.Context, src, dest stateMachineTag, e event, r round, p period, s step) context.Context {
	t.seq++
	if t.level >= all {
		// fmt.Fprintf(t.w, "%v %3v %23v  -> %23v: %30v\n", t.tag, t.seq, src, dest, e)
		fmt.Fprintf(t.w, "%v] %23v  -> %23v: %30v\n", t.tag, src, dest, e)
	}

	opname := e.t().String()
	ctx, span := oteltr.Start(ctx, opname, trace.WithAttributes(
		attribute.Stringer("src_machine", src),
		attribute.Stringer("dst_machine", dest),
		attribute.Any("round", r),
		attribute.Any("period", p),
		attribute.Any("step", s),
	))
	span.SetAttributes(attributesFromEvent(e, "in_")...)
	return ctx
}

func (t *tracer) eout(ctx context.Context, src, dest stateMachineTag, e event, r round, p period, s step) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attributesFromEvent(e, "out_")...)
	span.End()
	t.seq++
	if t.level >= all {
		// fmt.Fprintf(t.w, "%v %3v %23v <-  %23v: %30v\n", t.tag, t.seq, src, dest, e)
		fmt.Fprintf(t.w, "%v] %23v <-  %23v: %30v\n", t.tag, src, dest, e)
	} else if t.level >= key {
		switch e.t() {
		case proposalAccepted, proposalCommittable, softThreshold, certThreshold, nextThreshold:
			// fmt.Fprintf(t.w, "%v %3v %23v <-  %23v: %30v\n", t.tag, t.seq, src, dest, e)
			fmt.Fprintf(t.w, "%v] %23v <-  %23v: %30v\n", t.tag, src, dest, e)
		}
	}
}

func attributesFromEvent(e event, prefix string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Stringer(prefix+"eventtype", e.t()),
		attribute.Stringer(prefix+"event", e),
	}
}

func attributesFromActions(a []action) []attribute.KeyValue {
	var atypes []string
	var astrs []string
	for _, ai := range a {
		atypes = append(atypes, ai.t().String())
		astrs = append(astrs, ai.String())
	}
	return []attribute.KeyValue{
		attribute.Array("actiontype", atypes),
		attribute.Array("action", astrs),
	}
}

var oteltr trace.Tracer

func init() {
	oteltr = otel.Tracer("agreement")
}

func (t *tracer) ainTop(ctx context.Context, src, dest stateMachineTag, state player, e event, r round, p period, s step) context.Context {
	t.seq++
	if t.level >= top {
		// fmt.Fprintf(t.w, "%v %3v %23v  => %23v: %30v\n", t.tag, t.seq, src, dest, e)
		fmt.Fprintf(t.w, "%v] %23v =>  %23v: %30v\n", t.tag, src, dest, e)
	}
	ctx, span := oteltr.Start(ctx, "router.submitTop", trace.WithAttributes(
		attribute.Stringer("src_machine", src),
		attribute.Stringer("dst_machine", dest),
		attribute.Any("player", state),
	))
	span.SetAttributes(attributesFromEvent(e, "top_")...)
	return ctx
}

func (t *tracer) aoutTop(ctx context.Context, src, dest stateMachineTag, as []action, r round, p period, s step) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attributesFromActions(as)...)
	span.End()

	if t.log.IsLevelEnabled(logging.Debug) {
		var tags []string
		for _, a := range as {
			tags = append(tags, a.String())
		}
		outstr := strings.Join(tags, ", ")
		t.log.Debugf("emit actions %v", outstr)
	}

	t.seq++
	if t.level >= top {
		// fmt.Fprintf(t.w, "%v %3v %23v <=  %23v: %.30v\n", t.tag, t.seq, src, dest, as)
		fmt.Fprintf(t.w, "%v] %23v <=  %23v: %.30v\n", t.tag, src, dest, as)
	}
}

/* Ad-hoc logging */

func (t *tracer) logTimeout(ctx context.Context, p player) {
	if !t.log.IsLevelEnabled(logging.Info) {
		return
	}
	logEvent := logspec.AgreementEvent{
		Type:   logspec.StepTimeout,
		Round:  uint64(p.Round),
		Period: uint64(p.Period),
		Step:   uint64(p.Step),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("timeout fired on (%v, %v, %v) with value %v (napping: %v)", p.Round, p.Period, p.Step, p.Deadline, p.Napping)
}

func (t *tracer) logFastTimeout(ctx context.Context, p player) {
	if !t.log.IsLevelEnabled(logging.Info) {
		return
	}
	logEvent := logspec.AgreementEvent{
		Type:   logspec.StepTimeout,
		Round:  uint64(p.Round),
		Period: uint64(p.Period),
		Step:   uint64(p.Step),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("timeout fired on (%v, %v, %v) with value %v (napping: %v)", p.Round, p.Period, p.Step, p.FastRecoveryDeadline, p.Napping)
}

func (t *tracer) logProposalFrozen(ctx context.Context, prop proposalValue, propRound round, propPeriod period) {
	logEvent := logspec.AgreementEvent{
		Type:         logspec.ProposalFrozen,
		Hash:         prop.BlockDigest.String(),
		ObjectRound:  uint64(propRound),
		ObjectPeriod: uint64(propPeriod),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("froze proposal %v for (%v, %v)", prop, propRound, propPeriod)
}

func (t *tracer) logPeriodConcluded(ctx context.Context, p player, target period, prop proposalValue) {
	logEvent := logspec.AgreementEvent{
		Type:         logspec.PeriodConcluded,
		Hash:         prop.BlockDigest.String(),
		Round:        uint64(p.Round),
		Period:       uint64(p.Period),
		ObjectRound:  uint64(p.Round),
		ObjectPeriod: uint64(target),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("entering non-zero period (%v - %v) with value %v", p.Period, target, prop)

	if !t.verboseReports {
		return
	}
	// we should rarely need to enter a new period under common case operation.
	t.log.WithContext(ctx).EventWithDetails(telemetryspec.Agreement, telemetryspec.NewPeriodEvent, telemetryspec.NewRoundPeriodDetails{
		OldRound:  uint64(p.Round),
		OldPeriod: uint64(p.Period),
		OldStep:   uint64(p.Step),
		NewRound:  uint64(p.Round),
		NewPeriod: uint64(target),
		NewStep:   uint64(soft),
		LocalTime: time.Now(),
	})
}

func (t *tracer) logRoundStart(p player, target round) {
	// Log timing telemetry.
	if t.tR != nil && t.timingReports {
		timeInfo := t.tR.Build(p.Step)
		// Generate a distinct event than blockAccepted for convenience (this one is generated by player, other by service)
		t.log.Metrics(telemetryspec.Agreement, timeInfo, nil)
	}

}

func (t *tracer) logBundleBroadcast(ctx context.Context, p player, b unauthenticatedBundle) {
	if !t.log.IsLevelEnabled(logging.Info) {
		return
	}
	logEvent := logspec.AgreementEvent{
		Type:         logspec.BundleBroadcast,
		Hash:         b.Proposal.BlockDigest.String(),
		Round:        uint64(p.Round),
		Period:       uint64(p.Period),
		Step:         uint64(p.Step),
		ObjectRound:  uint64(b.Round),
		ObjectPeriod: uint64(b.Period),
		ObjectStep:   uint64(b.Step),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("broadcast bundle for (%v, %v, %v)", b.Round, b.Period, b.Step)
}

func (t *tracer) logProposalRepropagate(ctx context.Context, prop proposalValue, propRound round, propPeriod period) {
	if !t.log.IsLevelEnabled(logging.Info) {
		return
	}
	logEvent := logspec.AgreementEvent{
		Type:   logspec.BlockResent,
		Hash:   prop.BlockDigest.String(),
		Round:  uint64(propRound),
		Period: uint64(propPeriod),
	}
	t.log.with(logEvent).WithContext(ctx).Infof("resent block for (%v, %v)", propRound, propPeriod)
}

func (t *tracer) logProposalManagerResult(ctx context.Context, p player, input messageEvent, output event, pipelinedRound round, pipelinedPeriod period) {
	switch output.t() {
	case voteFiltered, voteMalformed:
		filtered := output.t() == voteFiltered
		if filtered && !t.log.IsLevelEnabled(logging.Debug) {
			return
		}
		uv := input.Input.UnauthenticatedVote
		logEvent := logspec.AgreementEvent{
			Type:         logspec.ProposalRejected,
			Round:        uint64(p.Round),
			Period:       uint64(p.Period),
			Step:         uint64(p.Step),
			Hash:         uv.R.Proposal.BlockDigest.String(),
			Sender:       uv.R.Sender.String(),
			ObjectRound:  uint64(uv.R.Round),
			ObjectPeriod: uint64(uv.R.Period),
		}
		if filtered {
			t.log.with(logEvent).WithContext(ctx).Debugf("rejected proposal for (%v, %v): %v", uv.R.Round, uv.R.Period, output.(filteredEvent).Err)
		} else {
			t.log.with(logEvent).WithContext(ctx).Warnf("malformed proposal for (%v, %v): %v", uv.R.Round, uv.R.Period, output.(filteredEvent).Err)
		}

	case payloadRejected, payloadMalformed:
		rejected := output.t() == payloadRejected
		if rejected && !t.log.IsLevelEnabled(logging.Info) {
			return
		}
		up := input.Input.UnauthenticatedProposal
		logEvent := logspec.AgreementEvent{
			Type:   logspec.BlockRejected,
			Round:  uint64(p.Round),
			Period: uint64(p.Period),
			Step:   uint64(p.Step),
			Hash:   up.Digest().String(),
		}

		if rejected {
			t.log.with(logEvent).WithContext(ctx).Debugf("rejected block for (%v, %v): %v", p.Round, p.Period, output.(payloadProcessedEvent).Err)
		} else {
			t.log.with(logEvent).WithContext(ctx).Warnf("rejected block for (%v, %v): %v", p.Round, p.Period, output.(filteredEvent).Err)
		}

	case payloadPipelined:
		if !t.log.IsLevelEnabled(logging.Info) {
			return
		}
		up := input.Input.UnauthenticatedProposal
		logEvent := logspec.AgreementEvent{
			Type:         logspec.BlockPipelined,
			Round:        uint64(p.Round),
			Period:       uint64(p.Period),
			Step:         uint64(p.Step),
			Sender:       up.OriginalProposer.String(),
			Hash:         up.Digest().String(),
			ObjectRound:  uint64(pipelinedRound),
			ObjectPeriod: uint64(pipelinedPeriod),
		}
		t.log.with(logEvent).WithContext(ctx).Infof("pipelined block for (%v, %v): %v", pipelinedRound, pipelinedPeriod, output.(payloadProcessedEvent).Err)

	case proposalAccepted:
		if !t.log.IsLevelEnabled(logging.Info) {
			return
		}
		uv := input.Input.UnauthenticatedVote
		pev := output.(proposalAcceptedEvent)
		logEvent := logspec.AgreementEvent{
			Type:         logspec.ProposalAccepted,
			Round:        uint64(p.Round),
			Period:       uint64(p.Period),
			Step:         uint64(p.Step),
			Sender:       uv.R.Sender.String(),
			Hash:         pev.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(pev.Round),
			ObjectPeriod: uint64(pev.Period),
		}
		t.log.with(logEvent).WithContext(ctx).Infof("proposal %v accepted at (%v, %v)", pev.Proposal, pev.Round, pev.Period)

	case payloadAccepted, proposalCommittable:
		if !t.log.IsLevelEnabled(logging.Info) {
			return
		}
		var prop proposalValue
		if output.t() == payloadAccepted {
			prop = output.(payloadProcessedEvent).Proposal
		} else {
			prop = output.(committableEvent).Proposal
		}

		logEvent := logspec.AgreementEvent{
			Round:        uint64(p.Round),
			Period:       uint64(p.Period),
			Sender:       prop.OriginalProposer.String(),
			Hash:         prop.BlockDigest.String(),
			ObjectRound:  uint64(p.Round),
			ObjectPeriod: uint64(prop.OriginalPeriod),
		}

		if output.t() == payloadAccepted {
			logEvent.Type = logspec.BlockAssembled
			t.log.with(logEvent).WithContext(ctx).Infof("block assembled for %v at (%v, %v)", logEvent.Hash, p.Round, p.Period)
		} else {
			logEvent.Type = logspec.BlockCommittable
			t.log.with(logEvent).WithContext(ctx).Infof("block committable for %v at (%v, %v)", logEvent.Hash, p.Round, p.Period)
		}
	}
}

func (t *tracer) logVoteAggregatorResult(ctx context.Context, input filterableMessageEvent, output event) {
	switch output.t() {
	case voteFiltered, voteMalformed:
		filtered := output.t() == voteFiltered
		if filtered && !t.log.IsLevelEnabled(logging.Debug) {
			return
		}
		uv := input.Input.UnauthenticatedVote
		logEvent := logspec.AgreementEvent{
			Type:         logspec.VoteRejected,
			Round:        uint64(t.playerInfo.Round),
			Period:       uint64(t.playerInfo.Period),
			Step:         uint64(t.playerInfo.Step),
			Sender:       uv.R.Sender.String(),
			Hash:         uv.R.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(uv.R.Round),
			ObjectPeriod: uint64(uv.R.Period),
			ObjectStep:   uint64(uv.R.Step),
		}
		// [TODO] Add Metrics here to capture telemetryspec.VoteRejectedEvent details
		// 	Reason:           fmt.Sprintf("rejected malformed message: %v", e.Err),
		if filtered {
			t.log.with(logEvent).WithContext(ctx).Debugf("filtered vote for (%v, %v, %v): %v", uv.R.Round, uv.R.Period, uv.R.Step, output.(filteredEvent).Err)
		} else {
			t.log.with(logEvent).WithContext(ctx).Warnf("malformed vote for (%v, %v, %v): %v", uv.R.Round, uv.R.Period, uv.R.Step, output.(filteredEvent).Err)
		}
	case bundleFiltered, bundleMalformed:
		filtered := output.t() == bundleFiltered
		if filtered && !t.log.IsLevelEnabled(logging.Debug) {
			return
		}
		ub := input.Input.UnauthenticatedBundle
		logEvent := logspec.AgreementEvent{
			Type:         logspec.BundleRejected,
			Round:        uint64(t.playerInfo.Round),
			Period:       uint64(t.playerInfo.Period),
			Step:         uint64(t.playerInfo.Step),
			Hash:         ub.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(ub.Round),
			ObjectPeriod: uint64(ub.Period),
			ObjectStep:   uint64(ub.Step),
		}
		if filtered {
			t.log.with(logEvent).WithContext(ctx).Debugf("bundle filtered for %v at (%v, %v, %v): %v", ub.Proposal, ub.Round, ub.Period, ub.Step, output.(filteredEvent).Err)
		} else {
			t.log.with(logEvent).WithContext(ctx).Warnf("bundle malformed for %v at (%v, %v, %v): %v", ub.Proposal, ub.Round, ub.Period, ub.Step, output.(filteredEvent).Err)
		}
	case softThreshold, certThreshold, nextThreshold:
		if input.t() != bundleVerified {
			return
		}
		if !t.log.IsLevelEnabled(logging.Info) {
			return
		}

		b := output.(thresholdEvent).Bundle
		logEvent := logspec.AgreementEvent{
			Type:   logspec.BundleAccepted,
			Round:  uint64(b.Round),
			Period: uint64(b.Period),
			Step:   uint64(b.Step),
			Hash:   b.Proposal.BlockDigest.String(),
		}
		t.log.with(logEvent).WithContext(ctx).Infof("bundle accepted for %v at (%v, %v, %v)", b.Proposal, b.Round, b.Period, b.Step)
	}
}

func (t *tracer) logVoteTrackerResult(ctx context.Context, p player, input voteAcceptedEvent, output thresholdEvent, weight uint64, inputTotal uint64, outputTotal uint64, proto config.ConsensusParams) {
	if !t.log.IsLevelEnabled(logging.Info) {
		return
	}
	// [TODO] Add Metrics here to capture telemetryspec.VoteAcceptedEvent details
	logEvent := logspec.AgreementEvent{
		Type:         logspec.VoteAccepted,
		Round:        uint64(p.Round),
		Period:       uint64(p.Period),
		Step:         uint64(p.Step),
		Sender:       input.Vote.R.Sender.String(),
		Hash:         input.Vote.R.Proposal.BlockDigest.String(),
		ObjectRound:  uint64(input.Vote.R.Round),
		ObjectPeriod: uint64(input.Vote.R.Period),
		ObjectStep:   uint64(input.Vote.R.Step),
		Weight:       weight,
		WeightTotal:  inputTotal,
	}
	t.log.with(logEvent).WithContext(ctx).Infof("vote accepted for %v at (%v, %v, %v)", input.Vote.R.Proposal, input.Vote.R.Round, input.Vote.R.Period, input.Vote.R.Step)

	if output.T != none {
		logEvent := logspec.AgreementEvent{
			Type:         logspec.ThresholdReached,
			Round:        uint64(p.Round),
			Period:       uint64(p.Period),
			Step:         uint64(p.Step),
			Hash:         output.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(output.Round),
			ObjectPeriod: uint64(output.Period),
			ObjectStep:   uint64(output.Step),
			Weight:       outputTotal,
			WeightTotal:  output.Step.threshold(proto),
		}
		t.log.with(logEvent).WithContext(ctx).Infof("threshold reached for %v at (%v, %v, %v)", output.Proposal.BlockDigest, output.Round, output.Period, output.Step)
	}
}

type serviceLogger struct {
	logging.Logger
}

func (log serviceLogger) with(e logspec.AgreementEvent) serviceLogger {
	fields := logging.Fields{
		"Context":      "Agreement",
		"Type":         e.Type.String(),
		"Round":        e.Round,
		"Period":       e.Period,
		"Step":         e.Step,
		"Hash":         e.Hash,
		"Sender":       e.Sender,
		"ObjectRound":  e.ObjectRound,
		"ObjectPeriod": e.ObjectPeriod,
		"ObjectStep":   e.ObjectStep,
		"Weight":       e.Weight,
		"WeightTotal":  e.WeightTotal,
	}
	return serviceLogger{log.Logger.WithFields(fields)}
}

// mini opentelemery tracing interface

type spanTracer interface {
	// Start creates a span.
	Start(ctx context.Context, spanName string, opts ...spanOption) (context.Context, span)
}

type spanOption interface {
	ApplySpan(*spanConfig)
}

type spanConfig struct {
	// Attributes describe the associated qualities of a Span.
	Attributes map[string]interface{}
	// Timestamp is a time in a Span life-cycle.
	Timestamp time.Time
	// Links are the associations a Span has with other Spans.
	//Links []Link
	// NewRoot identifies a Span as the root Span for a new trace. This is
	// commonly used when an existing trace crosses trust boundaries and the
	// remote parent span context should be ignored for security.
	NewRoot bool
	// SpanKind is the role a Span has in a trace.
	SpanKind spanKind
}

type spanKind int

type span interface {
	End(options ...spanOption)
	SetName(name string)
}
