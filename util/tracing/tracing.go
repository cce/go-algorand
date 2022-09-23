// Copyright (C) 2019-2022 Algorand, Inc.
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

package tracing

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("algod")

func StartTracing() error {
	return nil
}

// StartSpan creates a span, provided a context and options. If tracing is not configured, a no-op span is returned.
func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if ctx == nil {
		return ctx, noopSpan{}
	}
	return tracer.Start(ctx, spanName, opts...)
}

type noopSpan struct{}

func (noopSpan) SpanContext() trace.SpanContext          { return trace.SpanContext{} }
func (noopSpan) IsRecording() bool                       { return false }
func (noopSpan) SetStatus(codes.Code, string)            {}
func (noopSpan) SetError(bool)                           {}
func (noopSpan) SetAttributes(...attribute.KeyValue)     {}
func (noopSpan) End(...trace.SpanEndOption)              {}
func (noopSpan) RecordError(error, ...trace.EventOption) {}
func (noopSpan) AddEvent(string, ...trace.EventOption)   {}
func (noopSpan) SetName(string)                          {}
func (noopSpan) TracerProvider() trace.TracerProvider    { return noopTracerProvider{} }

type noopTracerProvider struct{}

func (p noopTracerProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return noopTracer{}
}

type noopTracer struct{}

func (t noopTracer) Start(ctx context.Context, name string, _ ...trace.SpanStartOption) (context.Context, trace.Span) {
	return ctx, noopSpan{}
}
