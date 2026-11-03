package accesslog

import (
	"context"
	"time"
)

type Send func(context.Context, []byte) (Ack, error)

// Report drains oldest-first without a flush-interval delay after recovery.
// Only a matching committed acknowledgement removes a durable batch.
func Report(ctx context.Context, spool *Spool, send Send, onError func(error)) {
	if onError == nil {
		onError = func(error) {}
	}
	for ctx.Err() == nil {
		state := spool.Snapshot()
		delay := time.Until(time.UnixMilli(state.NextAttemptAt))
		if delay > 0 {
			timer := time.NewTimer(min(delay, time.Minute))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		name, body, err := spool.Next(time.Now())
		if err == nil && name != "" {
			request, cancel := context.WithTimeout(ctx, ReportTimeout)
			var ack Ack
			ack, err = send(request, body)
			cancel()
			if err == nil {
				err = spool.Confirm(name, body, ack)
			}
			if err == nil {
				continue
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			onError(err)
			if e := spool.Retry(time.Now()); e != nil {
				onError(e)
				timer := time.NewTimer(Backoff(state.Failures + 1))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			continue
		}
		timer := time.NewTimer(FlushInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-spool.Wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}
