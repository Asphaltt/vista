// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

import "sync/atomic"

type OutputCounter struct {
	limit int64

	runForever bool
}

func NewOutputCounter(limit int64) *OutputCounter {
	return &OutputCounter{
		limit:      limit,
		runForever: limit == 0,
	}
}

func (c *OutputCounter) Next() bool {
	if c.runForever {
		return true
	}

	return atomic.AddInt64(&c.limit, -1) > 0
}
