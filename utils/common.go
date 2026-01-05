package utils

import (
	"sync/atomic"
	"time"
)

type CPSCounter struct {
	cps   *atomic.Int32
	timer *time.Timer
}

func NewCPSCounter() *CPSCounter {
	return &CPSCounter{
		cps:   new(atomic.Int32),
		timer: time.NewTimer(time.Second),
	}
}

func (c *CPSCounter) GetCPS() int32 {
	return c.cps.Load()
}

func (c *CPSCounter) IncCPS() {
	select {
	case <-c.timer.C:
		c.cps.Swap(0)
		c.timer.Reset(time.Second)
	default:
		c.cps.Add(1)
	}
}

func (c *CPSCounter) Reset() {
	c.timer.Reset(time.Second)
}
