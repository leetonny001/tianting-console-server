// Package clock 是 console-server 的时钟（[C 钟]）。测试模式可以冻结，语义和 im-server 的 [IM 钟] 相同。
package clock

import (
	"sync"
	"time"
)

// Clock 返回当前时间。
type Clock interface{ Now() time.Time }

// Settable 默认走真实时间；Freeze 之后返回固定时间，Unfreeze 恢复。
type Settable struct {
	mu     sync.RWMutex
	frozen *time.Time
}

// New 创建时钟。
func New() *Settable { return &Settable{} }

func (c *Settable) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.frozen != nil {
		return *c.frozen
	}
	return time.Now()
}

// Freeze 冻结到 t。
func (c *Settable) Freeze(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen = &t
}

// Unfreeze 恢复真实时间。
func (c *Settable) Unfreeze() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen = nil
}
