package cracker

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"time"
)

var ErrConn = errors.New("cannot connect to server")

type Cracker interface {
	Init() error
	Check(ip netip.AddrPort) (*GoodResult, error)
}

type GoodResult struct {
	IP        netip.AddrPort
	Data      string
	Type      string
	Timestamp time.Time
}

func (r GoodResult) String() string {
	x := r.Data

	if x != "" {
		x = "#" + x
	}

	return fmt.Sprintf("%s %s://%s%s", r.Timestamp.Format(time.DateTime), r.Type, r.IP.String(), x)
}

func (r GoodResult) Color() int {
	switch r.Type {
	case "ssh":
		return 0xFF0000
	case "xui":
		return 0x00FF00
	case "telnet":
		return 0x0000FF
	default:
		return 0x000000
	}
}

type CheckCombo []Combo

type Combo struct {
	Username string
	Password string
}

type IteratorSession struct {
	CheckCombo
	index int
}

func NewIteratorSession(c CheckCombo) *IteratorSession {
	return &IteratorSession{
		CheckCombo: c,
		index:      0,
	}
}

func ParseCombo(text string) *Combo {
	n := strings.SplitN(text, ":", 2)
	if len(n) != 2 {
		return nil
	}

	return &Combo{
		Username: n[0],
		Password: n[1],
	}
}

func (s *IteratorSession) Next() *Combo {
	if s.index == len(s.CheckCombo) {
		return nil
	}

	s.index = (s.index + 1) % len(s.CheckCombo)
	return &s.CheckCombo[s.index]
}

func (s *IteratorSession) Prev() *Combo {
	if s.index == 0 {
		return nil
	}

	s.index = (s.index - 1) % len(s.CheckCombo)
	return &s.CheckCombo[s.index]
}

func (s *IteratorSession) HasNext() bool {
	return s.index < len(s.CheckCombo)
}

func (c CheckCombo) Random() Combo {
	return c[rand.Intn(len(c))]
}

func (c CheckCombo) Iterator() *IteratorSession {
	return NewIteratorSession(c)
}

func NewGoodResult(combo *Combo, Type string, ip netip.AddrPort) *GoodResult {
	return &GoodResult{
		IP:        ip,
		Data:      combo.Username + ":" + combo.Password,
		Type:      Type,
		Timestamp: time.Now(),
	}
}
func NewScanResult(Type string, ip netip.AddrPort) *GoodResult {
	return &GoodResult{
		IP:        ip,
		Type:      Type,
		Timestamp: time.Now(),
	}
}
