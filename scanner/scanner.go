package scanner

import (
	"net"
	"net/netip"
)

type Scanner interface {
	Init() error
	Scan(scan chan netip.AddrPort, port uint16, cidrs ...*net.IPNet)
}
