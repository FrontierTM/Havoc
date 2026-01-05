package scanner

import (
	"encoding/binary"
	"github.com/XenonCommunity/RawSocketWrapper/RawSocket"
	"math"
	"math/rand"
	"net"
	"net/netip"
)

type SYNScanner struct {
	socket RawSocket.RawSocket
}

func NewSynScanner() *SYNScanner {
	return &SYNScanner{}
}

func (s *SYNScanner) Init() error {
	socket, err := RawSocket.OpenRawSocket(RawSocket.IPPROTO_TCP)
	if err != nil {
		return err
	}
	s.socket = socket
	return nil
}

func (s *SYNScanner) Scan(scan chan netip.AddrPort, port uint16, cidrs ...*net.IPNet) {
	listenPort := uint16(rand.Intn(math.MaxUint16))

	go func() {
		bytes := make([]byte, 65535)
		for {
			n, addr, err := s.socket.Read(bytes)

			if err != nil {
				break
			}

			packet := bytes[:n]

			if isSamePort(packet, listenPort) && isSYNACK(packet) {
				s.sendRST(addr.(*net.IPAddr), listenPort, port, packet)
				scan <- netip.AddrPortFrom(netip.MustParseAddr(addr.String()), port)
				continue
			}
		}
	}()

	for _, cidr := range cidrs {
		for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); incIP(ip) {
			target := net.TCPAddr{
				IP:   ip,
				Port: int(port),
			}

			if err := s.scanIP(target, listenPort); err != nil {
				panic(err)
			}
		}
	}

}

func (s *SYNScanner) sendRST(addr *net.IPAddr, sport, dport uint16, packet []byte) {
	tcp := RawSocket.TCP{
		RST:      true,
		Sequence: binary.BigEndian.Uint32(packet[4:8]),
		Window:   binary.BigEndian.Uint16(packet[14:16]),
	}

	src := net.TCPAddr{
		IP:   RawSocket.GetSelfIP(),
		Port: int(sport),
	}
	dst := net.TCPAddr{
		IP:   addr.IP,
		Port: int(dport),
	}

	build := tcp.Build(src, dst)

	_, _ = s.socket.Write(build, addr)
}

func isSamePort(packet []byte, port uint16) bool {
	destPort := binary.BigEndian.Uint16(packet[2:4])
	return destPort == port
}
func isSYNACK(tcpBuffer []byte) bool {
	if len(tcpBuffer) < 4 {
		return false
	}

	synFlag := tcpBuffer[1] & 0x02
	ackFlag := tcpBuffer[1] & 0x10

	return synFlag != 0 && ackFlag != 0
}

func (s *SYNScanner) scanIP(dst net.TCPAddr, port uint16) error {
	// Send SYN packet
	tcp := RawSocket.TCP{
		SYN: true,
	}

	src := net.TCPAddr{IP: RawSocket.GetSelfIP(), Port: int(port)}
	addr := &net.IPAddr{IP: dst.IP}

	build := tcp.Build(src, dst)

	if _, err := s.socket.Write(build, addr); err != nil {
		return err
	}

	return nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified() && ip[0] != 0 {
			break
		}
	}
}
