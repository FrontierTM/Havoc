package scanner

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type MinecraftConn struct {
	MinecraftBuffer
	io.Closer
	ProtocolVersion int
	*bufio.Reader
	*bufio.Writer
}

type MinecraftBuffer struct {
	*bytes.Buffer
}

func NewMinecraftBuffer(packetId int) *MinecraftBuffer {
	m := &MinecraftBuffer{Buffer: new(bytes.Buffer)}
	_ = m.WriteVarInt(packetId)
	return m
}

func NewMinecraftConn(conn net.Conn, ProtocolVersion int) *MinecraftConn {
	return &MinecraftConn{
		Closer:          conn,
		ProtocolVersion: ProtocolVersion,
		Reader:          bufio.NewReaderSize(conn, 1500),
		Writer:          bufio.NewWriterSize(conn, 1500),
	}
}

func (c MinecraftBuffer) ReadVarInt() (int, error) {
	value := 0
	position := 0

	for {
		currentByte, err := c.ReadByte()

		if err != nil {
			return 0, err
		}

		value |= (int(currentByte) & 0x7F) << position

		if (int(currentByte) & 0x80) == 0 {
			break
		}

		position += 7

		if position >= 32 {
			return 0, errors.New("VarInt is too big")
		}
	}

	return value, nil
}

func (c MinecraftBuffer) WriteVarInt(value int) error {
	for {
		if (value & ^0x7F) == 0 {
			c.WriteByte(byte(value))
			break
		}

		err := c.WriteByte(byte((value & 0x7F) | 0x80))

		if err != nil {
			return err
		}

		value >>= 7
	}

	return nil
}

func (c MinecraftBuffer) WriteString(s string) error {
	if err := c.WriteVarInt(len(s)); err != nil {
		return err
	}

	if _, err := c.Write([]byte(s)); err != nil {
		return err
	}

	return nil
}

func (c MinecraftBuffer) ReadStr() (string, error) {
	varInt, err := c.ReadVarInt()

	if err != nil {
		return "", err
	}

	var b = make([]byte, varInt)

	if _, err := io.ReadFull(c, b); err != nil {
		return "", err
	}

	return string(b), nil
}

func (c MinecraftBuffer) WriteUShort(i uint16) error {
	return binary.Write(c, binary.BigEndian, i)
}

func (c MinecraftBuffer) WriteBoolean(n bool) interface{} {
	if n {
		c.WriteByte(1)
	} else {
		c.WriteByte(0)
	}
	return nil
}

func (c MinecraftBuffer) WriteLong(i int64) error {
	return binary.Write(c, binary.BigEndian, i)
}

func (c *MinecraftConn) WriteBuffer(buffer *MinecraftBuffer) error {
	minecraftBuffer := NewMinecraftBuffer(0)

	if err := minecraftBuffer.WriteVarInt(buffer.Len()); err != nil {
		return err
	}

	if _, err := minecraftBuffer.Write(buffer.Bytes()); err != nil {
		return err
	}

	if _, err := c.Write(minecraftBuffer.Bytes()); err != nil {
		return err
	}

	fmt.Println(buffer.Bytes())
	fmt.Println(minecraftBuffer.Bytes())

	return c.Flush()
}

func (c *MinecraftConn) SendHandshake(hostname string, port int16, state int) error {
	buffer := NewMinecraftBuffer(0x00)

	_ = buffer.WriteVarInt(c.ProtocolVersion)
	_ = buffer.WriteString(hostname)
	_ = buffer.WriteUShort(uint16(port))
	_ = buffer.WriteVarInt(state)

	return c.WriteBuffer(buffer)
}

func (c *MinecraftConn) SendLogin(name string, uuid string) error {
	buffer := NewMinecraftBuffer(0x00)

	_ = buffer.WriteString(name)

	if c.ProtocolVersion >= 763 {
		_ = buffer.WriteString(uuid)
	} else if c.ProtocolVersion >= 759 {
		_ = buffer.WriteBoolean(false)
	}

	if c.ProtocolVersion >= 759 {
		_ = buffer.WriteBoolean(true)
		_ = buffer.WriteString(uuid)

	}

	return c.WriteBuffer(buffer)
}

func (c *MinecraftConn) SendPing() error {
	buffer := NewMinecraftBuffer(0x00)
	return c.WriteBuffer(buffer)
}

func (c *MinecraftConn) KeepAlive() interface{} {
	var packetId int

	switch {
	case c.ProtocolVersion < 107: // 1.9 snapshots
		packetId = 0x1F // Assuming 0x1F is correct for versions between 47 and 107
	case c.ProtocolVersion < 316: // versions 1.9 to 1.11.2
		packetId = 0x0B // Assuming 0x0B is correct for versions between 107 and 316
	case c.ProtocolVersion < 338: // versions 1.12 to 1.12.1
		packetId = 0x0B // Assuming the same ID continues to be used for these versions
	case c.ProtocolVersion < 340: // version 1.12.2
		packetId = 0x0B // Assuming the same ID continues to be used for 1.12.2
	case c.ProtocolVersion == 338:
		packetId = 0x03
	case c.ProtocolVersion == 340:
		packetId = 0x04
	default:
		packetId = 0x00 // This could be a placeholder. You might want to handle this case.
	}

	buffer := NewMinecraftBuffer(packetId)
	_ = buffer.WriteLong(time.Now().Unix())
	return c.WriteBuffer(buffer)
}

func (c *MinecraftConn) SendBookEdit() error {

	return nil
}
