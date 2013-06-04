package gotrntmessages

import (
	"bytes"
)

// BitTorrent protocol header
var goTrntHeader string = "BitTorrent protocol"
var goTrntHeaderLen byte = byte(len(goTrntHeader))

// Message types
const (
	MsgTypeChoke = iota
	MsgTypeUnchoke
	MsgTypeInterested
	MsgTypeNotInterested
	MsgTypeHave
	MsgTypeBitfield
	MsgTypeRequest
	MsgTypePiece
	MsgTypeCancel
	MsgTypePort
	MsgTypeHandshake
	MsgTypeKeepAlive
	MsgTypeInvalid
)

// Message type names
var MsgTypeNames []string = []string{
	"Choke",
	"Unchoke",
	"Interested",
	"NotInterested",
	"Have",
	"Bitfiled",
	"Request",
	"Piece",
	"Cancel",
	"Port",
	"Handshake",
	"KeepAlive",
	"Invalid"}

// Generic interface used to handle messages
type MsgData interface {
	GetMsgType() (uint, string)
}

// Base data struct for peer messages
type MsgDataCommon struct {
	MsgType uint
}

// Base data struct implements interface method
func (msgDataCmn MsgDataCommon) GetMsgType() (uint, string) {
	return msgDataCmn.MsgType, MsgTypeNames[msgDataCmn.MsgType]
}

// Choke and Unchoke messages
type MsgDataChoke struct {
	MsgDataCommon
	IsChoking bool
}

// Interested and Not Interested messages
type MsgDataInterested struct {
	MsgDataCommon
	IsInterested bool
}

// Have message
type MsgDataHave struct {
	MsgDataCommon
	PieceIndex uint32
}

// Bitfield message
type MsgDataBitfield struct {
	MsgDataCommon
	Bitfield []byte
}

// Request and cancel messages
type MsgDataRequestCancel struct {
	MsgDataCommon
	PieceIndex      uint32
	PieceBytesBegin uint32
	PieceBytesLen   uint32
}

// Piece message
type MsgDataPiece struct {
	MsgDataCommon
	PieceIndex      uint32
	PieceBytesBegin uint32
	PieceBlock      []byte
}

// Handshake message
type MsgDataHandshake struct {
	MsgDataCommon
	ProtocolStrLen int
	ProtocolStr    string
	ReservedBytes  string
	InfoHash       string
	PeerId         string
}

// Port message
type MsgDataPort struct {
	MsgDataCommon
	PeerPort uint16
}

// Gets message type from raw buffer received from peer
func GetMessageType(buf []byte) (uint, string) {
	if len(buf) > int(goTrntHeaderLen) && buf[0] == goTrntHeaderLen &&
		string(buf[1:1+goTrntHeaderLen]) == goTrntHeader {
		// This is handshake message, if first byte is length
		// of protocol name and bytes that follow it is
		// protocol name string itself.
		return MsgTypeHandshake, MsgTypeNames[MsgTypeHandshake]
	} else if len(buf) > 4 {
		// BitTorrent messages are of format <len><id><payload>,
		// where <len> is of four bytes.
		msgType := uint(buf[4])
		if msgType > MsgTypeInvalid {
			msgType = MsgTypeInvalid
		}
		return msgType, MsgTypeNames[msgType]
	}
	return MsgTypeInvalid, MsgTypeNames[MsgTypeInvalid]
}

// Decode raw buffer received from peer into our structs
func DecodeMessage(buf []byte) (MsgData, bool) {
	// Sanity checks
	if len(buf) <= 0 {
		return nil, false
	}

	// Get message type from buffer
	msgType, _ := GetMessageType(buf)

	// Remove <len> prefix from buffer, as we no longer need it.
	if msgType >= MsgTypeChoke && msgType <= MsgTypePort {
		buf = buf[4:]
	}

	switch msgType {
	case MsgTypeChoke, MsgTypeUnchoke:
		// <len=0001><id=0/1>
		var msgData MsgDataChoke
		msgData.MsgType = msgType
		if msgType == MsgTypeChoke {
			msgData.IsChoking = true
		} else {
			msgData.IsChoking = false
		}
		return msgData, true

	case MsgTypeInterested, MsgTypeNotInterested:
		// <len=0001><id=2/3>
		var msgData MsgDataInterested
		msgData.MsgType = msgType
		if msgType == MsgTypeInterested {
			msgData.IsInterested = true
		} else {
			msgData.IsInterested = false
		}
		return msgData, true

	case MsgTypeHave:
		// <id=4><piece index>
		var msgData MsgDataHave
		msgData.MsgType = msgType
		msgData.PieceIndex = getUint32FromBytes(buf[1:5])
		return msgData, true

	case MsgTypeBitfield:
		// <id=5><bitfield>
		var msgData MsgDataBitfield
		msgData.MsgType = msgType
		msgData.Bitfield = buf[1:]
		return msgData, true

	case MsgTypePiece:
		// <id=7><index><begin><block>
		var msgData MsgDataPiece
		msgData.MsgType = msgType
		msgData.PieceIndex = getUint32FromBytes(buf[1:5])
		msgData.PieceBytesBegin = getUint32FromBytes(buf[5:9])
		msgData.PieceBlock = buf[9:]
		return msgData, true

	case MsgTypeRequest, MsgTypeCancel:
		// <id=6/8><index><begin><length>
		var msgData MsgDataRequestCancel
		msgData.MsgType = msgType
		msgData.PieceIndex = getUint32FromBytes(buf[1:5])
		msgData.PieceBytesBegin = getUint32FromBytes(buf[5:9])
		msgData.PieceBytesLen = getUint32FromBytes(buf[9:13])
		return msgData, true

	case MsgTypePort:
		// <id=9><listen-port>
		var msgData MsgDataPort
		msgData.MsgType = msgType
		msgData.PeerPort = getUint16FromBytes(buf[1:3])
		return msgData, true

	case MsgTypeHandshake:
		// <pstrlen><pstr><reserved><info_hash><peer_id>
		var msgData MsgDataHandshake
		msgData.MsgType = msgType
		msgData.ProtocolStrLen = int(buf[0])
		msgData.ProtocolStr = string(buf[1:20])
		msgData.ReservedBytes = string(buf[20:28])
		msgData.InfoHash = string(buf[28:48])
		msgData.PeerId = string(buf[48:68])
		return msgData, true

	case MsgTypeKeepAlive:

	default:
	}
	return nil, false
}

// Build raw message buffer to send to a peer
// Message format: <length prefix><message ID><payload>
func EncodeMessage(msgType uint, msgData MsgData) ([]byte, bool) {
	buf := new(bytes.Buffer)

	switch msgType {
	case MsgTypeChoke, MsgTypeUnchoke, MsgTypeInterested, MsgTypeNotInterested:
		// <len=0001><id=0/1/2/3>
		buf.Write(getBytesFromUint32(1)) // len
		buf.WriteByte(byte(msgType))     // id
		return buf.Bytes(), true
	}

	// Sanity checks
	if msgData == nil {
		return buf.Bytes(), false
	}

	switch msgType {
	case MsgTypeHave:
		// <len=0005><id=4><piece index>
		msgHave, ok := msgData.(MsgDataHave)
		if !ok {
			return buf.Bytes(), false
		}
		buf.Write(getBytesFromUint32(5))                  // len
		buf.WriteByte(byte(4))                            // id
		buf.Write(getBytesFromUint32(msgHave.PieceIndex)) // piece index

	case MsgTypeBitfield:
		// <len=0001+X><id=5><bitfield>
		msgBitfield, ok := msgData.(MsgDataBitfield)
		if !ok || len(msgBitfield.Bitfield) <= 0 {
			return buf.Bytes(), false
		}
		msgLen := uint32(1 + len(msgBitfield.Bitfield))
		buf.Write(getBytesFromUint32(msgLen)) // len
		buf.WriteByte(byte(5))                // id
		buf.Write(msgBitfield.Bitfield)       // bitfield

	case MsgTypeRequest, MsgTypeCancel:
		// <len=0013><id=6/8><index><begin><length>
		msgReqCancl, ok := msgData.(MsgDataRequestCancel)
		if !ok {
			return buf.Bytes(), false
		}
		buf.Write(getBytesFromUint32(13)) // len
		if msgType == MsgTypeRequest {
			buf.WriteByte(byte(6)) // id
		} else {
			buf.WriteByte(byte(8)) // id
		}
		buf.Write(getBytesFromUint32(msgReqCancl.PieceIndex))      // piece index
		buf.Write(getBytesFromUint32(msgReqCancl.PieceBytesBegin)) // piece begin
		buf.Write(getBytesFromUint32(msgReqCancl.PieceBytesLen))   // piece len

	case MsgTypePiece:
		// <len=0009+X><id=7><index><begin><block>
		msgPiece, ok := msgData.(MsgDataPiece)
		if !ok || len(msgPiece.PieceBlock) <= 0 {
			return buf.Bytes(), false
		}
		msgLen := uint32(9 + len(msgPiece.PieceBlock))
		buf.Write(getBytesFromUint32(msgLen))                   // len
		buf.WriteByte(byte(7))                                  // id
		buf.Write(getBytesFromUint32(msgPiece.PieceIndex))      // peice index
		buf.Write(getBytesFromUint32(msgPiece.PieceBytesBegin)) // piece begin
		buf.Write(msgPiece.PieceBlock)                          // block

	case MsgTypePort:
		// <len=0003><id=9><listen-port>
		msgPort, ok := msgData.(MsgDataPort)
		if !ok {
			return buf.Bytes(), false
		}
		buf.Write(getBytesFromUint32(3))                // len
		buf.WriteByte(byte(9))                          // id
		buf.Write(getBytesFromUint16(msgPort.PeerPort)) // listen-port

	case MsgTypeHandshake:
		// <pstrlen><pstr><reserved><info_hash><peer_id>
		msgHs, ok := msgData.(MsgDataHandshake)
		if !ok {
			return buf.Bytes(), false
		}
		buf.WriteByte(goTrntHeaderLen) // pstrlen
		buf.WriteString(goTrntHeader)  // pstr
		for i := 0; i < 8; i++ {       // reserved
			buf.WriteByte(0)
		}
		buf.WriteString(msgHs.InfoHash) // info hash
		buf.WriteString(msgHs.PeerId)   // my id

	case MsgTypeKeepAlive:
		// <len=0000>
		buf.Write(getBytesFromUint32(0)) // len

	default:
		return buf.Bytes(), false
	}

	return buf.Bytes(), true
}

func getBytesFromUint32(num uint32) []byte {
	var buf [4]byte
	buf[0] = byte((num >> 24) & 0xff)
	buf[1] = byte((num >> 16) & 0xff)
	buf[2] = byte((num >> 8) & 0xff)
	buf[3] = byte(num & 0xff)
	return buf[0:]
}

func getBytesFromUint16(num uint16) []byte {
	var buf [2]byte
	buf[0] = byte((num >> 8) | 0xff)
	buf[1] = byte(num | 0xff)
	return buf[0:]
}

func getUint16FromBytes(buf []byte) uint16 {
	if len(buf) < 2 {
		return 0
	}
	return ((uint16(buf[0]) << 8) | uint16(buf[1]))
}

func getUint32FromBytes(buf []byte) uint32 {
	if len(buf) < 4 {
		return 0
	}
	return ((uint32(buf[0]) << 24) | (uint32(buf[1]) << 16) |
		(uint32(buf[2]) << 8) | uint32(buf[3]))
}
