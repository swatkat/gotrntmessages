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
	getMsgType() (uint, string)
}

// Base data struct for peer messages
type MsgDataCommon struct {
	msgType uint
}

// Base data struct implements interface method
func (msgDataCmn MsgDataCommon) getMsgType() (uint, string) {
	return msgDataCmn.msgType, MsgTypeNames[msgDataCmn.msgType]
}

// Choke and Unchoke messages
type MsgDataChoke struct {
	MsgDataCommon
	isChoking bool
}

// Interested and Not Interested messages
type MsgDataInterested struct {
	MsgDataCommon
	isInterested bool
}

// Have message
type MsgDataHave struct {
	MsgDataCommon
	pieceIndex uint32
}

// Bitfield message
type MsgDataBitfield struct {
	MsgDataCommon
	bitfieldBytes []byte
}

// Request and cancel messages
type MsgDataRequestCancel struct {
	MsgDataCommon
	pieceIndex      uint32
	pieceBytesBegin uint32
	pieceBytesLen   uint32
}

// Piece message
type MsgDataPiece struct {
	MsgDataCommon
	pieceIndex      uint32
	pieceBytesBegin uint32
	pieceBlock      []byte
}

// Handshake message
type MsgDataHandshake struct {
	MsgDataCommon
	protocolStrLen int
	protocolStr    string
	reservedBytes  string
	infoHash       string
	peerId         string
}

// Port message
type MsgDataPort struct {
	MsgDataCommon
	peerPort uint16
}

// Gets message type from raw buffer received from peer
func GetMessageType(buf []byte) (uint, string) {
	bufLen := len(buf)
	if bufLen <= 0 {
		return MsgTypeInvalid, MsgTypeNames[MsgTypeInvalid]
	}
	if bufLen > int(goTrntHeaderLen) && buf[0] == goTrntHeaderLen &&
		string(buf[1:1+goTrntHeaderLen]) == goTrntHeader {
		/*
		 * This is handshake message if first byte is length
		 * of protocol name and bytes that follow it is
		 * protocol name string itself.
		 */
		return MsgTypeHandshake, MsgTypeNames[MsgTypeHandshake]
	} else if buf[0] >= MsgTypeChoke && buf[0] <= MsgTypePort {
		/*
		 * BitTorrent messages are of format <len><id><payload>.
		 * But, <len> is already read by PeerInfo.ReadMessageLenFromPeer().
		 * Here we just have buffer starting from <id> itself. So,
		 * just return first byte itself as message type.
		 */
		msgType := uint(buf[0])
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
	switch msgType {
	case MsgTypeChoke, MsgTypeUnchoke:
		// <len=0001><id=0/1>
		var msgData MsgDataChoke
		msgData.msgType = msgType
		if msgType == MsgTypeChoke {
			msgData.isChoking = true
		} else {
			msgData.isChoking = false
		}
		return msgData, true

	case MsgTypeInterested, MsgTypeNotInterested:
		// <len=0001><id=2/3>
		var msgData MsgDataInterested
		msgData.msgType = msgType
		if msgType == MsgTypeInterested {
			msgData.isInterested = true
		} else {
			msgData.isInterested = false
		}
		return msgData, true

	case MsgTypeHave:
		// <id=4><piece index>
		var msgData MsgDataHave
		msgData.msgType = msgType
		msgData.pieceIndex = getUint32FromBytes(buf[1:5])
		return msgData, true

	case MsgTypeBitfield:
		// <id=5><bitfield>
		var msgData MsgDataBitfield
		msgData.msgType = msgType
		msgData.bitfieldBytes = buf[1:]
		return msgData, true

	case MsgTypePiece:
		// <id=7><index><begin><block>
		var msgData MsgDataPiece
		msgData.msgType = msgType
		msgData.pieceIndex = getUint32FromBytes(buf[1:5])
		msgData.pieceBytesBegin = getUint32FromBytes(buf[5:9])
		msgData.pieceBlock = buf[9:]
		return msgData, true

	case MsgTypeRequest, MsgTypeCancel:
		// <id=6/8><index><begin><length>
		var msgData MsgDataRequestCancel
		msgData.msgType = msgType
		msgData.pieceIndex = getUint32FromBytes(buf[1:5])
		msgData.pieceBytesBegin = getUint32FromBytes(buf[5:9])
		msgData.pieceBytesLen = getUint32FromBytes(buf[9:13])
		return msgData, true

	case MsgTypePort:
		// <id=9><listen-port>
		var msgData MsgDataPort
		msgData.msgType = msgType
		msgData.peerPort = getUint16FromBytes(buf[1:3])
		return msgData, true

	case MsgTypeHandshake:
		// <pstrlen><pstr><reserved><info_hash><peer_id>
		var msgData MsgDataHandshake
		msgData.msgType = msgType
		msgData.protocolStrLen = int(buf[0])
		msgData.protocolStr = string(buf[1:20])
		msgData.reservedBytes = string(buf[20:28])
		msgData.infoHash = string(buf[28:48])
		msgData.peerId = string(buf[48:68])
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
		buf.Write(getBytesFromUint32(msgHave.pieceIndex)) // piece index

	case MsgTypeBitfield:
		// <len=0001+X><id=5><bitfield>
		msgBitfield, ok := msgData.(MsgDataBitfield)
		if !ok || len(msgBitfield.bitfieldBytes) <= 0 {
			return buf.Bytes(), false
		}
		msgLen := uint32(1 + len(msgBitfield.bitfieldBytes))
		buf.Write(getBytesFromUint32(msgLen)) // len
		buf.WriteByte(byte(5))                // id
		buf.Write(msgBitfield.bitfieldBytes)  // bitfield

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
		buf.Write(getBytesFromUint32(msgReqCancl.pieceIndex))      // piece index
		buf.Write(getBytesFromUint32(msgReqCancl.pieceBytesBegin)) // piece begin
		buf.Write(getBytesFromUint32(msgReqCancl.pieceBytesLen))   // piece len

	case MsgTypePiece:
		// <len=0009+X><id=7><index><begin><block>
		msgPiece, ok := msgData.(MsgDataPiece)
		if !ok || len(msgPiece.pieceBlock) <= 0 {
			return buf.Bytes(), false
		}
		msgLen := uint32(9 + len(msgPiece.pieceBlock))
		buf.Write(getBytesFromUint32(msgLen))                   // len
		buf.WriteByte(byte(7))                                  // id
		buf.Write(getBytesFromUint32(msgPiece.pieceIndex))      // peice index
		buf.Write(getBytesFromUint32(msgPiece.pieceBytesBegin)) // piece begin
		buf.Write(msgPiece.pieceBlock)                          // block

	case MsgTypePort:
		// <len=0003><id=9><listen-port>
		msgPort, ok := msgData.(MsgDataPort)
		if !ok {
			return buf.Bytes(), false
		}
		buf.Write(getBytesFromUint32(3))                // len
		buf.WriteByte(byte(9))                          // id
		buf.Write(getBytesFromUint16(msgPort.peerPort)) // listen-port

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
		buf.WriteString(msgHs.infoHash) // info hash
		buf.WriteString(msgHs.peerId)   // my id

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
