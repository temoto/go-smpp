// Copyright 2015 go-smpp authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package pdufield

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fiorix/go-smpp/smpp/pdu/pdutext"
)

// TLV Tags
const (
	DestAddrSubunit          TLVTag = 0x0005
	DestNetworkType          TLVTag = 0x0006
	DestBearerType           TLVTag = 0x0007
	DestTelematicsID         TLVTag = 0x0008
	SourceAddrSubunit        TLVTag = 0x000D
	SourceNetworkType        TLVTag = 0x000E
	SourceBearerType         TLVTag = 0x000F
	SourceTelematicsID       TLVTag = 0x0010
	QosTimeToLive            TLVTag = 0x0017
	PayloadType              TLVTag = 0x0019
	AdditionalStatusInfoText TLVTag = 0x001D
	ReceiptedMessageID       TLVTag = 0x001E
	MsMsgWaitFacilities      TLVTag = 0x0030
	PrivacyIndicator         TLVTag = 0x0201
	SourceSubaddress         TLVTag = 0x0202
	DestSubaddress           TLVTag = 0x0203
	UserMessageReference     TLVTag = 0x0204
	UserResponseCode         TLVTag = 0x0205
	SourcePort               TLVTag = 0x020A
	DestinationPort          TLVTag = 0x020B
	SarMsgRefNum             TLVTag = 0x020C
	LanguageIndicator        TLVTag = 0x020D
	SarTotalSegments         TLVTag = 0x020E
	SarSegmentSeqnum         TLVTag = 0x020F
	CallbackNumPresInd       TLVTag = 0x0302
	CallbackNumAtag          TLVTag = 0x0303
	NumberOfMessages         TLVTag = 0x0304
	CallbackNum              TLVTag = 0x0381
	DpfResult                TLVTag = 0x0420
	SetDpf                   TLVTag = 0x0421
	MsAvailabilityStatus     TLVTag = 0x0422
	NetworkErrorCode         TLVTag = 0x0423
	MessagePayload           TLVTag = 0x0424
	DeliveryFailureReason    TLVTag = 0x0425
	MoreMessagesToSend       TLVTag = 0x0426
	MessageStateOption       TLVTag = 0x0427
	UssdServiceOp            TLVTag = 0x0501
	DisplayTime              TLVTag = 0x1201
	SmsSignal                TLVTag = 0x1203
	MsValidity               TLVTag = 0x1204
	AlertOnMessageDelivery   TLVTag = 0x130C
	ItsReplyType             TLVTag = 0x1380
	ItsSessionInfo           TLVTag = 0x1383
)

// TLV is the Tag Length Value.
type TLVTag uint16

// TLVBody represents data of a TLV field.
type TLVBody struct {
	Tag  TLVTag
	Len  uint16
	data []byte
}

// Bytes return raw TLV binary data.
func (tlv *TLVBody) Bytes() []byte {
	return tlv.data
}

func (tlv *TLVBody) Set(d []byte) *TLVBody {
	tlv.data = d
	tlv.Len = uint16(len(d))
	return tlv
}

// SerializeTo serializes TLV data to its binary form.
func (tlv *TLVBody) SerializeTo(w io.Writer) error {
	b := make([]byte, 4+len(tlv.data))
	binary.BigEndian.PutUint16(b[0:2], uint16(tlv.Tag))
	binary.BigEndian.PutUint16(b[2:4], tlv.Len)
	copy(b[4:], tlv.data)
	_, err := w.Write(b)
	return err
}

// TLVMap is a collection of PDU TLV field data indexed by tag.
type TLVMap map[TLVTag]*TLVBody

// Decode scans the given byte buffer to build a TLVMap from binary data.
func (t TLVMap) Decode(r *bytes.Buffer) error {
	for r.Len() >= 4 {
		b := r.Next(4)
		ft := TLVTag(binary.BigEndian.Uint16(b[0:2]))
		fl := binary.BigEndian.Uint16(b[2:4])
		if r.Len() < int(fl) {
			return fmt.Errorf("not enough data for tag %#x: want %d, have %d",
				ft, fl, r.Len())
		}
		b = r.Next(int(fl))
		t[ft] = &TLVBody{
			Tag:  ft,
			Len:  fl,
			data: b,
		}
	}
	return nil
}

// Set updates the PDU map with the given key and value, and
// returns error if the value cannot be converted to type Data.
//
// This is a shortcut for m[k] = New(k, v) converting v properly.
//
// If k is ShortMessage and v is of type pdutext.Codec, text is
// encoded and data_coding PDU and sm_length PDUs are set.
func (m TLVMap) Set(k TLVTag, v interface{}) error {
	tlv := &TLVBody{Tag: k}
	switch v.(type) {
	case nil:
		m[k] = tlv.Set(nil)
	case uint8:
		m[k] = tlv.Set([]byte{v.(uint8)})
	case int:
		m[k] = tlv.Set([]byte{uint8(v.(int))})
	case string:
		m[k] = tlv.Set([]byte(v.(string)))
	case []byte:
		m[k] = tlv.Set([]byte(v.([]byte)))
	case pdutext.Codec:
		m[k] = tlv.Set(v.(pdutext.Codec).Encode())
	default:
		return fmt.Errorf("unsupported field data: %#v", v)
	}
	return nil
}
