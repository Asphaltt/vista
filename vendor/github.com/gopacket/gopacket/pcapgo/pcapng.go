// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ErrNgVersionMismatch gets returned for unknown pcapng section versions. This can only happen if ReaderOptions.SkipUnknownVersion == false
var ErrNgVersionMismatch = errors.New("Unknown pcapng Version in Section Header")

// ErrNgLinkTypeMismatch gets returned if the link type of an interface is not the same as the link type from the first interface. This can only happen if ReaderOptions.ErrorOnMismatchingLinkType == true && ReaderOptions.WantMixedLinkType == false
var ErrNgLinkTypeMismatch = errors.New("Link type of current interface is different from first one")

const (
	ngByteOrderMagic = 0x1A2B3C4D

	// We can handle only version 1.0
	ngVersionMajor = 1
	ngVersionMinor = 0
)

type ngBlockType uint32

const (
	ngBlockTypeInterfaceDescriptor ngBlockType = 1          // Interface description block
	ngBlockTypePacket              ngBlockType = 2          // Packet block (deprecated)
	ngBlockTypeSimplePacket        ngBlockType = 3          // Simple packet block
	ngBlockTypeNameResolution      ngBlockType = 4          // Name resolution block
	ngBlockTypeInterfaceStatistics ngBlockType = 5          // Interface statistics block
	ngBlockTypeEnhancedPacket      ngBlockType = 6          // Enhanced packet block
	ngBlockTypeDecryptionSecrets   ngBlockType = 0x0000000A // Decryption secrets block
	ngBlockTypeSectionHeader       ngBlockType = 0x0A0D0D0A // Section header block (same in both endians)
)

const (
	/*
	 * Type describing the format of Decryption Secrets Block (DSB).
	 */
	DSB_SECRETS_TYPE_TLS            uint32 = 0x544c534b /* TLS Key Log */
	DSB_SECRETS_TYPE_SSH            uint32 = 0x5353484b /* SSH Key Log */
	DSB_SECRETS_TYPE_WIREGUARD      uint32 = 0x57474b4c /* WireGuard Key Log */
	DSB_SECRETS_TYPE_ZIGBEE_NWK_KEY uint32 = 0x5a4e574b /* Zigbee NWK Key */
	DSB_SECRETS_TYPE_ZIGBEE_APS_KEY uint32 = 0x5a415053 /* Zigbee APS Key */
)

// define error types for DSB
var (
	ErrUnknownSecretsType = errors.New("Unknown Decryption Secrets Block (DSB) type")
)

type ngOptionCode uint16

const (
	ngOptionCodeEndOfOptions    ngOptionCode = iota // end of options. must be at the end of options in a block
	ngOptionCodeComment                             // comment
	ngOptionCodeHardware                            // description of the hardware
	ngOptionCodeOS                                  // name of the operating system
	ngOptionCodeUserApplication                     // name of the application
)

const (
	ngOptionCodeInterfaceName                ngOptionCode = iota + 2 // interface name
	ngOptionCodeInterfaceDescription                                 // interface description
	ngOptionCodeInterfaceIPV4Address                                 // IPv4 network address and netmask for the interface
	ngOptionCodeInterfaceIPV6Address                                 // IPv6 network address and prefix length for the interface
	ngOptionCodeInterfaceMACAddress                                  // interface hardware MAC address
	ngOptionCodeInterfaceEUIAddress                                  // interface hardware EUI address
	ngOptionCodeInterfaceSpeed                                       // interface speed in bits/s
	ngOptionCodeInterfaceTimestampResolution                         // timestamp resolution
	ngOptionCodeInterfaceTimezone                                    // time zone
	ngOptionCodeInterfaceFilter                                      // capture filter
	ngOptionCodeInterfaceOS                                          // operating system
	ngOptionCodeInterfaceFCSLength                                   // length of the Frame Check Sequence in bits
	ngOptionCodeInterfaceTimestampOffset                             // offset (in seconds) that must be added to packet timestamp
)

const (
	ngOptionCodeInterfaceStatisticsStartTime         ngOptionCode = iota + 2 // Start of capture
	ngOptionCodeInterfaceStatisticsEndTime                                   // End of capture
	ngOptionCodeInterfaceStatisticsInterfaceReceived                         // Packets received by physical interface
	ngOptionCodeInterfaceStatisticsInterfaceDropped                          // Packets dropped by physical interface
	ngOptionCodeInterfaceStatisticsFilterAccept                              // Packets accepted by filter
	ngOptionCodeInterfaceStatisticsOSDrop                                    // Packets dropped by operating system
	ngOptionCodeInterfaceStatisticsDelivered                                 // Packets delivered to user
)

const (
	ngOptionCodeEnhancedPacketFlags   ngOptionCode = iota + 2 // Enhanced Packet Block flags
	ngOptionCodeEnhancedPacketHash                            // Enhanced Packet Block hash
	ngOptionCodeEnhancedPacketDrops                           // Enhanced Packet Block drops
	ngOptionCodeEnhancedPacketID                              // Enhanced Packet Block ID
	ngOptionCodeEnhancedPacketQueueID                         // Enhanced Packet Block queue ID
	ngOptionCodeEnhancedPacketVerdict                         // Enhanced Packet Block verdict
)

// EnhancedPacketFlag specify flag option for Enhanced Packet Block
type EnhancedPacketFlag uint32

// Packet direction. Bits 0-1 of EnhancedPacketFlag option
const (
	FlagEnhancedPacketDirectionUnknown  EnhancedPacketFlag = 0x00000000 // 00 = information not available
	FlagEnhancedPacketDirectionInbound                     = 0x00000001 // 01 = inbound
	FlagEnhancedPacketDirectionOutbound                    = 0x00000002 // 10 = outbound
	FlagEnhancedPacketDirectionMask                        = 0x00000003 // Packet direction mask
)

// Reception type. Bits 2-4 of EnhancedPacketFlag option
const (
	FlagEnhancedPacketReceptionTypeNotSpecified EnhancedPacketFlag = 0x00000000 // 000 = not specified
	FlagEnhancedPacketReceptionTypeUnicast                         = 0x00000004 // 001 = unicast
	FlagEnhancedPacketReceptionTypeMulticast                       = 0x00000008 // 010 = multicast
	FlagEnhancedPacketReceptionTypeBroadcast                       = 0x0000000C // 011 = broadcast
	FlagEnhancedPacketReceptionTypePromiscuous                     = 0x00000010 // 100 = promiscuous
	FlagEnhancedPacketReceptionTypeMask                            = 0x0000001C // Reception type mask
)

// Packet FCS. Bits 5-8 of EnhancedPacketFlag
const (
	FlagEnhancedPacketFCSLengthMask EnhancedPacketFlag = 0x000001E0 // Packet FCS length mask
)

// Packet link-layer-dependent errors. Bits 16-31 of EnhancedPacketFlag option
const (
	FlagEnhancedPacketErrorCRC            EnhancedPacketFlag = 0x01 << (iota + 24) // Bit 24 = CRC error
	FlagEnhancedPacketErrorLongPacket                                              // Bit 25 = packet too long error
	FlagEnhancedPacketErrorShortPacket                                             // Bit 26 = packet too short error
	FlagEnhancedPacketErrorFrameGap                                                // Bit 27 = wrong Inter Frame Gap error
	FlagEnhancedPacketErrorUnalignedFrame                                          // Bit 28 = unaligned frame error
	FlagEnhancedPacketErrorFrameDelimiter                                          // Bit 29 = Start Frame Delimiter error
	FlagEnhancedPacketErrorPreamble                                                // Bit 30 = preamble error
	FlagEnhancedPacketErrorSymbol                                                  // Bit 31 = symbol error
	FlagEnhancedPacketErrorMask           = 0xFFFF0000                             // Error mask
)

const (
	// Name Resolution Block: record types
	ngNameRecordEnd   uint16 = iota // End of name resolution records
	ngNameRecordIPv4                // IPv4 record
	ngNameRecordIPv6                // IPv6 record
	ngNameRecordEUI48               // EUI-48 record
	ngNameRecordEUI64               // EUI-64 record
)

// NgOption is a pcapng option
type NgOption struct {
	code   ngOptionCode
	value  []byte
	raw    interface{}
	length uint16
}

// NewOptionComment returns NgOption with a comment for Enhanced Packet Block.
func NewOptionComment(comment string) NgOption {
	return NgOption{
		code:   ngOptionCodeComment,
		raw:    comment,
		length: uint16(len(comment)),
	}
}

// NewOptionEnhancedPacketFlags returns NgOption with flags for Enhanced Packet
// Block.
func NewOptionEnhancedPacketFlags(flag EnhancedPacketFlag) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketFlags,
		raw:    uint32(flag),
		length: 4,
	}
}

// NewOptionEnhancedPacketHash returns NgOption with a hash for Enhanced Packet
// Block.
func NewOptionEnhancedPacketHash(hash []byte) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketHash,
		value:  hash,
		length: uint16(len(hash)),
	}
}

// NewOptionEnhancedPacketDrops returns NgOption with drops for Enhanced Packet
// Block.
func NewOptionEnhancedPacketDrops(drops uint64) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketDrops,
		raw:    drops,
		length: 8,
	}
}

// NewOptionEnhancedPacketID returns NgOption with ID for Enhanced Packet Block.
func NewOptionEnhancedPacketID(id uint64) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketID,
		raw:    id,
		length: 8,
	}
}

// NewOptionEnhancedPacketQueueID returns NgOption with queue ID for Enhanced
// Packet Block.
func NewOptionEnhancedPacketQueueID(queueID uint32) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketQueueID,
		raw:    queueID,
		length: 4,
	}
}

// NewOptionEnhancedPacketVerdict returns NgOption with verdict for Enhanced
// Packet Block.
func NewOptionEnhancedPacketVerdict(verdict []byte) NgOption {
	return NgOption{
		code:   ngOptionCodeEnhancedPacketVerdict,
		raw:    verdict,
		length: uint16(len(verdict)),
	}
}

// ngBlock is a pcapng block header
type ngBlock struct {
	typ    ngBlockType
	length uint32 // remaining length of block
}

// NgResolution represents a pcapng timestamp resolution
type NgResolution uint8

// Binary returns true if the timestamp resolution is a negative power of two. Otherwise NgResolution is a negative power of 10.
func (r NgResolution) Binary() bool {
	if r&0x80 == 0x80 {
		return true
	}
	return false
}

// Exponent returns the negative exponent of the resolution.
func (r NgResolution) Exponent() uint8 {
	return uint8(r) & 0x7f
}

// ToTimestampResolution converts an NgResolution to a gopaket.TimestampResolution
func (r NgResolution) ToTimestampResolution() (ret gopacket.TimestampResolution) {
	if r.Binary() {
		ret.Base = 2
	} else {
		ret.Base = 10
	}
	ret.Exponent = -int(r.Exponent())
	return
}

// NgNoValue64 is a placeholder for an empty numeric 64 bit value.
const NgNoValue64 = math.MaxUint64

// NgInterfaceStatistics hold the statistic for an interface at a single point in time. These values are already supposed to be accumulated. Most pcapng files contain this information at the end of the file/section.
type NgInterfaceStatistics struct {
	// LastUpdate is the last time the statistics were updated.
	LastUpdate time.Time
	// StartTime is the time packet capture started on this interface. This value might be zero if this option is missing.
	StartTime time.Time
	// EndTime is the time packet capture ended on this interface This value might be zero if this option is missing.
	EndTime time.Time
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsReceived uint64
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsDropped uint64
}

var ngEmptyStatistics = NgInterfaceStatistics{
	PacketsReceived: NgNoValue64,
	PacketsDropped:  NgNoValue64,
}

// NgInterface holds all the information of a pcapng interface.
type NgInterface struct {
	// Name is the name of the interface. This value might be empty if this option is missing.
	Name string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// Description is a description of the interface. This value might be empty if this option is missing.
	Description string
	// Filter is the filter used during packet capture. This value might be empty if this option is missing.
	Filter string
	// OS is the operating system this interface was controlled by. This value might be empty if this option is missing.
	OS string
	// LinkType is the linktype of the interface.
	LinkType layers.LinkType
	// TimestampResolution is the timestamp resolution of the packets in the pcapng file belonging to this interface.
	TimestampResolution NgResolution
	// TimestampResolution is the timestamp offset in seconds of the packets in the pcapng file belonging to this interface.
	TimestampOffset uint64
	// SnapLength is the maximum packet length captured by this interface. 0 for unlimited
	SnapLength uint32
	// Statistics holds the interface statistics
	Statistics NgInterfaceStatistics

	secondMask uint64
	scaleUp    uint64
	scaleDown  uint64
}

// Resolution returns the timestamp resolution of acquired timestamps before scaling to NanosecondTimestampResolution.
func (i NgInterface) Resolution() gopacket.TimestampResolution {
	return i.TimestampResolution.ToTimestampResolution()
}

// NgSectionInfo contains additional information of a pcapng section
type NgSectionInfo struct {
	// Hardware is the hardware this file was generated on. This value might be empty if this option is missing.
	Hardware string
	// OS is the operating system this file was generated on. This value might be empty if this option is missing.
	OS string
	// Application is the user space application this file was generated with. This value might be empty if this option is missing.
	Application string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
}

type ngAddressType uint16

const (
	ngAddressIPv4 uint16 = iota
	ngAddressIPv6
	ngAddressEUI48
	ngAddressEUI64
)

type NgAddress interface {
	Len() int
}

type NgIPAddress struct {
	Addr netip.Addr
}

func (addr *NgIPAddress) Len() int {
	return addr.Addr.BitLen() / 8
}

type NgEUIAddress struct {
	Addr net.HardwareAddr
}

func (addr *NgEUIAddress) Len() int {
	return len(addr.Addr)
}

type NgNameRecord struct {
	Addr  NgAddress
	Names []string
}
