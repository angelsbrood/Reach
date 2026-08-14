// SPDX-License-Identifier: MIT

package netroutes

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
)

const (
	netlinkHeaderLength = 16
	routeMessageLength  = 12
	routeAttrLength     = 4
	nlmsgNoop           = 1
	nlmsgError          = 2
	nlmsgDone           = 3
	nlmsgOverrun        = 4
	rtmNewRoute         = 24
	rtaDestination      = 1
	addressFamilyIPv4   = 2
	nlmFDumpInterrupted = 0x10
	routeDumpSequence   = 1
)

type netlinkMessage struct {
	messageType uint16
	payload     []byte
}

func decodeNetlinkMessages(data []byte, expectedSequence, expectedPortID uint32) ([]netlinkMessage, error) {
	if len(data) == 0 {
		return nil, errors.New("empty netlink route response")
	}
	messages := make([]netlinkMessage, 0)
	for offset := 0; offset < len(data); {
		if len(data)-offset < netlinkHeaderLength {
			return nil, errors.New("truncated netlink header")
		}
		length := int(binary.NativeEndian.Uint32(data[offset : offset+4]))
		if length < netlinkHeaderLength || length > len(data)-offset {
			return nil, errors.New("invalid netlink message length")
		}
		alignedLength := align4(length)
		if alignedLength > len(data)-offset {
			return nil, errors.New("truncated netlink alignment padding")
		}
		flags := binary.NativeEndian.Uint16(data[offset+6 : offset+8])
		if flags&nlmFDumpInterrupted != 0 {
			return nil, errors.New("interrupted netlink route dump")
		}
		if binary.NativeEndian.Uint32(data[offset+8:offset+12]) != expectedSequence {
			return nil, errors.New("netlink route sequence mismatch")
		}
		if binary.NativeEndian.Uint32(data[offset+12:offset+16]) != expectedPortID {
			return nil, errors.New("netlink route sender mismatch")
		}
		messages = append(messages, netlinkMessage{
			messageType: binary.NativeEndian.Uint16(data[offset+4 : offset+6]),
			payload:     data[offset+netlinkHeaderLength : offset+length],
		})
		offset += alignedLength
	}
	return messages, nil
}

func inspectNetlinkChunk(data []byte, expectedSequence, expectedPortID uint32) (bool, error) {
	messages, err := decodeNetlinkMessages(data, expectedSequence, expectedPortID)
	if err != nil {
		return false, err
	}
	terminal := false
	for index, message := range messages {
		switch message.messageType {
		case rtmNewRoute:
			if terminal {
				return false, errors.New("route followed netlink terminator")
			}
		case nlmsgDone:
			if terminal || index != len(messages)-1 {
				return false, errors.New("invalid netlink terminator position")
			}
			if len(message.payload) != 0 {
				if len(message.payload) < 4 || int32(binary.NativeEndian.Uint32(message.payload[:4])) != 0 {
					return false, errors.New("netlink route dump terminated with error")
				}
			}
			terminal = true
		case nlmsgError:
			return false, errors.New("netlink route dump returned error")
		case nlmsgOverrun:
			return false, errors.New("netlink route dump overrun")
		case nlmsgNoop:
			return false, errors.New("unexpected netlink no-op")
		default:
			return false, errors.New("unexpected netlink route message")
		}
	}
	return terminal, nil
}

func ParseNetlinkRouteDump(data []byte, expectedSequence, expectedPortID uint32) ([]netip.Prefix, error) {
	messages, err := decodeNetlinkMessages(data, expectedSequence, expectedPortID)
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Prefix]struct{})
	terminal := false
	for index, message := range messages {
		switch message.messageType {
		case nlmsgDone:
			if terminal || index != len(messages)-1 {
				return nil, errors.New("invalid netlink terminator position")
			}
			if len(message.payload) != 0 {
				if len(message.payload) < 4 || int32(binary.NativeEndian.Uint32(message.payload[:4])) != 0 {
					return nil, errors.New("netlink route dump terminated with error")
				}
			}
			terminal = true
		case nlmsgError:
			return nil, errors.New("netlink route dump returned error")
		case nlmsgOverrun:
			return nil, errors.New("netlink route dump overrun")
		case nlmsgNoop:
			return nil, errors.New("unexpected netlink no-op")
		case rtmNewRoute:
			if terminal {
				return nil, errors.New("route followed netlink terminator")
			}
			payload := message.payload
			if len(payload) < routeMessageLength {
				return nil, errors.New("truncated route message")
			}
			family := payload[0]
			destinationBits := int(payload[1])
			if family != addressFamilyIPv4 || destinationBits == 0 {
				break
			}
			if destinationBits > 32 {
				return nil, errors.New("invalid route destination length")
			}
			attributes := payload[routeMessageLength:]
			var destination []byte
			for attributeOffset := 0; attributeOffset < len(attributes); {
				if len(attributes)-attributeOffset < routeAttrLength {
					return nil, errors.New("truncated route attribute")
				}
				attributeLength := int(binary.NativeEndian.Uint16(attributes[attributeOffset : attributeOffset+2]))
				attributeType := binary.NativeEndian.Uint16(attributes[attributeOffset+2:attributeOffset+4]) & 0x3fff
				if attributeLength < routeAttrLength || attributeLength > len(attributes)-attributeOffset {
					return nil, errors.New("invalid route attribute length")
				}
				if attributeOffset+align4(attributeLength) > len(attributes) {
					return nil, errors.New("truncated route attribute alignment padding")
				}
				if attributeType == rtaDestination {
					if destination != nil {
						return nil, errors.New("duplicate route destination")
					}
					destination = attributes[attributeOffset+routeAttrLength : attributeOffset+attributeLength]
				}
				attributeOffset += align4(attributeLength)
			}
			if len(destination) != 4 {
				return nil, errors.New("missing IPv4 route destination")
			}
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte(destination)), destinationBits).Masked()
			seen[prefix] = struct{}{}
		default:
			return nil, errors.New("unexpected netlink route message")
		}
	}
	if !terminal {
		return nil, errors.New("incomplete netlink route dump")
	}
	result := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func align4(value int) int { return (value + 3) &^ 3 }
