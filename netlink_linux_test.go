package ipvs

import (
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// unknownAttrType represents an unrecognized netlink attribute,
// used to verify that unknown attributes are ignored.
const unknownAttrType = 0x7fff

func Test_getIPFamily(t *testing.T) {
	testcases := []struct {
		name           string
		address        []byte
		expectedFamily uint16
		expectedErr    error
	}{
		{
			name:           "16 byte IPv4 10.0.0.1",
			address:        []byte{10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedFamily: syscall.AF_INET,
			expectedErr:    nil,
		},
		{
			name:           "16 byte IPv6 2001:db8:3c4d:15::1a00",
			address:        []byte{32, 1, 13, 184, 60, 77, 0, 21, 0, 0, 0, 0, 0, 0, 26, 0},
			expectedFamily: syscall.AF_INET6,
			expectedErr:    nil,
		},
		{
			name:           "zero address",
			address:        []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedFamily: 0,
			expectedErr:    errors.New("could not parse IP family from address data"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			family, err := getIPFamily(tc.address)
			if !reflect.DeepEqual(err, tc.expectedErr) {
				t.Logf("got err: %v", err)
				t.Logf("expected err: %v", tc.expectedErr)
				t.Errorf("unexpected error")
			}

			if family != tc.expectedFamily {
				t.Logf("got IP family: %v", family)
				t.Logf("expected IP family: %v", tc.expectedFamily)
				t.Errorf("unexpected IP family")
			}
		})
	}
}

func Test_AssembleService(t *testing.T) {
	tests := []struct {
		name  string
		attrs []syscall.NetlinkRouteAttr
		want  Service
	}{
		{
			name: "IPv4 service",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)},
					Value: net.IPv4(192, 0, 2, 1).To4(),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)},
					Value: nl.Uint16Attr(unix.AF_INET),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrProtocol)},
					Value: nl.Uint16Attr(unix.IPPROTO_TCP),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrPort)},
					Value: []byte{0x00, 0x50},
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrSchedName)},
					Value: nl.ZeroTerminated("rr"),
				},
				{
					// Unknown attributes should be ignored for forward compatibility.
					Attr:  syscall.RtAttr{Type: unknownAttrType},
					Value: []byte{1, 2, 3, 4},
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrPEName)},
					Value: nl.ZeroTerminated("sip"),
				},
			},
			want: Service{
				AddressFamily: unix.AF_INET,
				Address:       net.IPv4(192, 0, 2, 1).To4(),
				Protocol:      unix.IPPROTO_TCP,
				Port:          80,
				SchedName:     "rr",
				PEName:        "sip",
			},
		},
		{
			name: "IPv6 service",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)},
					Value: nl.Uint16Attr(unix.AF_INET6),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)},
					Value: net.ParseIP("2001:db8::1").To16(),
				},
			},
			want: Service{
				AddressFamily: unix.AF_INET6,
				Address:       net.ParseIP("2001:db8::1"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assembleService(tc.attrs)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("assembleService() = %+v, want %+v", *got, tc.want)
			}
		})
	}
}

func Test_AssembleDestination(t *testing.T) {
	tests := []struct {
		name  string
		attrs []syscall.NetlinkRouteAttr
		want  Destination
	}{
		{
			name: "IPv4 destination",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrAddress)},
					Value: net.IPv4(192, 0, 2, 2).To4(),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrAddressFamily)},
					Value: nl.Uint16Attr(unix.AF_INET),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrPort)},
					Value: []byte{0x1f, 0x90},
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrWeight)},
					Value: nl.Uint32Attr(65536),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrActiveConnections)},
					Value: nl.Uint32Attr(10),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrInactiveConnections)},
					Value: nl.Uint32Attr(20),
				},
				{
					// Unknown attributes should be ignored for forward compatibility.
					Attr:  syscall.RtAttr{Type: unknownAttrType},
					Value: []byte{1, 2, 3, 4},
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrPersistentConnections)},
					Value: nl.Uint32Attr(30),
				},
			},
			want: Destination{
				AddressFamily:         unix.AF_INET,
				Address:               net.IPv4(192, 0, 2, 2).To4(),
				Port:                  8080,
				Weight:                65536,
				ActiveConnections:     10,
				InactiveConnections:   20,
				PersistentConnections: 30,
			},
		},
		{
			name: "IPv6 destination",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrAddressFamily)},
					Value: nl.Uint16Attr(unix.AF_INET6),
				},
				{
					Attr:  syscall.RtAttr{Type: uint16(ipvsDestAttrAddress)},
					Value: net.ParseIP("2001:db8::2").To16(),
				},
			},
			want: Destination{
				AddressFamily: unix.AF_INET6,
				Address:       net.ParseIP("2001:db8::2"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assembleDestination(tc.attrs)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("assembleDestination() = %+v, want %+v", *got, tc.want)
			}
		})
	}
}
