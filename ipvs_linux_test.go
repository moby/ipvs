package ipvs

import (
	"net"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/moby/ipvs/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var (
	schedMethods = []string{
		RoundRobin,
		LeastConnection,
		DestinationHashing,
		SourceHashing,
		WeightedLeastConnection,
		WeightedRoundRobin,
	}

	protocols = []string{
		"TCP",
		"UDP",
		"FWM",
	}

	fwdMethods = []uint32{
		ConnectionFlagMasq,
		ConnectionFlagTunnel,
		ConnectionFlagDirectRoute,
	}

	fwdMethodStrings = []string{
		"Masq",
		"Tunnel",
		"Route",
	}
)

func lookupFwMethod(fwMethod uint32) string {
	switch fwMethod {
	case ConnectionFlagMasq:
		return fwdMethodStrings[0]
	case ConnectionFlagTunnel:
		return fwdMethodStrings[1]
	case ConnectionFlagDirectRoute:
		return fwdMethodStrings[2]
	}
	return ""
}

func checkDestination(t *testing.T, i *Handle, s *Service, d *Destination, checkPresent bool) {
	var dstFound bool

	dstArray, err := i.GetDestinations(s)
	if err != nil {
		t.Fatalf("Failed to get destination; %v", err)
	}

	for _, dst := range dstArray {
		if dst.Address.Equal(d.Address) && dst.Port == d.Port &&
			lookupFwMethod(dst.ConnectionFlags) == lookupFwMethod(d.ConnectionFlags) &&
			dst.AddressFamily == d.AddressFamily {
			dstFound = true
			break
		}
	}

	switch checkPresent {
	case true: // The test expects the service to be present
		if !dstFound {
			t.Fatalf("Did not find the service %s in ipvs output", d.Address.String())
		}
	case false: // The test expects that the service should not be present
		if dstFound {
			t.Fatalf("Did not find the destination %s fwdMethod %s in ipvs output", d.Address.String(), lookupFwMethod(d.ConnectionFlags))
		}
	}
}

func checkService(t *testing.T, i *Handle, s *Service, checkPresent bool) {
	svcArray, err := i.GetServices()
	if err != nil {
		t.Fatalf("Failed to get service; %v", err)
	}

	var svcFound bool

	for _, svc := range svcArray {
		if svc.Protocol == s.Protocol && svc.Address.String() == s.Address.String() && svc.Port == s.Port {
			svcFound = true
			break
		}
	}

	switch checkPresent {
	case true: // The test expects the service to be present
		if !svcFound {
			t.Fatalf("Did not find the service %s in ipvs output", s.Address.String())
		}
	case false: // The test expects that the service should not be present
		if svcFound {
			t.Fatalf("Did not expect the service %s in ipvs output", s.Address.String())
		}
	}
}

func TestGetFamily(t *testing.T) {
	id, err := getIPVSFamily()
	if err != nil {
		t.Fatal("Failed to get IPVS family:", err)
	}
	if id == 0 {
		t.Error("IPVS family was 0")
	}
}

func TestService(t *testing.T) {
	defer setupTestOSContext(t)()

	i, err := New("")
	if err != nil {
		t.Fatal("Failed to create IPVS handle:", err)
	}

	for _, protocol := range protocols {
		for _, schedMethod := range schedMethods {
			testDatas := []struct {
				AddressFamily uint16
				IP            string
				Netmask       uint32
			}{
				{
					AddressFamily: nl.FAMILY_V4,
					IP:            "1.2.3.4",
					Netmask:       0xFFFFFFFF,
				}, {
					AddressFamily: nl.FAMILY_V6,
					IP:            "2001:db8:3c4d:15::1a00",
					Netmask:       128,
				},
			}
			for _, td := range testDatas {
				s := Service{
					AddressFamily: td.AddressFamily,
					SchedName:     schedMethod,
				}

				switch protocol {
				case "FWM":
					s.FWMark = 1234
					s.Netmask = td.Netmask
				case "TCP":
					s.Protocol = unix.IPPROTO_TCP
					s.Port = 80
					s.Address = net.ParseIP(td.IP)
					s.Netmask = td.Netmask
				case "UDP":
					s.Protocol = unix.IPPROTO_UDP
					s.Port = 53
					s.Address = net.ParseIP(td.IP)
					s.Netmask = td.Netmask
				}

				err := i.NewService(&s)
				if err != nil {
					t.Fatal("Failed to create service:", err)
				}
				checkService(t, i, &s, true)
				for _, updateSchedMethod := range schedMethods {
					if updateSchedMethod == schedMethod {
						continue
					}

					s.SchedName = updateSchedMethod
					err = i.UpdateService(&s)
					if err != nil {
						t.Fatal("Failed to update service:", err)
					}
					checkService(t, i, &s, true)

					scopy, err := i.GetService(&s)
					if err != nil {
						t.Fatal("Failed to get service:", err)
					}
					if expected := (*scopy).Address.String(); expected != s.Address.String() {
						t.Errorf("expected: %v, got: %v", expected, s.Address.String())
					}
					if expected := (*scopy).Port; expected != s.Port {
						t.Errorf("expected: %v, got: %v", expected, s.Port)
					}
					if expected := (*scopy).Protocol; expected != s.Protocol {
						t.Errorf("expected: %v, got: %v", expected, s.Protocol)
					}
				}

				err = i.DelService(&s)
				if err != nil {
					t.Fatal("Failed to delete service:", err)
				}
				checkService(t, i, &s, false)
			}
		}
	}

	svcs := []Service{
		{
			AddressFamily: nl.FAMILY_V4,
			SchedName:     RoundRobin,
			Protocol:      unix.IPPROTO_TCP,
			Port:          80,
			Address:       net.ParseIP("10.20.30.40"),
			Netmask:       0xFFFFFFFF,
		},
		{
			AddressFamily: nl.FAMILY_V4,
			SchedName:     LeastConnection,
			Protocol:      unix.IPPROTO_UDP,
			Port:          8080,
			Address:       net.ParseIP("10.20.30.41"),
			Netmask:       0xFFFFFFFF,
		},
	}
	// Create services for testing flush
	for _, svc := range svcs {
		if !i.IsServicePresent(&svc) {
			err = i.NewService(&svc)
			if err != nil {
				t.Fatal("Failed to create service:", err)
			}
			checkService(t, i, &svc, true)
		} else {
			t.Errorf("svc: %v exists", svc)
		}
	}
	err = i.Flush()
	if err != nil {
		t.Fatal("Failed to flush:", err)
	}
	got, err := i.GetServices()
	if err != nil {
		t.Fatal("Failed to get service:", err)
	}
	if len(got) != 0 {
		t.Errorf("Unexpected services after flush")
	}
}

func createDummyInterface(t *testing.T) {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: "dummy",
		},
	}

	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatal("Failed to add link:", err)
	}

	dummyLink, err := netlink.LinkByName("dummy")
	if err != nil {
		t.Fatal("Failed to get dummy link:", err)
	}

	ip, ipNet, err := net.ParseCIDR("10.1.1.1/24")
	if err != nil {
		t.Fatal("Failed to parse CIDR:", err)
	}

	ipNet.IP = ip

	ipAddr := &netlink.Addr{IPNet: ipNet, Label: ""}
	err = netlink.AddrAdd(dummyLink, ipAddr)
	if err != nil {
		t.Fatal("Failed to add IP address:", err)
	}
}

func TestDestination(t *testing.T) {
	defer setupTestOSContext(t)()

	createDummyInterface(t)
	i, err := New("")
	if err != nil {
		t.Fatal("Failed to create IPVS handle:", err)
	}

	for _, protocol := range protocols {
		testDatas := []struct {
			AddressFamily uint16
			IP            string
			Netmask       uint32
			Destinations  []string
		}{
			{
				AddressFamily: nl.FAMILY_V4,
				IP:            "1.2.3.4",
				Netmask:       0xFFFFFFFF,
				Destinations:  []string{"10.1.1.2", "10.1.1.3", "10.1.1.4"},
			}, {
				AddressFamily: nl.FAMILY_V6,
				IP:            "2001:db8:3c4d:15::1a00",
				Netmask:       128,
				Destinations:  []string{"2001:db8:3c4d:15::1a2b", "2001:db8:3c4d:15::1a2c", "2001:db8:3c4d:15::1a2d"},
			},
		}
		for _, td := range testDatas {
			s := Service{
				AddressFamily: td.AddressFamily,
				SchedName:     RoundRobin,
			}

			switch protocol {
			case "FWM":
				s.FWMark = 1234
				s.Netmask = td.Netmask
			case "TCP":
				s.Protocol = unix.IPPROTO_TCP
				s.Port = 80
				s.Address = net.ParseIP(td.IP)
				s.Netmask = td.Netmask
			case "UDP":
				s.Protocol = unix.IPPROTO_UDP
				s.Port = 53
				s.Address = net.ParseIP(td.IP)
				s.Netmask = td.Netmask
			}

			err := i.NewService(&s)
			if err != nil {
				t.Fatal("Failed to create service:", err)
			}
			checkService(t, i, &s, true)

			s.SchedName = ""
			for _, fwdMethod := range fwdMethods {
				destinations := make([]Destination, 0)
				for _, ip := range td.Destinations {
					d := Destination{
						AddressFamily:   td.AddressFamily,
						Address:         net.ParseIP(ip),
						Port:            5000,
						Weight:          1,
						ConnectionFlags: fwdMethod,
					}
					destinations = append(destinations, d)
					err := i.NewDestination(&s, &d)
					if err != nil {
						t.Fatal("Failed to create destination:", err)
					}
					checkDestination(t, i, &s, &d, true)
				}

				for _, updateFwdMethod := range fwdMethods {
					if updateFwdMethod == fwdMethod {
						continue
					}
					for _, d := range destinations {
						d.ConnectionFlags = updateFwdMethod
						err = i.UpdateDestination(&s, &d)
						if err != nil {
							t.Fatal("Failed to update destination:", err)
						}
						checkDestination(t, i, &s, &d, true)
					}
				}
				for _, d := range destinations {
					err = i.DelDestination(&s, &d)
					if err != nil {
						t.Fatal("Failed to delete destination:", err)
					}
					checkDestination(t, i, &s, &d, false)
				}
			}

		}
	}
}

func TestTimeouts(t *testing.T) {
	defer setupTestOSContext(t)()

	i, err := New("")
	if err != nil {
		t.Fatal("Failed to create IPVS handle:", err)
	}

	_, err = i.GetConfig()
	if err != nil {
		t.Fatal("Failed to get config:", err)
	}

	cfg := Config{66 * time.Second, 66 * time.Second, 66 * time.Second}
	err = i.SetConfig(&cfg)
	if err != nil {
		t.Fatal("Failed to set config:", err)
	}

	c2, err := i.GetConfig()
	if err != nil {
		t.Fatal("Failed to get config:", err)
	}
	if !reflect.DeepEqual(*c2, cfg) {
		t.Fatalf("expected: %+v, got: %+v", cfg, *c2)
	}

	//  A timeout value 0 means that the current timeout value of the corresponding entry is preserved
	cfg = Config{77 * time.Second, 0 * time.Second, 77 * time.Second}
	err = i.SetConfig(&cfg)
	if err != nil {
		t.Fatal("Failed to set config:", err)
	}

	c3, err := i.GetConfig()
	if err != nil {
		t.Fatal("Failed to get config:", err)
	}
	expected := Config{77 * time.Second, 66 * time.Second, 77 * time.Second}
	if !reflect.DeepEqual(*c3, expected) {
		t.Fatalf("expected: %+v, got: %+v", expected, *c3)
	}
}

// setupTestOSContext joins a new network namespace, and returns its associated
// teardown function.
//
// Example usage:
//
//	defer setupTestOSContext(t)()
func setupTestOSContext(t *testing.T) func() {
	t.Helper()
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		t.Fatalf("Failed to enter netns: %v", err)
	}

	fd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal("Failed to open netns file:", err)
	}

	// Since we are switching to a new test namespace make
	// sure to re-initialize initNs context
	ns.Init()

	runtime.LockOSThread()

	return func() {
		if err := syscall.Close(fd); err != nil {
			t.Logf("Warning: netns closing failed (%v)", err)
		}
		runtime.UnlockOSThread()
	}
}
