package ns

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// NetlinkSocketsTimeout represents the default timeout duration for the sockets
const NetlinkSocketsTimeout = 3 * time.Second

// Init initializes the initial network namespace handles.
func Init() {
	_, _ = initHandles()
}

type handles struct {
	ns netns.NsHandle
	nl *netlink.Handle
}

var initHandles = sync.OnceValues(func() (handles, error) {
	ns, err := netns.Get()
	if err != nil {
		return handles{}, fmt.Errorf("get initial namespace: %w", err)
	}

	nl, err := netlink.NewHandle(getSupportedNlFamilies()...)
	if err != nil {
		_ = ns.Close()
		return handles{}, fmt.Errorf("create netlink handle: %w", err)
	}

	if err := nl.SetSocketTimeout(NetlinkSocketsTimeout); err != nil {
		nl.Close()
		_ = ns.Close()
		return handles{}, fmt.Errorf("set netlink socket timeout: %w", err)
	}

	return handles{ns: ns, nl: nl}, nil
})

// SetNamespace sets the initial namespace handler
func SetNamespace() error {
	h, err := initHandles()
	if err != nil {
		return fmt.Errorf("initialize namespace: %w", err)
	}

	if err := netns.Set(h.ns); err != nil {
		linkInfo, linkErr := getLink()
		if linkErr != nil {
			linkInfo = linkErr.Error()
		}
		return fmt.Errorf("failed to set to initial namespace, %v, initns fd %d: %w", linkInfo, h.ns, err)
	}
	return nil
}

// ParseHandlerInt transforms the namespace handler into an integer
func ParseHandlerInt() int {
	h, _ := initHandles()
	return int(h.ns)
}

func getLink() (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid()))
}

// NlHandle returns the netlink handler
func NlHandle() *netlink.Handle {
	h, _ := initHandles()
	return h.nl
}

func getSupportedNlFamilies() []int {
	fams := []int{unix.NETLINK_ROUTE}

	if err := checkXfrmSocket(); err == nil {
		fams = append(fams, unix.NETLINK_XFRM)
	}
	if err := checkNfSocket(); err == nil {
		fams = append(fams, unix.NETLINK_NETFILTER)
	}

	return fams
}

// API check on required xfrm modules (xfrm_user, xfrm_algo)
func checkXfrmSocket() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_XFRM)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// API check on required nf_conntrack* modules (nf_conntrack, nf_conntrack_netlink)
func checkNfSocket() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}
