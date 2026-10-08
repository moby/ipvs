package ipvs

import "golang.org/x/sys/unix"

const (
	genlCtrlID = unix.GENL_ID_CTRL
)

// Generic netlink controller constants.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/genetlink.h#L36-L53
const (
	genlCtrlCmdUnspec    = unix.CTRL_CMD_UNSPEC
	genlCtrlCmdNewFamily = unix.CTRL_CMD_NEWFAMILY
	genlCtrlCmdDelFamily = unix.CTRL_CMD_DELFAMILY
	genlCtrlCmdGetFamily = unix.CTRL_CMD_GETFAMILY
)

// Generic netlink family attributes.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/genetlink.h#L57-L70
const (
	genlCtrlAttrUnspec     = unix.CTRL_ATTR_UNSPEC
	genlCtrlAttrFamilyID   = unix.CTRL_ATTR_FAMILY_ID
	genlCtrlAttrFamilyName = unix.CTRL_ATTR_FAMILY_NAME
)

// IPVS generic netlink commands.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/ip_vs.h#L301-L329
const (
	ipvsCmdUnspec     = 0  // IPVS_CMD_UNSPEC
	ipvsCmdNewService = 1  // IPVS_CMD_NEW_SERVICE
	ipvsCmdSetService = 2  // IPVS_CMD_SET_SERVICE
	ipvsCmdDelService = 3  // IPVS_CMD_DEL_SERVICE
	ipvsCmdGetService = 4  // IPVS_CMD_GET_SERVICE
	ipvsCmdNewDest    = 5  // IPVS_CMD_NEW_DEST
	ipvsCmdSetDest    = 6  // IPVS_CMD_SET_DEST
	ipvsCmdDelDest    = 7  // IPVS_CMD_DEL_DEST
	ipvsCmdGetDest    = 8  // IPVS_CMD_GET_DEST
	ipvsCmdNewDaemon  = 9  // IPVS_CMD_NEW_DAEMON
	ipvsCmdDelDaemon  = 10 // IPVS_CMD_DEL_DAEMON
	ipvsCmdGetDaemon  = 11 // IPVS_CMD_GET_DAEMON
	ipvsCmdSetConfig  = 12 // IPVS_CMD_SET_CONFIG
	ipvsCmdGetConfig  = 13 // IPVS_CMD_GET_CONFIG
	ipvsCmdSetInfo    = 14 // IPVS_CMD_SET_INFO
	ipvsCmdGetInfo    = 15 // IPVS_CMD_GET_INFO
	ipvsCmdZero       = 16 // IPVS_CMD_ZERO
	ipvsCmdFlush      = 17 // IPVS_CMD_FLUSH
)

// IPVS generic netlink command attributes.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/ip_vs.h#L333-L343
const (
	ipvsCmdAttrUnspec        = 0 // IPVS_CMD_ATTR_UNSPEC
	ipvsCmdAttrService       = 1 // IPVS_CMD_ATTR_SERVICE
	ipvsCmdAttrDest          = 2 // IPVS_CMD_ATTR_DEST
	ipvsCmdAttrDaemon        = 3 // IPVS_CMD_ATTR_DAEMON
	ipvsCmdAttrTimeoutTCP    = 4 // IPVS_CMD_ATTR_TIMEOUT_TCP
	ipvsCmdAttrTimeoutTCPFin = 5 // IPVS_CMD_ATTR_TIMEOUT_TCP_FIN
	ipvsCmdAttrTimeoutUDP    = 6 // IPVS_CMD_ATTR_TIMEOUT_UDP
)

// IPVS service attributes, nested in IPVS_CMD_ATTR_SERVICE.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/ip_vs.h#L347-L372
const (
	ipvsSvcAttrUnspec        = 0  // IPVS_SVC_ATTR_UNSPEC
	ipvsSvcAttrAddressFamily = 1  // IPVS_SVC_ATTR_AF
	ipvsSvcAttrProtocol      = 2  // IPVS_SVC_ATTR_PROTOCOL
	ipvsSvcAttrAddress       = 3  // IPVS_SVC_ATTR_ADDR
	ipvsSvcAttrPort          = 4  // IPVS_SVC_ATTR_PORT
	ipvsSvcAttrFWMark        = 5  // IPVS_SVC_ATTR_FWMARK
	ipvsSvcAttrSchedName     = 6  // IPVS_SVC_ATTR_SCHED_NAME
	ipvsSvcAttrFlags         = 7  // IPVS_SVC_ATTR_FLAGS
	ipvsSvcAttrTimeout       = 8  // IPVS_SVC_ATTR_TIMEOUT
	ipvsSvcAttrNetmask       = 9  // IPVS_SVC_ATTR_NETMASK
	ipvsSvcAttrStats         = 10 // IPVS_SVC_ATTR_STATS
	ipvsSvcAttrPEName        = 11 // IPVS_SVC_ATTR_PE_NAME
)

// IPVS destination attributes, nested in IPVS_CMD_ATTR_DEST.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/ip_vs.h#L376-L409
const (
	ipvsDestAttrUnspec                = 0  // IPVS_DEST_ATTR_UNSPEC
	ipvsDestAttrAddress               = 1  // IPVS_DEST_ATTR_ADDR
	ipvsDestAttrPort                  = 2  // IPVS_DEST_ATTR_PORT
	ipvsDestAttrForwardingMethod      = 3  // IPVS_DEST_ATTR_FWD_METHOD
	ipvsDestAttrWeight                = 4  // IPVS_DEST_ATTR_WEIGHT
	ipvsDestAttrUpperThreshold        = 5  // IPVS_DEST_ATTR_U_THRESH
	ipvsDestAttrLowerThreshold        = 6  // IPVS_DEST_ATTR_L_THRESH
	ipvsDestAttrActiveConnections     = 7  // IPVS_DEST_ATTR_ACTIVE_CONNS
	ipvsDestAttrInactiveConnections   = 8  // IPVS_DEST_ATTR_INACT_CONNS
	ipvsDestAttrPersistentConnections = 9  // IPVS_DEST_ATTR_PERSIST_CONNS
	ipvsDestAttrStats                 = 10 // IPVS_DEST_ATTR_STATS
	ipvsDestAttrAddressFamily         = 11 // IPVS_DEST_ATTR_ADDR_FAMILY
)

// IPVS statistics attributes.
// See https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/ip_vs.h#L433-L454
const (
	ipvsStatsUnspec   = 0  // IPVS_STATS_ATTR_UNSPEC
	ipvsStatsConns    = 1  // IPVS_STATS_ATTR_CONNS
	ipvsStatsPktsIn   = 2  // IPVS_STATS_ATTR_INPKTS
	ipvsStatsPktsOut  = 3  // IPVS_STATS_ATTR_OUTPKTS
	ipvsStatsBytesIn  = 4  // IPVS_STATS_ATTR_INBYTES
	ipvsStatsBytesOut = 5  // IPVS_STATS_ATTR_OUTBYTES
	ipvsStatsCPS      = 6  // IPVS_STATS_ATTR_CPS
	ipvsStatsPPSIn    = 7  // IPVS_STATS_ATTR_INPPS
	ipvsStatsPPSOut   = 8  // IPVS_STATS_ATTR_OUTPPS
	ipvsStatsBPSIn    = 9  // IPVS_STATS_ATTR_INBPS
	ipvsStatsBPSOut   = 10 // IPVS_STATS_ATTR_OUTBPS
)

// Destination forwarding methods
const (
	// ConnectionFlagFwdMask indicates the mask in the connection
	// flags which is used by forwarding method bits.
	ConnectionFlagFwdMask = 0x0007

	// ConnectionFlagMasq is used for masquerade forwarding method.
	ConnectionFlagMasq = 0x0000

	// ConnectionFlagLocalNode is used for local node forwarding
	// method.
	ConnectionFlagLocalNode = 0x0001

	// ConnectionFlagTunnel is used for tunnel mode forwarding
	// method.
	ConnectionFlagTunnel = 0x0002

	// ConnectionFlagDirectRoute is used for direct routing
	// forwarding method.
	ConnectionFlagDirectRoute = 0x0003
)

const (
	// RoundRobin distributes jobs equally amongst the available
	// real servers.
	RoundRobin = "rr"

	// LeastConnection assigns more jobs to real servers with
	// fewer active jobs.
	LeastConnection = "lc"

	// DestinationHashing assigns jobs to servers through looking
	// up a statically assigned hash table by their destination IP
	// addresses.
	DestinationHashing = "dh"

	// SourceHashing assigns jobs to servers through looking up
	// a statically assigned hash table by their source IP
	// addresses.
	SourceHashing = "sh"

	// WeightedRoundRobin assigns jobs to real servers proportionally
	// to there real servers' weight. Servers with higher weights
	// receive new jobs first and get more jobs than servers
	// with lower weights. Servers with equal weights get
	// an equal distribution of new jobs
	WeightedRoundRobin = "wrr"

	// WeightedLeastConnection assigns more jobs to servers
	// with fewer jobs and relative to the real servers' weight
	WeightedLeastConnection = "wlc"
)

const (
	// ConnFwdMask is a mask for the fwd methods
	ConnFwdMask = 0x0007

	// ConnFwdMasq denotes forwarding via masquerading/NAT
	ConnFwdMasq = 0x0000

	// ConnFwdLocalNode denotes forwarding to a local node
	ConnFwdLocalNode = 0x0001

	// ConnFwdTunnel denotes forwarding via a tunnel
	ConnFwdTunnel = 0x0002

	// ConnFwdDirectRoute denotes forwarding via direct routing
	ConnFwdDirectRoute = 0x0003

	// ConnFwdBypass denotes forwarding while bypassing the cache
	ConnFwdBypass = 0x0004
)
