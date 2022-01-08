package wireless

import (
	"errors"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

// WPAConn is an interface to the connection
type WPAConn interface {
	SendCommand(...string) (string, error)
	SendCommandBool(...string) error
	SendCommandInt(...string) (int, error)
	io.Closer
	Subscribe(...string) *Subscription
}

// Client represents a wireless client
type Client struct {
	conn WPAConn
}

// NewClient will create a new client by connecting to the
// given interface in WPA
func NewClient(iface string) (c *Client, err error) {
	c = new(Client)
	c.conn, err = Dial(iface)
	if err != nil {
		return
	}

	return
}

// NewClientFromConn returns a new client from an already established connection
func NewClientFromConn(conn WPAConn) (c *Client) {
	c.conn = conn
	return
}

// Close will close the client connection
func (cl *Client) Close() {
	cl.conn.Close()
}

// Conn will return the underlying connection
func (cl *Client) Conn() *Conn {
	return cl.conn.(*Conn)
}

// Subscribe will subscribe to certain events that happen in WPA
func (cl *Client) Subscribe(topics ...string) *Subscription {
	return cl.conn.Subscribe(topics...)
}

// Status will return the current state of the WPA
func (cl *Client) Status() (State, error) {
	data, err := cl.conn.SendCommand(CmdStatus)
	if err != nil {
		return State{}, err
	}
	s := NewState(data)
	return s, nil
}

// Scan will scan for networks and return the APs it finds
func (cl *Client) Scan() (nets APs, err error) {
	err = cl.conn.SendCommandBool(CmdScan)
	if err != nil {
		return
	}

	results := cl.conn.Subscribe(EventScanResults)
	failed := cl.conn.Subscribe(EventScanFailed)

	func() {
		for {
			select {
			case <-failed.Next():
				err = ErrScanFailed
				return
			case <-results.Next():
				return
			case <-time.NewTimer(time.Second * 2).C:
				return
			}
		}
	}()

	scanned, err := cl.conn.SendCommand(CmdScanResults)
	if err != nil {
		return
	}

	return parseAP([]byte(scanned))
}

// Networks lists the known networks
func (cl *Client) Networks() (nets Networks, err error) {
	data, err := cl.conn.SendCommand(CmdListNetworks)
	if err != nil {
		return nil, err
	}

	nets, err = parseNetwork([]byte(data))
	if err != nil {
		return nil, err
	}

	for i := range nets {
		nets[i].Known = true
		(&nets[i]).populateAttrs(cl)
	}

	return nets, nil
}

// Connect to a new or existing network
// Deprecated
func (cl *Client) Connect(net Network) (Network, error) {
	net, err := cl.AddOrUpdateNetwork(net)
	if err != nil {
		return net, err
	}

	sub := cl.conn.Subscribe(EventNetworkNotFound, EventAuthReject, EventConnected, EventDisconnected, EventAssocReject)
	if err := cl.EnableNetwork(net.ID); err != nil {
		return net, err
	}

	ev := <-sub.Next()

	switch ev.Name {
	case EventConnected:
		return net, cl.SaveConfig()
	case EventNetworkNotFound:
		return net, ErrSSIDNotFound
	case EventAuthReject:
		return net, ErrAuthFailed
	case EventDisconnected:
		return net, ErrDisconnected
	case EventAssocReject:
		return net, ErrAssocRejected
	}

	return net, errors.New("failed to catch event " + ev.Name)
}

// ConnectAndPrioritize will connect to a new or existing network and set its priority to 1, and all other networks to 0
func (cl *Client) ConnectAndPrioritize(net Network) (Network, error) {
	net, err := cl.AddOrUpdateNetwork(net)

	if err != nil {
		return net, err
	}

	status, err := cl.Status()
	if err != nil {
		return net, err
	}

	sub := cl.Subscribe(
		EventNetworkNotFound,
		EventAuthReject,
		EventConnected,
		EventDisconnected,
		EventAssocReject,
	)

	if err := cl.SelectNetwork(net.ID); err != nil {
		return net, err
	}

	if err = cl.Reassociate(); err != nil {
		return net, err
	}

	for {
		ev := <-sub.Next()

		if ev.Name == EventConnected {
			cl.EnableAllNetworksAndResetPriority()
			cl.SetNetworkPriority(net.ID, 1)
			return net, cl.SaveConfig()
		}
		if ev.Name == EventDisconnected {
			// when switching networks, we expect the current network to first disconnect
			bssId, ok := ev.Arguments["bssid"]
			if ok && status.BSSID == bssId {
				continue
			}
		}

		// undo any changes we've made to the wpa_supplicant state
		// without attempting to connect to something else

		// TODO: if this *updated* a network and failed, and then a
		// successful connection is made to a different network, the
		// previous (successful) configuration for the initial network
		// would be removed.
		err = cl.RemoveNetwork(net.ID)
		if err != nil {
			cl.Conn().log.Println("Error removing network", err)
		}

		switch ev.Name {
		case EventNetworkNotFound:
			return net, ErrSSIDNotFound
		case EventAuthReject:
			return net, ErrAuthFailed
		case EventDisconnected:
			return net, ErrDisconnected
		case EventAssocReject:
			return net, ErrAssocRejected
		}

		return net, errors.New("failed to catch event " + ev.Name)
	}
}

// AddOrUpdateNetwork will add a network or, if the network is already present, update it
func (cl *Client) AddOrUpdateNetwork(net Network) (Network, error) {
	nets, err := cl.Networks()
	if err != nil {
		return net, err
	}

	for _, n := range nets {
		if n.SSID == net.SSID {
			net.ID = n.ID
			return cl.UpdateNetwork(net)
		}
	}

	return cl.AddNetwork(net)
}

// UpdateNetwork will update the given network, an error will be thrown
// if the network doesn't have IDStr specified
func (cl *Client) UpdateNetwork(net Network) (Network, error) {
	if net.IDStr == "" {
		return net, ErrNoIdentifier
	}

	for _, cmd := range setCmds(net) {
		if err := cl.conn.SendCommandBool(cmd); err != nil {
			return net, err
		}
	}

	return net, nil
}

// AddNetwork will add a new network
func (cl *Client) AddNetwork(net Network) (Network, error) {
	i, err := cl.conn.SendCommandInt(CmdAddNetwork)
	if err != nil {
		return net, err
	}

	net.ID = i

	if net.IDStr == "" {
		net.IDStr = net.SSID
	}

	for _, cmd := range setCmds(net) {
		if err := cl.conn.SendCommandBool(cmd); err != nil {
			return net, err
		}
	}

	net.Known = true
	return net, nil
}

// enable all networks and reset all network priorities
func (cl *Client) EnableAllNetworksAndResetPriority() error {
	nets, err := cl.Networks()
	if err != nil {
		return err
	}
	for _, net := range nets {
		err = cl.SetNetworkPriority(net.ID, 0)
		if err != nil {
			return err
		}
		err = cl.EnableNetwork(net.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveNetwork will RemoveNetwork
func (cl *Client) RemoveNetwork(id int) error {
	return cl.conn.SendCommandBool(CmdRemoveNetwork, strconv.Itoa(id))
}

// EnableNetwork will EnableNetwork
func (cl *Client) EnableNetwork(id int) error {
	return cl.conn.SendCommandBool(CmdEnableNetwork + " " + strconv.Itoa(id))
}

// DisableNetwork will DisableNetwork
func (cl *Client) DisableNetwork(id int) error {
	return cl.conn.SendCommandBool(CmdDisableNetwork + " " + strconv.Itoa(id))
}

// SetNetworkPriority sets the priority of the given network id to the given amount
func (cl *Client) SetNetworkPriority(id int, priority int) error {
	return cl.conn.SendCommandBool(setCmdJoin(id, "priority", strconv.Itoa(priority)))
}

// RelectNetwork will select specific network
func (cl *Client) SelectNetwork(id int) error {
	return cl.conn.SendCommandBool(CmdSelectNetwork + " " + strconv.Itoa(id))
}

// Reassociate will force a network reassociation
func (cl *Client) Reassociate() error {
	return cl.conn.SendCommandBool(CmdReassociate)
}

// SaveConfig will save the current wpa_supplicant network configuration to the on-disk configuration file
func (cl *Client) SaveConfig() error {
	return cl.conn.SendCommandBool(CmdSaveConfig)
}

// Reconfigure will reconfigure wpa_supplicant with the on-disk configuration file
func (cl *Client) Reconfigure() error {
	return cl.conn.SendCommandBool(CmdReconfigure)
}

// GetNetworkAttr will get the given attribute of the given network
func (cl *Client) GetNetworkAttr(id int, attr string) (string, error) {
	s, err := cl.conn.SendCommand(CmdGetNetwork, strconv.Itoa(id), attr)
	if err != nil {
		return s, err
	}

	return strings.TrimSpace(s), nil
}

// Print to std out all wireless events
func (cl *Client) Debug() {
	cl.Conn().WithLogOutput(log.Writer())
	go func() {
		sub := cl.Subscribe("")
		var (
			msg Event
		)
		for {
			msg = <-sub.Next()
			cl.Conn().log.Println("wpa_supplicant Event:", msg)
		}
	}()
}
