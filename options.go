package storeandforward

import (
	"fmt"
	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	peer "github.com/libp2p/go-libp2p-peer"
	protocol "github.com/libp2p/go-libp2p-protocol"
	"time"
)

// ProtocolSNF is the protocol ID used by libp2p.
const ProtocolSNF protocol.ID = "/libp2p/store-and-forward/0.1.0"

var (
	defaultProtocols = []protocol.ID{ProtocolSNF}
)

// Options is a structure containing all the options that can be used when constructing a Store and Forward node.
type Options struct {
	Datastore            ds.Batching
	Protocols            []protocol.ID
	ReplicationPeers     []peer.ID
	RegistrationDuration time.Duration
	BootstrapDone        chan struct{}
}

// Apply applies the given options to this Option
func (o *Options) Apply(opts ...Option) error {
	for i, opt := range opts {
		if err := opt(o); err != nil {
			return fmt.Errorf("snf option %d failed: %s", i, err)
		}
	}
	return nil
}

// Option Store and Forward option type.
type Option func(*Options) error

// Defaults are the default options. This option will be automatically
// prepended to any options you pass to the constructor.
var Defaults = func(o *Options) error {
	o.Datastore = dssync.MutexWrap(ds.NewMapDatastore())
	o.Protocols = defaultProtocols
	o.RegistrationDuration = time.Hour * 24 * 365 * 10 // 10 years.
	return nil
}

// Datastore configures the Server to use the specified datastore.
//
// Defaults to an in-memory (temporary) map.
func Datastore(ds ds.Batching) Option {
	return func(o *Options) error {
		o.Datastore = ds
		return nil
	}
}

// Protocols sets the protocols for the Store and Forward nodes.
//
// Defaults to defaultProtocols
func Protocols(protocols ...protocol.ID) Option {
	return func(o *Options) error {
		o.Protocols = protocols
		return nil
	}
}

// ReplicationPeers registers server peers to replicate data to.
//
// Defaults to nil
func ReplicationPeers(peers ...peer.ID) Option {
	return func(o *Options) error {
		o.ReplicationPeers = peers
		return nil
	}
}

// BootstrapDone is closed when the initial bootstrap completes.
//
// Defaults to nil
func BootstrapDone(done chan struct{}) Option {
	return func(o *Options) error {
		o.BootstrapDone = done
		return nil
	}
}

// RegistrationDuration sets the duration of the registration used by the client.
//
// Defaults to 10 years.
func RegistrationDuration(duration time.Duration) Option {
	return func(o *Options) error {
		o.RegistrationDuration = duration
		return nil
	}
}
