package go_store_and_forward

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/ipfs/go-datastore"
	crypto "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	ma "github.com/multiformats/go-multiaddr"
	"net"
	"testing"
	"time"
)

var blackholeIP6 = net.ParseIP("100::")

func newPeer() (crypto.PrivKey, ma.Multiaddr, error) {
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	id, err := peer.IDFromPrivateKey(sk)
	if err != nil {
		return nil, nil, err
	}

	suffix := id
	if len(id) > 8 {
		suffix = id[len(id)-8:]
	}
	ip := append(net.IP{}, blackholeIP6...)
	copy(ip[net.IPv6len-len(suffix):], suffix)
	a, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/4242", ip))
	if err != nil {
		return nil, nil, err
	}
	return sk, a, nil
}

func Test_Authentication(t *testing.T) {
	mn, err := mocknet.WithNPeers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(context.Background(), mn.Hosts()[0])
	if err != nil {
		t.Fatal(err)
	}

	sk, a, err := newPeer()
	if err != nil {
		t.Fatal(err)
	}

	_, err = mn.AddPeer(sk, a)
	if err != nil {
		t.Fatal(err)
	}

	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(context.Background(), sk, []peer.ID{}, mn.Hosts()[1])
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.authenticate(mn.Peers()[0]); err != nil {
		t.Fatal(err)
	}

	if !server.authenticatedConns[mn.Peers()[1]] {
		t.Fatal("Authentication failed")
	}
}

func Test_Registration(t *testing.T) {
	mn, err := mocknet.WithNPeers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(context.Background(), mn.Hosts()[0])
	if err != nil {
		t.Fatal(err)
	}

	sk, a, err := newPeer()
	if err != nil {
		t.Fatal(err)
	}

	_, err = mn.AddPeer(sk, a)
	if err != nil {
		t.Fatal(err)
	}

	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(context.Background(), sk, []peer.ID{}, mn.Hosts()[1])
	if err != nil {
		t.Fatal(err)
	}

	client.registerSingle(mn.Peers()[0], time.Hour)

	if !server.authenticatedConns[mn.Peers()[1]] {
		t.Fatal("Authentication failed")
	}

	_, err = server.ds.Get(registrationKey(mn.Peers()[1]))
	if err != nil {
		t.Fatal(err)
	}

	if !client.peers[mn.Peers()[0]] {
		t.Fatal("Registration failed")
	}
}

func TestClient_Messages(t *testing.T) {
	mn, err := mocknet.WithNPeers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(context.Background(), mn.Hosts()[0])
	if err != nil {
		t.Fatal(err)
	}

	sk1, a1, err := newPeer()
	if err != nil {
		t.Fatal(err)
	}

	sk2, a2, err := newPeer()
	if err != nil {
		t.Fatal(err)
	}

	h1, err := mn.AddPeer(sk1, a1)
	if err != nil {
		t.Fatal(err)
	}

	h2, err := mn.AddPeer(sk2, a2)
	if err != nil {
		t.Fatal(err)
	}

	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}

	client1, err := NewClient(context.Background(), sk1, []peer.ID{}, h1)
	if err != nil {
		t.Fatal(err)
	}

	client1.registerSingle(mn.Hosts()[0].ID(), time.Hour)

	client2, err := NewClient(context.Background(), sk2, []peer.ID{}, h2)
	if err != nil {
		t.Fatal(err)
	}

	client2.registerSingle(mn.Hosts()[0].ID(), time.Hour)

	var (
		sub    = client2.SubscribeMessages()
		encMsg = []byte("encrypted message")
	)

	if err := client1.SendMessage(context.Background(), h2.ID(), mn.Hosts()[0].ID(), encMsg); err != nil {
		t.Fatal(err)
	}

	select {
	case m := <-sub.Out:
		if !bytes.Equal(m.EncryptedMessage, encMsg) {
			t.Errorf("Wrong message. Expected %s, got %s", string(encMsg), string(m.EncryptedMessage))
		}
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting on sub")
	}

	messages, err := client2.GetMessages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("Wrong number of messages. Expected %d, got %d", 1, len(messages))
	}
	if !bytes.Equal(messages[0].EncryptedMessage, encMsg) {
		t.Errorf("Wrong message. Expected %s, got %s", string(encMsg), string(messages[0].EncryptedMessage))
	}

	if err := client2.AckMessage(context.Background(), messages[0].MessageID); err != nil {
		t.Fatal(err)
	}

	_, err = server.ds.Get(messageKey(h2.ID(), messages[0].MessageID))
	if err != datastore.ErrNotFound {
		t.Errorf("Expected ErrNotFound got %v", err)
	}
}
