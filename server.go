package go_store_and_forward

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	ggio "github.com/gogo/protobuf/io"
	"github.com/golang/protobuf/ptypes"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	logging "github.com/ipfs/go-log"
	ctxio "github.com/jbenet/go-context/io"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	inet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	protocol "github.com/libp2p/go-libp2p-protocol"
	"github.com/multiformats/go-base32"
	"go-store-and-forward/pb"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	protectionTag         = "store-and-forward"
	registrationKeyPrefix = "/snf/registeredPeer/"
	messageKeyPrefix      = "/snf/message/"
)

var log = logging.Logger("relay")

// Server is a store and forward server which can be used for asynchronous
// communication between peers on the network.
type Server struct {
	host               host.Host
	ctx                context.Context
	ds                 datastore.Datastore
	authenticatedConns map[peer.ID]bool
	protocol           protocol.ID
	mtx                sync.RWMutex
}

// NewServer returns a new store and forward server.
func NewServer(ctx context.Context, h host.Host, opts ...Option) (*Server, error) {
	var cfg Options
	if err := cfg.Apply(append([]Option{Defaults}, opts...)...); err != nil {
		return nil, err
	}

	if len(cfg.Protocols) == 0 {
		return nil, errors.New("protocol option is required")
	}

	s := &Server{
		host:               h,
		ctx:                ctx,
		authenticatedConns: make(map[peer.ID]bool),
		ds:                 cfg.Datastore,
		protocol:           cfg.Protocols[0],
		mtx:                sync.RWMutex{},
	}

	for _, protocol := range cfg.Protocols {
		h.SetStreamHandler(protocol, s.handleNewStream)
	}

	disConnected := func(_ inet.Network, conn inet.Conn) {
		s.mtx.Lock()
		delete(s.authenticatedConns, conn.RemotePeer())
		s.mtx.Unlock()
	}

	notifier := &inet.NotifyBundle{
		DisconnectedF: disConnected,
	}

	h.Network().Notify(notifier)

	return s, nil
}

func (svr *Server) handleNewStream(s inet.Stream) {
	go svr.streamHandler(s)
}

func (svr *Server) streamHandler(s inet.Stream) {
	defer s.Close()
	contextReader := ctxio.NewReader(svr.ctx, s)
	reader := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
	writer := ggio.NewDelimitedWriter(s)
	remotePeer := s.Conn().RemotePeer()

	for {
		select {
		case <-svr.ctx.Done():
			return
		default:
		}

		pmes := new(pb.Message)
		if err := reader.ReadMsg(pmes); err != nil {
			s.Reset()
			if err == io.EOF {
				log.Debugf("peer %s closed stream", remotePeer)
			}
			return
		}

		var err error
		switch pmes.Type {
		case pb.Message_AUTHENTICATE:
			err = svr.handleAuthenticate(s, reader, writer, pmes, remotePeer)
		case pb.Message_REGISTER:
			if !svr.isAuthenticated(remotePeer) {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
			}
			err = svr.handleRegister(writer, pmes, remotePeer)
		case pb.Message_UNREGISTER:
			if !svr.isAuthenticated(remotePeer) {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
			}
			err = svr.handleUnregister(writer, pmes, remotePeer)
		case pb.Message_GET_MESSAGES:
			if !svr.isAuthenticated(remotePeer) {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
			}
			err = svr.handleGetMessages(writer, pmes, remotePeer)
		case pb.Message_MESSAGE_ACK:
			if !svr.isAuthenticated(remotePeer) {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
			}
			err = svr.handleAckMessage(writer, pmes, remotePeer)
		case pb.Message_STORE_MESSAGE:
			err = svr.handleStoreMessage(writer, pmes, remotePeer)
		}
		if err != nil {
			log.Errorf("Peer %s: Error handling %s message: %s", remotePeer, pmes.Type, err)
		}
	}
}

func (svr *Server) isAuthenticated(p peer.ID) bool {
	var authenticated bool
	svr.mtx.RLock()
	_, authenticated = svr.authenticatedConns[p]
	svr.mtx.RUnlock()
	return authenticated
}

// handleAuthenticate runs the authentication protocol which contains a challenge and response.
func (svr *Server) handleAuthenticate(s inet.Stream, r ggio.Reader, w ggio.Writer, pmes *pb.Message, peer peer.ID) error {
	// Check to make sure we are not already authenticated.
	svr.mtx.RLock()
	_, ok := svr.authenticatedConns[peer]
	svr.mtx.RUnlock()
	if ok {
		return writeStatusMessage(w, pb.Message_ALREADY_AUTHENTICATED)

	}

	// Parse pubkey and make sure it's valid.
	pubkeyMsg := pmes.GetPubkey()
	if pubkeyMsg == nil {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}

	pubkey, err := crypto.UnmarshalPublicKey(pubkeyMsg.Pubkey)
	if err != nil {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}

	if !peer.MatchesPublicKey(pubkey) {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}

	// Send challenge message
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	err = writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_CHALLENGE,
		Payload: &pb.Message_Challenge_{
			Challenge: &pb.Message_Challenge{
				Challenge: challengeBytes,
			},
		},
	})
	if err != nil {
		return err
	}

	// Read challenge response.
	respMsg := new(pb.Message)
	if err := readMsgWithTimeout(r, respMsg); err != nil {
		return err
	}

	if respMsg.Type != pb.Message_RESPONSE {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}

	// Verify signature.
	sigMsg := respMsg.GetSignature()
	if sigMsg == nil {
		return writeStatusMessage(w, pb.Message_SIGNATURE_INVALID)
	}
	valid, err := pubkey.Verify(challengeBytes, sigMsg.Signature)
	if !valid || err != nil {
		return writeStatusMessage(w, pb.Message_SIGNATURE_INVALID)
	}

	// Protect connection.
	svr.host.ConnManager().Protect(peer, protectionTag)

	// Add to authenticatedConns.
	svr.mtx.Lock()
	svr.authenticatedConns[peer] = true
	svr.mtx.Unlock()

	// Write success response.
	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleRegister saves a user registration in the db. Duplicate registrations are allowed
// and a prior registration is overridden.
func (svr *Server) handleRegister(w ggio.Writer, pmes *pb.Message, peer peer.ID) error {
	regMsg := pmes.GetRegistration()
	if regMsg == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	var (
		expiry = time.Unix(math.MaxUint64, 0)
		err    error
	)
	ts := regMsg.GetExpiry()
	if ts != nil {
		expiry, err = ptypes.Timestamp(ts)
		if err != nil {
			return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
		}
	}

	tsBytes, err := expiry.MarshalBinary()
	if err != nil {
		return err
	}

	err = svr.ds.Put(registrationKey(peer), tsBytes)
	if err != nil {
		return err
	}

	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleUnregister unregisters a peer from this server.
func (svr *Server) handleUnregister(w ggio.Writer, pmes *pb.Message, peer peer.ID) error {
	err := svr.ds.Delete(registrationKey(peer))
	if err != nil {
		return err
	}
	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleGetMessages loads all the messages for the given peer from the database and sends
// them in separate MESSAGE messages.
func (svr *Server) handleGetMessages(w ggio.Writer, pmes *pb.Message, peer peer.ID) error {
	record, err := svr.ds.Get(registrationKey(peer))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	var expiry time.Time
	err = expiry.UnmarshalBinary(record)
	if err != nil {
		return err
	}
	if expiry.After(time.Now()) {
		err := svr.ds.Delete(registrationKey(peer))
		if err != nil {
			return err
		}
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	q := query.Query{
		Prefix: messageKeyPrefix + peer.Pretty(),
	}
	results, err := svr.ds.Query(q)
	if err != nil {
		return err
	}

	for {
		result, more := results.NextSync()

		s := strings.Split(result.Key, "/")

		messageID, err := base32.RawStdEncoding.DecodeString(s[4])
		if err != nil {
			return err
		}

		err = writeMsgWithTimeout(w, &pb.Message{
			Type: pb.Message_MESSAGE,
			Payload: &pb.Message_EncryptedMessage_{
				EncryptedMessage: &pb.Message_EncryptedMessage{
					MessageID: messageID,
					Message:   result.Value,
					More:      more,
				},
			},
		})
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}

	return nil
}

// handleAckMessage deletes the message with the provided ID from the database. The client
// should take care to make sure it is fully committed on the client side before acking
// the message.
func (svr *Server) handleAckMessage(w ggio.Writer, pmes *pb.Message, peer peer.ID) error {
	record, err := svr.ds.Get(registrationKey(peer))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	var expiry time.Time
	err = expiry.UnmarshalBinary(record)
	if err != nil {
		return err
	}
	if expiry.After(time.Now()) {
		err := svr.ds.Delete(registrationKey(peer))
		if err != nil {
			return err
		}
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	ack := pmes.GetAck()
	if ack == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}

	return svr.ds.Delete(messageKey(peer, ack.MessageID))
}

// handleStoreMessage stores the given message in the db with a random messageID.
// If the peer is not registered with this server we return an error.
// Further, we check to see if the recipient is connected to us and if so relay
// the message to them.
func (svr *Server) handleStoreMessage(w ggio.Writer, pmes *pb.Message, from peer.ID) error {
	encMsg := pmes.GetEncryptedMessage()
	if encMsg == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	if encMsg.GetToPeerID() == nil {
		return writeStatusMessage(w, pb.Message_PEERID_INVALID)
	}

	to := peer.ID(encMsg.GetToPeerID())

	record, err := svr.ds.Get(registrationKey(to))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	var expiry time.Time
	err = expiry.UnmarshalBinary(record)
	if err != nil {
		return err
	}
	if expiry.After(time.Now()) {
		err := svr.ds.Delete(registrationKey(to))
		if err != nil {
			return err
		}
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	fromBytes, err := from.MarshalBinary()
	if err != nil {
		return err
	}
	id := sha256.Sum256(append(fromBytes, encMsg.Message...))

	if err := svr.ds.Put(messageKey(to, id[:]), encMsg.Message); err != nil {
		return err
	}

	go func() {
		connectedness := svr.host.Network().Connectedness(to)
		if connectedness == inet.Connected {
			stream, err := svr.host.NewStream(svr.ctx, to, svr.protocol)
			if err != nil {
				log.Errorf("Error relaying message to connected peer %s: %s", to, err)
				return
			}
			defer stream.Close()

			writer := ggio.NewDelimitedWriter(stream)
			err = writeMsgWithTimeout(writer, &pb.Message{
				Type: pb.Message_MESSAGE,
				Payload: &pb.Message_EncryptedMessage_{
					EncryptedMessage: &pb.Message_EncryptedMessage{
						MessageID: id,
						Message:   encMsg.Message,
					},
				},
			})
			if err != nil {
				log.Errorf("Error relaying message to connected peer %s: %s", to, err)
			}
		}
	}()

	return writeStatusMessage(w, pb.Message_SUCCESS)
}

func writeStatusMessage(w ggio.Writer, code pb.Message_Status) error {
	return writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_STATUS,
		Code: code,
	})
}

func registrationKey(p peer.ID) datastore.Key {
	return datastore.NewKey(registrationKeyPrefix + p.Pretty())
}

func messageKey(p peer.ID, messageID []byte) datastore.Key {
	id := base32.RawStdEncoding.EncodeToString(messageID)
	return datastore.NewKey(messageKeyPrefix + p.Pretty() + "/" + id)
}
