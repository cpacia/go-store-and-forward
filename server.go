package storeandforward

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/cpacia/go-store-and-forward/pb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	logging "github.com/ipfs/go-log"
	ctxio "github.com/jbenet/go-context/io"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	inet "github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	msgio "github.com/libp2p/go-msgio"
	"github.com/multiformats/go-base32"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	protectionTag         = "store-and-forward"
	registrationKeyPrefix = "/snf/registeredPeer/"
	messageKeyPrefix      = "/snf/message/"
)

var log = logging.Logger("snf")

// Server is a store and forward server which can be used for asynchronous
// communication between peers on the network.
type Server struct {
	host             host.Host
	ctx              context.Context
	ds               datastore.Datastore
	replicationPeers map[peer.ID]inet.Stream
	protocol         protocol.ID
	mtx              sync.RWMutex
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

	repPeersMap := make(map[peer.ID]inet.Stream)
	for _, p := range cfg.ReplicationPeers {
		h.ConnManager().Protect(p, protectionTag)
		repPeersMap[p] = nil
	}

	s := &Server{
		host:             h,
		ctx:              ctx,
		ds:               cfg.Datastore,
		protocol:         cfg.Protocols[0],
		replicationPeers: repPeersMap,
		mtx:              sync.RWMutex{},
	}

	for _, protocol := range cfg.Protocols {
		h.SetStreamHandler(protocol, s.handleNewStream)
	}

	return s, nil
}

func (svr *Server) handleNewStream(s inet.Stream) {
	go svr.streamHandler(s)
}

func (svr *Server) streamHandler(s inet.Stream) {
	defer s.Close()
	contextReader := ctxio.NewReader(svr.ctx, s)
	reader := msgio.NewVarintReaderSize(contextReader, inet.MessageSizeMax)
	writer := msgio.NewVarintWriter(s)
	remotePeer := s.Conn().RemotePeer()

	defer func() {
		svr.mtx.Lock()
		if _, ok := svr.replicationPeers[remotePeer]; ok {
			svr.replicationPeers[remotePeer] = nil
		}
		svr.mtx.Unlock()
	}()

	for {
		select {
		case <-svr.ctx.Done():
			return
		default:
		}

		pmes := new(pb.Message)
		msgBytes, err := reader.ReadMsg()
		if err != nil {
			reader.ReleaseMsg(msgBytes)
			s.Reset()
			if err == io.EOF {
				log.Debugf("peer %s closed stream", remotePeer)
			}
			return
		}
		if err := proto.Unmarshal(msgBytes, pmes); err != nil {
			reader.ReleaseMsg(msgBytes)
			s.Reset()
			return
		}
		reader.ReleaseMsg(msgBytes)

		switch pmes.Type {
		case pb.Message_REGISTER:
			err = svr.handleRegister(writer, pmes, remotePeer)
		case pb.Message_UNREGISTER:
			err = svr.handleUnregister(writer, pmes, remotePeer)
		case pb.Message_GET_MESSAGES:
			err = svr.handleGetMessages(writer, pmes, remotePeer)
		case pb.Message_MESSAGE_ACK:
			err = svr.handleAckMessage(writer, pmes, remotePeer)
		case pb.Message_PROVE_REGISTRATION:
			err = svr.handleProveRegistrationMessage(writer, pmes, remotePeer)
		case pb.Message_STORE_MESSAGE:
			err = svr.handleStoreMessage(writer, pmes, remotePeer)
		case pb.Message_GET_MESSAGE:
			if _, ok := svr.replicationPeers[remotePeer]; !ok {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
				break
			}
			err = svr.handleGetMessage(writer, pmes, remotePeer)
		case pb.Message_REPLICATE:
			if _, ok := svr.replicationPeers[remotePeer]; !ok {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
				break
			}
			err = svr.handleReplicateMessage(writer, pmes, remotePeer)
		case pb.Message_MESSAGE:
			if _, ok := svr.replicationPeers[remotePeer]; !ok {
				err = writeStatusMessage(writer, pb.Message_UNAUTHORIZED)
				break
			}
			err = svr.handleMessageMessage(writer, pmes, remotePeer)
		}
		if err != nil {
			log.Errorf("Peer %s: Error handling %s message: %s", remotePeer, pmes.Type, err)
		}
	}
}

// handleRegister saves a user registration in the db. Duplicate registrations are allowed
// and a prior registration is overridden.
func (svr *Server) handleRegister(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleRegister: peer %s", from)
	regMsg := pmes.GetRegistration()
	if regMsg == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	if peer.ID(regMsg.Server) != svr.host.ID() {
		return writeStatusMessage(w, pb.Message_PEERID_INVALID)
	}

	var (
		pubKey crypto.PubKey
		err    error
	)
	if regMsg.GetPubkey() != nil {
		pubKey, err = crypto.UnmarshalPublicKey(regMsg.GetPubkey())
	} else {
		pubKey, err = from.ExtractPublicKey()
	}
	if err != nil {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}

	checkID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}
	if checkID != from {
		return writeStatusMessage(w, pb.Message_PUBKEY_INVALID)
	}

	m := proto.Clone(regMsg)
	regCpy := m.(*pb.Message_Registration)
	regCpy.Signature = nil
	sigSer, err := proto.Marshal(regCpy)
	if err != nil {
		return err
	}
	valid, err := pubKey.Verify(sigSer, regMsg.Signature)
	if err != nil {
		return err
	}
	if !valid {
		return writeStatusMessage(w, pb.Message_SIGNATURE_INVALID)
	}

	ser, err := proto.Marshal(regMsg)
	if err != nil {
		return err
	}

	err = svr.ds.Put(registrationKey(from), ser)
	if err != nil {
		return err
	}

	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleUnregister unregisters a peer from this server.
func (svr *Server) handleUnregister(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleUnregister: peer %s", from)
	err := svr.ds.Delete(registrationKey(from))
	if err != nil {
		return err
	}
	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleProveRegistrationMessage returns the peer's registration info if it exists.
func (svr *Server) handleProveRegistrationMessage(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleProveRegistration: peer %s", from)
	ids := pmes.GetIds()
	if ids == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	record, err := svr.ds.Get(registrationKey(peer.ID(ids.PeerID)))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	reg := new(pb.Message_Registration)
	err = proto.Unmarshal(record, reg)
	if err != nil {
		return err
	}
	expiry, err := ptypes.Timestamp(reg.Expiry)
	if err != nil {
		return err
	}
	if expiry.Before(time.Now()) {
		err := svr.ds.Delete(registrationKey(peer.ID(ids.PeerID)))
		if err != nil {
			return err
		}
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}
	return writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_RESPONSE,
		Payload: &pb.Message_Registration_{
			Registration: reg,
		},
	})
}

// handleReplicateMessage checks the db for the message and if it doesn't exist it requests it.
// This method may only be used by a replication peer.
func (svr *Server) handleReplicateMessage(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleReplicate: peer %s", from)
	ids := pmes.GetIds()
	if ids == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}

	has, err := svr.ds.Has(messageKey(peer.ID(ids.PeerID), ids.MessageID))
	if err != nil {
		return err
	}
	if !has {
		return writeMsgWithTimeout(w, &pb.Message{
			Type: pb.Message_GET_MESSAGE,
			Payload: &pb.Message_Ids{
				Ids: &pb.Message_IDs{
					MessageID: ids.MessageID,
					PeerID:    ids.PeerID,
				},
			},
		})
	}
	return nil
}

// handleMessageMessage saves the message straight into the db.
// This method may only be used by a replication peer.
func (svr *Server) handleMessageMessage(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleMessage: peer %s", from)
	enc := pmes.GetEncryptedMessage()
	if enc == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	return svr.ds.Put(messageKey(peer.ID(enc.PeerID), enc.MessageID), enc.Message)
}

// handleGetMessage loads a specific message from the db and returns it. This method
// may only be used by a replication peer.
func (svr *Server) handleGetMessage(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleGetMessage: peer %s", from)
	ids := pmes.GetIds()
	if ids == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}

	message, err := svr.ds.Get(messageKey(peer.ID(ids.PeerID), ids.MessageID))
	if err != nil {
		return err
	}
	return writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_MESSAGE,
		Payload: &pb.Message_EncryptedMessage_{
			EncryptedMessage: &pb.Message_EncryptedMessage{
				MessageID: ids.MessageID,
				Message:   message,
				PeerID:    ids.PeerID,
			},
		},
	})
}

// handleGetMessages loads all the messages for the given peer from the database and sends
// them in separate MESSAGE messages.
func (svr *Server) handleGetMessages(w msgio.Writer, pmes *pb.Message, peer peer.ID) error {
	log.Debugf("handleGetMessages: peer %s", peer)
	record, err := svr.ds.Get(registrationKey(peer))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	reg := new(pb.Message_Registration)
	err = proto.Unmarshal(record, reg)
	if err != nil {
		return err
	}
	expiry, err := ptypes.Timestamp(reg.Expiry)
	if err != nil {
		return err
	}
	if expiry.Before(time.Now()) {
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
		if !more {
			return writeMsgWithTimeout(w, &pb.Message{
				Type: pb.Message_MESSAGE,
				Payload: &pb.Message_EncryptedMessage_{
					EncryptedMessage: &pb.Message_EncryptedMessage{
						More: more,
					},
				},
			})
		}

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
	}
}

// handleAckMessage deletes the message with the provided ID from the database. The client
// should take care to make sure it is fully committed on the client side before acking
// the message.
func (svr *Server) handleAckMessage(w msgio.Writer, pmes *pb.Message, peer peer.ID) error {
	log.Debugf("handleAck: peer %s", peer)
	record, err := svr.ds.Get(registrationKey(peer))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	reg := new(pb.Message_Registration)
	err = proto.Unmarshal(record, reg)
	if err != nil {
		return err
	}
	expiry, err := ptypes.Timestamp(reg.Expiry)
	if err != nil {
		return err
	}
	if expiry.Before(time.Now()) {
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

	if err := svr.ds.Delete(messageKey(peer, ack.MessageID)); err != nil {
		return err
	}

	return writeStatusMessage(w, pb.Message_SUCCESS)
}

// handleStoreMessage stores the given message in the db with a random messageID.
// If the peer is not registered with this server we return an error.
// Further, we check to see if the recipient is connected to us and if so relay
// the message to them.
func (svr *Server) handleStoreMessage(w msgio.Writer, pmes *pb.Message, from peer.ID) error {
	log.Debugf("handleStore: peer %s", from)
	encMsg := pmes.GetEncryptedMessage()
	if encMsg == nil {
		return writeStatusMessage(w, pb.Message_MALFORMED_MESSAGE)
	}
	if encMsg.GetPeerID() == nil {
		return writeStatusMessage(w, pb.Message_PEERID_INVALID)
	}

	to := peer.ID(encMsg.GetPeerID())

	record, err := svr.ds.Get(registrationKey(to))
	if err != nil && err == datastore.ErrNotFound {
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	reg := new(pb.Message_Registration)
	err = proto.Unmarshal(record, reg)
	if err != nil {
		return err
	}
	expiry, err := ptypes.Timestamp(reg.Expiry)
	if err != nil {
		return err
	}
	if expiry.Before(time.Now()) {
		err := svr.ds.Delete(registrationKey(to))
		if err != nil {
			return err
		}
		return writeStatusMessage(w, pb.Message_NOT_REGISTERED)
	}

	id := sha256.Sum256(append([]byte(from), encMsg.Message...))

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

			writer := msgio.NewVarintWriter(stream)
			err = writeMsgWithTimeout(writer, &pb.Message{
				Type: pb.Message_MESSAGE,
				Payload: &pb.Message_EncryptedMessage_{
					EncryptedMessage: &pb.Message_EncryptedMessage{
						MessageID: id[:],
						Message:   encMsg.Message,
					},
				},
			})
			if err != nil {
				log.Errorf("Error relaying message to connected peer %s: %s", to, err)
			}
		}
	}()

	svr.mtx.RLock()
	for p, s := range svr.replicationPeers {
		go func(p peer.ID, s inet.Stream) {
			if s == nil {
				s, err = svr.host.NewStream(svr.ctx, p, svr.protocol)
				if err != nil {
					log.Errorf("Error replicating message to peer %s: %s", p, err)
					return
				}
				svr.mtx.Lock()
				svr.replicationPeers[p] = s
				svr.mtx.Unlock()
				svr.handleNewStream(s)
			}

			writer := msgio.NewVarintWriter(s)
			err = writeMsgWithTimeout(writer, &pb.Message{
				Type: pb.Message_REPLICATE,
				Payload: &pb.Message_Ids{
					Ids: &pb.Message_IDs{
						MessageID: id[:],
						PeerID:    []byte(to),
					},
				},
			})
			if err != nil {
				log.Errorf("Error writing REPLICATE message to peer %s: %s", p, err)
			}
		}(p, s)
	}
	svr.mtx.RUnlock()
	return writeStatusMessage(w, pb.Message_SUCCESS)
}

func writeStatusMessage(w msgio.Writer, code pb.Message_Status) error {
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
