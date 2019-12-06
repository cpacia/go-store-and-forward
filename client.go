package go_store_and_forward

import (
	"context"
	"encoding/hex"
	"fmt"
	ggio "github.com/gogo/protobuf/io"
	"github.com/golang/protobuf/ptypes"
	ctxio "github.com/jbenet/go-context/io"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	inet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	protocol "github.com/libp2p/go-libp2p-protocol"
	"github.com/pkg/errors"
	"go-store-and-forward/pb"
	"io"
	"math/rand"
	"sync"
	"time"
)

type Message struct {
	MessageID        []byte
	EncryptedMessage []byte
}

type Subscription struct {
	Out   chan Message
	Close func()
}

type Client struct {
	peers           map[peer.ID]bool
	subs            map[int32]*Subscription
	recentlyRelayed map[string]bool
	host            host.Host
	ctx             context.Context
	mtx             sync.RWMutex
	sk              crypto.PrivKey
	protocol        protocol.ID
}

func NewClient(ctx context.Context, sk crypto.PrivKey, peers []peer.ID, h host.Host, opts ...Option) (*Client, error) {
	var cfg Options
	if err := cfg.Apply(append([]Option{Defaults}, opts...)...); err != nil {
		return nil, err
	}

	peerMap := make(map[peer.ID]bool)
	for _, peer := range peers {
		peerMap[peer] = false
	}

	c := &Client{
		peers:           peerMap,
		subs:            make(map[int32]*Subscription),
		recentlyRelayed: make(map[string]bool),
		host:            h,
		ctx:             ctx,
		sk:              sk,
		mtx:             sync.RWMutex{},
		protocol:        cfg.Protocols[0],
	}

	if !h.ID().MatchesPrivateKey(sk) {
		return nil, errors.New("private key does not match host peer ID")
	}

	if cfg.RegistrationDuration < time.Hour {
		return nil, errors.New("expiration duration must be at least one hour")
	}
	if len(cfg.Protocols) == 0 {
		return nil, errors.New("protocol option is required")
	}

	for _, protocol := range cfg.Protocols {
		h.SetStreamHandler(protocol, c.handleNewStream)
	}

	go c.registerWithPeers(cfg.RegistrationDuration)

	return c, nil
}

func (cli *Client) handleNewStream(s inet.Stream) {
	go cli.streamHandler(s)
}

func (cli *Client) streamHandler(s inet.Stream) {
	defer s.Close()
	contextReader := ctxio.NewReader(cli.ctx, s)
	reader := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
	remotePeer := s.Conn().RemotePeer()

	for {
		select {
		case <-cli.ctx.Done():
			return
		default:
		}

		pmes := new(pb.Message)
		if err := reader.ReadMsg(pmes); err != nil {
			s.Reset()
			if err == io.EOF {
				log.Debugf("server %s closed stream", remotePeer)
			}
			return
		}

		if pmes.Type != pb.Message_MESSAGE || pmes.GetEncryptedMessage() == nil {
			log.Errorf("Server %s sending malformed MESSAGE", remotePeer)
			continue
		}
		enc := pmes.GetEncryptedMessage()
		messageIDStr := hex.EncodeToString(enc.MessageID)

		cli.mtx.Lock()
		_, ok := cli.recentlyRelayed[messageIDStr]
		if !ok {
			cli.recentlyRelayed[messageIDStr] = true
			time.AfterFunc(time.Minute*5, func() {
				cli.mtx.Lock()
				delete(cli.recentlyRelayed, messageIDStr)
				cli.mtx.Unlock()
			})

			for _, sub := range cli.subs {
				sub.Out <- Message{
					MessageID:        enc.MessageID,
					EncryptedMessage: enc.Message,
				}
			}
		}
		cli.mtx.Unlock()
	}
}

func (cli *Client) AckMessage(ctx context.Context, messageID []byte) error {
	var wg sync.WaitGroup
	for p, registered := range cli.peers {
		if registered {
			wg.Add(1)
			go func(p peer.ID) {
				defer wg.Done()

				s, err := cli.host.NewStream(ctx, p, cli.protocol)
				if err != nil {
					log.Errorf("Error opening stream with server %s", p)
					return
				}
				defer s.Close()

				contextReader := ctxio.NewReader(cli.ctx, s)
				r := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
				w := ggio.NewDelimitedWriter(s)

				err = writeMsgWithTimeout(w, &pb.Message{
					Type: pb.Message_MESSAGE_ACK,
					Payload: &pb.Message_Ack_{
						Ack: &pb.Message_Ack{
							MessageID: messageID,
						},
					},
				})
				if err != nil {
					log.Errorf("Error sending MESSAGE_ACK to server %s", p)
					return
				}

				resp := new(pb.Message)
				if err = readMsgWithTimeout(r, resp); err != nil {
					log.Errorf("Error reading MESSAGE_ACK response from server %s", p)
					return
				}
				if resp.Code != pb.Message_SUCCESS {
					log.Errorf("message ack to server %s failed with code: %s", p, resp.Code)
				}
			}(p)
		}
	}
	wg.Wait()
	return nil
}

func (cli *Client) SubscribeMessages() *Subscription {
	cli.mtx.Lock()
	defer cli.mtx.Unlock()

	n := rand.Int31()
	sub := &Subscription{
		Out: make(chan Message),
		Close: func() {
			cli.mtx.Lock()
			delete(cli.subs, n)
			cli.mtx.Unlock()

		},
	}
	cli.subs[n] = sub
	return sub
}

func (cli *Client) GetMessages(ctx context.Context) ([]Message, error) {
	resp, err := cli.GetMessagesAsync(ctx)
	if err != nil {
		return nil, err
	}
	var messages []Message
	for m := range resp {
		messages = append(messages, m)
	}
	return messages, nil
}

func (cli *Client) GetMessagesAsync(ctx context.Context) (<-chan Message, error) {
	var (
		downloaded = make(map[string]bool)
		mtx        = sync.Mutex{}
		resp       = make(chan Message)
		wg         sync.WaitGroup
	)
	for p, registered := range cli.peers {
		if registered {
			wg.Add(1)
			go func(p peer.ID) {
				defer wg.Done()

				s, err := cli.host.NewStream(ctx, p, cli.protocol)
				if err != nil {
					log.Errorf("Error opening stream with server %s", p)
					return
				}
				defer s.Close()

				contextReader := ctxio.NewReader(ctx, s)
				r := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
				w := ggio.NewDelimitedWriter(s)

				err = writeMsgWithTimeout(w, &pb.Message{
					Type: pb.Message_GET_MESSAGES,
				})
				if err != nil {
					log.Errorf("Error sending GET_MESSAGES to server %s", p)
					return
				}

				for {
					pmes := new(pb.Message)
					if err := readMsgWithTimeout(r, pmes); err != nil {
						log.Errorf("Error reading MESSAGE from server %s", p)
						return
					}
					if pmes.Type != pb.Message_MESSAGE || pmes.GetEncryptedMessage() == nil {
						log.Errorf("Server %s sending malformed MESSAGE", p)
						return
					}
					enc := pmes.GetEncryptedMessage()

					if !enc.More {
						return
					}

					messageIDStr := hex.EncodeToString(enc.MessageID)
					mtx.Lock()
					_, ok := downloaded[messageIDStr]
					if !ok {
						downloaded[messageIDStr] = true
						resp <- Message{
							MessageID:        enc.MessageID,
							EncryptedMessage: enc.Message,
						}
					}
					mtx.Unlock()
				}
			}(p)
		}
	}
	go func() {
		wg.Wait()
		close(resp)
	}()

	return resp, nil
}

func (cli *Client) SendMessage(ctx context.Context, to, server peer.ID, encryptedMessage []byte) error {
	s, err := cli.host.NewStream(ctx, server, cli.protocol)
	if err != nil {
		return err
	}
	defer s.Close()

	w := ggio.NewDelimitedWriter(s)
	contextReader := ctxio.NewReader(ctx, s)
	r := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
	err = writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_STORE_MESSAGE,
		Payload: &pb.Message_EncryptedMessage_{
			EncryptedMessage: &pb.Message_EncryptedMessage{
				Message:  encryptedMessage,
				ToPeerID: []byte(to),
			},
		},
	})
	if err != nil {
		return err
	}
	resp := new(pb.Message)
	if err = readMsgWithTimeout(r, resp); err != nil {
		return err
	}
	if resp.Code != pb.Message_SUCCESS {
		return fmt.Errorf("store failed with code: %s", resp.Code)
	}
	return nil
}

func (cli *Client) registerWithPeers(expiration time.Duration) {
	for p := range cli.peers {
		go cli.registerSingle(p, expiration)
	}

	newRegistrationTicker := time.NewTicker(expiration - time.Minute*10)
	boostrapTicker := time.NewTicker(time.Minute)

	for {
		select {
		case <-newRegistrationTicker.C:
			for p := range cli.peers {
				go cli.registerSingle(p, expiration)
			}
		case <-boostrapTicker.C:
			cli.mtx.RLock()
			for p := range cli.peers {
				if !cli.peers[p] {
					go cli.registerSingle(p, expiration)
				}
			}
			cli.mtx.RUnlock()
		case <-cli.ctx.Done():
			return
		}
	}
}

func (cli *Client) authenticate(peer peer.ID) (inet.Stream, error) {
	s, err := cli.host.NewStream(cli.ctx, peer, cli.protocol)
	if err != nil {
		return nil, err
	}

	// Protect connection.
	cli.host.ConnManager().Protect(peer, protectionTag)

	contextReader := ctxio.NewReader(cli.ctx, s)
	r := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
	w := ggio.NewDelimitedWriter(s)

	pubkeyBytes, err := cli.sk.GetPublic().Bytes()
	if err != nil {
		return nil, err
	}
	err = writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_AUTHENTICATE,
		Payload: &pb.Message_Pubkey_{
			Pubkey: &pb.Message_Pubkey{
				Pubkey: pubkeyBytes,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	pmes := new(pb.Message)
	if err := readMsgWithTimeout(r, pmes); err != nil {
		return nil, err
	}

	challengeMsg := pmes.GetChallenge()
	if challengeMsg == nil || challengeMsg.Challenge == nil {
		return nil, fmt.Errorf("server %s sent us invalid challenge message", peer)
	}

	sig, err := cli.sk.Sign(challengeMsg.Challenge)
	if err != nil {
		return nil, err
	}

	err = writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_RESPONSE,
		Payload: &pb.Message_Signature_{
			Signature: &pb.Message_Signature{
				Signature: sig,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	resp := new(pb.Message)
	if err := readMsgWithTimeout(r, resp); err != nil {
		return nil, err
	}

	if resp.Type != pb.Message_STATUS {
		return nil, fmt.Errorf("server %s sent us an invalid challenge response", peer)
	}

	if resp.Code != pb.Message_SUCCESS {
		return nil, fmt.Errorf("server %s sent rejected our authentication. code: %s", peer, resp.Code.String())
	}
	return s, nil
}

func (cli *Client) registerSingle(peer peer.ID, expiration time.Duration) {
	var (
		s          inet.Stream
		err        error
		registered bool
	)
	cli.mtx.RLock()
	registered = cli.peers[peer]
	cli.mtx.RUnlock()

	if !registered {
		s, err = cli.authenticate(peer)
		if err != nil {
			log.Errorf("Server %s authentication fail. Error: %s", peer, err)
		}
	} else {
		s, err = cli.host.NewStream(cli.ctx, peer, cli.protocol)
		if err != nil {
			log.Errorf("Server %s authentication fail. Error: %s", peer, err)
			return
		}
	}

	contextReader := ctxio.NewReader(cli.ctx, s)
	r := ggio.NewDelimitedReader(contextReader, inet.MessageSizeMax)
	w := ggio.NewDelimitedWriter(s)

	ts, err := ptypes.TimestampProto(time.Now().Add(expiration))
	if err != nil {
		log.Errorf("Server %s registration error. Error: %s", peer, err)
		return
	}
	err = writeMsgWithTimeout(w, &pb.Message{
		Type: pb.Message_REGISTER,
		Payload: &pb.Message_Registration_{
			Registration: &pb.Message_Registration{
				Expiry: ts,
			},
		},
	})
	if err != nil {
		log.Errorf("Server %s registration error. Error: %s", peer, err)
		return
	}

	resp := new(pb.Message)
	if err := readMsgWithTimeout(r, resp); err != nil {
		log.Errorf("Server %s registration error. Error: %s", peer, err)
		return
	}

	if resp.Type != pb.Message_STATUS {
		log.Errorf("Server %s sent us an invalid challenge response", peer)
		return
	}

	if resp.Code != pb.Message_SUCCESS {
		log.Errorf("Server %s rejected our authentication", peer)
		return
	}

	cli.mtx.Lock()
	cli.peers[peer] = true
	cli.mtx.Unlock()
}
