package storeandforward

import (
	"context"
	"errors"
	"github.com/cpacia/go-store-and-forward/pb"
	ggio "github.com/gogo/protobuf/io"
	"github.com/gogo/protobuf/proto"
	"time"
)

var ReadWriteTimeout = time.Second * 30

func writeMsgWithTimeout(w ggio.Writer, pmes *pb.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), ReadWriteTimeout)
	defer cancel()

	errCh := make(chan error)
	go func() {
		errCh <- w.WriteMsg(pmes)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return errors.New("write message timeout")
	}
}

func readMsgWithTimeout(r ggio.Reader, msg proto.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), ReadWriteTimeout)
	defer cancel()

	doneCh := make(chan error)
	go func() {
		err := r.ReadMsg(msg)
		doneCh <- err
	}()

	select {
	case err := <-doneCh:
		return err
	case <-ctx.Done():
		return errors.New("read message timeout")
	}
}
