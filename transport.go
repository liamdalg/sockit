package sockit

import (
	"io"

	"golang.org/x/sync/errgroup"
)

func copyStreams(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	g := errgroup.Group{}

	g.Go(func() error {
		_, err := io.Copy(a, b)
		return err
	})
	g.Go(func() error {
		_, err := io.Copy(b, a)
		return err
	})

	return g.Wait()
}
