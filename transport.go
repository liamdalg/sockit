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

func readN(reader io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(reader, buf)
	return buf, err
}
