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

func waitForClose(src io.ReadCloser, dst io.Closer) {
	for {
		buf := make([]byte, 1)
		_, err := src.Read(buf)
		if err != nil {
			dst.Close()
		}
	}
}

func readBytes(reader io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(reader, buf)
	return buf, err
}

func readBytesFromLength(reader io.Reader) ([]byte, error) {
	length, err := readBytes(reader, 1)
	if err != nil {
		return nil, err
	}

	return readBytes(reader, int(length[0]))
}
