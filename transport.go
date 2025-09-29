package sockit

import (
	"fmt"
	"io"

	"golang.org/x/sync/errgroup"
)

func copyStreams(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	g := errgroup.Group{}

	g.Go(func() error {
		if _, err := io.Copy(a, b); err != nil {
			return fmt.Errorf("failed to copy from stream a to b: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if _, err := io.Copy(b, a); err != nil {
			return fmt.Errorf("failed to copy from stream b to a: %w", err)
		}
		return nil
	})

	//nolint:wrapcheck
	return g.Wait()
}

// func waitForClose(src io.ReadCloser, dst io.Closer) {
// 	buf := make([]byte, 1)
// 	for {
// 		_, err := src.Read(buf)
// 		if err != nil {
// 			dst.Close()
// 		}
// 	}
// }

func readBytes(reader io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(reader, buf)
	//nolint:wrapcheck
	return buf, err
}

func readBytesFromLength(reader io.Reader) ([]byte, error) {
	length, err := readBytes(reader, 1)
	if err != nil {
		return nil, err
	}

	return readBytes(reader, int(length[0]))
}
