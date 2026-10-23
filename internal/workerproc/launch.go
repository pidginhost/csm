package workerproc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

// Process is a started worker.
type Process interface {
	// Conn is the parent's end of the worker socket.
	Conn() *net.UnixConn
	// Kill sends SIGKILL and never blocks.
	Kill() error
	// Done is closed once the process has exited and been reaped.
	Done() <-chan struct{}
	// PID is for logs and Stats only.
	PID() int
}

// Launcher starts one worker.
type Launcher func(ctx context.Context) (Process, error)

// ExecLauncher starts command as a child process whose fd 0 and fd 1 are both
// its end of one Unix socket pair. ctx is checked before starting and not
// held: ending the request must not kill the worker, because whether a
// worker dies is the supervisor's decision.
func ExecLauncher(command string, args, env []string) Launcher {
	return func(ctx context.Context) (Process, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pair, err := socketpair()
		if err != nil {
			return nil, fmt.Errorf("workerproc: socketpair: %w", err)
		}
		parentFile := os.NewFile(uintptr(pair[0]), "worker-parent")
		childFile := os.NewFile(uintptr(pair[1]), "worker-child")
		defer childFile.Close()
		c, err := net.FileConn(parentFile)
		_ = parentFile.Close()
		if err != nil {
			return nil, fmt.Errorf("workerproc: worker socket: %w", err)
		}
		conn := c.(*net.UnixConn)

		cmd := exec.Command(command, args...) // #nosec G204 -- command comes from the daemon's own config, not from scanned content.
		cmd.Env = env
		cmd.Stdin = childFile
		cmd.Stdout = childFile
		if err := cmd.Start(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("workerproc: start worker: %w", err)
		}
		p := &execProcess{cmd: cmd, conn: conn, done: make(chan struct{})}
		go func() {
			_ = cmd.Wait()
			close(p.done)
		}()
		return p, nil
	}
}

type execProcess struct {
	cmd  *exec.Cmd
	conn *net.UnixConn
	done chan struct{}
}

func (p *execProcess) Conn() *net.UnixConn   { return p.conn }
func (p *execProcess) Done() <-chan struct{} { return p.done }
func (p *execProcess) PID() int              { return p.cmd.Process.Pid }

func (p *execProcess) Kill() error {
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// socketpair returns a close-on-exec Unix stream pair. Holding ForkLock keeps
// a concurrent exec from inheriting the descriptors before they are marked;
// SOCK_CLOEXEC would do this atomically, but it does not exist on every
// platform the packages are built on.
func socketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return [2]int{}, err
	}
	syscall.CloseOnExec(pair[0])
	syscall.CloseOnExec(pair[1])
	return pair, nil
}
