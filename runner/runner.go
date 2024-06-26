// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/sirupsen/logrus"
)

type Runner struct {
	id              string
	labels          []string
	organization    string
	group           string
	ephemeral       bool
	machine         *firecracker.Machine
	iface           string
	bridgeIPv4      netip.Addr
	bridgeIPv6      netip.Addr
	ipv4            netip.Addr
	ipv6            netip.Addr
	bridgeInterface string
	mac             string

	kernel     string
	filesystem string

	firecrackerBinary string
	jailerBinary      string

	logger *slog.Logger
	logrus *logrus.Logger

	CpuCount   int64
	MemorySize int64
	SMT        bool
	DiskSize   int64

	Interactive bool
	exitCh      chan error
}

type wrappingHook struct {
	logger *slog.Logger
}

func (h *wrappingHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel, logrus.TraceLevel}
}

func (h *wrappingHook) Fire(entry *logrus.Entry) error {
	var level slog.Level
	switch entry.Level {
	case logrus.PanicLevel:
		level = slog.LevelError
	case logrus.FatalLevel:
		level = slog.LevelError
	case logrus.ErrorLevel:
		level = slog.LevelError
	case logrus.WarnLevel:
		level = slog.LevelWarn
	case logrus.InfoLevel:
		level = slog.LevelInfo
	case logrus.DebugLevel:
		level = slog.LevelDebug
	case logrus.TraceLevel:
		level = slog.LevelDebug
	}

	attributes := make([]slog.Attr, 0)
	for key, value := range entry.Data {
		attributes = append(attributes, slog.Any(key, value))
	}
	h.logger.LogAttrs(context.Background(), level, entry.Message, attributes...)

	return nil
}

func New(logger *slog.Logger, id string, bridgeInterface string, ipv4 netip.Addr, ipv6 netip.Addr, kernel, filesystem, jailerBinary, firecrackerBinary string, organization string, labels []string, group string, bridgeIPv4 netip.Addr, bridgeIPv6 netip.Addr, ephemeral bool) (*Runner, error) {
	macBuffer := make([]byte, 6)
	_, err := rand.Read(macBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mac address: %w", err)
	}

	macBuffer[0] = (macBuffer[0] | 2) & 0xfe
	macBuffer[0] = (macBuffer[0] | 2) & 0xfe
	macAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", macBuffer[0], macBuffer[1], macBuffer[2], macBuffer[3], macBuffer[4], macBuffer[5])

	r := &Runner{
		id:              id,
		organization:    organization,
		labels:          labels,
		group:           group,
		iface:           "tap" + id,
		bridgeIPv4:      bridgeIPv4,
		bridgeIPv6:      bridgeIPv6,
		ipv4:            ipv4,
		ipv6:            ipv6,
		bridgeInterface: bridgeInterface,
		mac:             macAddress,
		ephemeral:       ephemeral,

		kernel:     kernel,
		filesystem: filesystem,

		jailerBinary:      jailerBinary,
		firecrackerBinary: firecrackerBinary,

		CpuCount:   2,
		MemorySize: 4 * 1024,
		SMT:        false,
		DiskSize:   10 * 1024 * 1024 * 1024,

		logger: logger,
		logrus: &logrus.Logger{
			Out:          io.Discard,
			Level:        logrus.DebugLevel,
			Hooks:        make(logrus.LevelHooks),
			Formatter:    new(logrus.TextFormatter),
			ExitFunc:     os.Exit,
			ReportCaller: false,
		},
		exitCh: make(chan error),
	}
	r.logrus.Hooks.Add(&wrappingHook{logger: logger})
	return r, nil
}

func (r *Runner) ID() string {
	return r.id
}

func (r *Runner) IPv4() netip.Addr {
	return r.ipv4
}

func (r *Runner) IPv6() netip.Addr {
	return r.ipv6
}

func (r *Runner) setupInterface(ctx context.Context) error {
	log.Printf("creating network interface %s for runner %s", r.iface, r.id)

	err := exec.CommandContext(ctx, "ip", "tuntap", "add", r.iface, "mode", "tap").Run()
	if err != nil {
		return fmt.Errorf("failed to create tuntap interface %s: %w", r.iface, err)
	}

	err = exec.CommandContext(ctx, "ip", "link", "set", r.iface, "master", r.bridgeInterface).Run()
	if err != nil {
		return fmt.Errorf("failed to set ip on tuntap interface %s: %w", r.iface, err)
	}

	err = exec.CommandContext(ctx, "ip", "link", "set", r.iface, "up").Run()
	if err != nil {
		return fmt.Errorf("failed to set tuntap interface up %s: %w", r.bridgeInterface, err)
	}

	return nil
}

func (r *Runner) destroyInterface(ctx context.Context) error {
	log.Printf("destroying network interface %s for runner %s", r.iface, r.id)

	err := exec.CommandContext(ctx, "ip", "link", "del", r.iface).Run()
	if err != nil {
		return fmt.Errorf("failed to destroy network interface %s: %w", r.iface, err)
	}

	return nil
}

func (r *Runner) cleanup(ctx context.Context) error {
	r.logger.Debug("cleaning up vm resources")
	path := filepath.Join("/srv/jailer/firecracker", r.id)
	if r.ephemeral {
		os.RemoveAll(path)
	} else {
		path = filepath.Join(path, "root")
		os.Remove(filepath.Join(path, "firecracker.socket"))
		os.Remove(filepath.Join(path, "firecracker"))
		os.Remove(filepath.Join(path, filepath.Base(r.kernel)))
		os.Remove(filepath.Join(path, filepath.Base(r.filesystem)))
		os.RemoveAll(filepath.Join(path, "run"))
		os.RemoveAll(filepath.Join(path, "dev"))
	}

	if err := r.destroyInterface(ctx); err != nil {
		return fmt.Errorf("failed to remove network interface: %w", err)
	}

	return nil
}

func (r *Runner) Stop(ctx context.Context) error {
	if r.machine == nil {
		return fmt.Errorf("could not stop runner not started")
	}

	if err := r.machine.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown runner: %w", err)
	}

	return nil
}

func (r *Runner) Wait(ctx context.Context) error {
	if r.machine == nil {
		return fmt.Errorf("could not wait runner not started")
	}
	if err := r.machine.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait runner: %w", err)
	}
	return <-r.exitCh
}

type logWriter struct {
	l      *slog.Logger
	buffer bytes.Buffer
}

func (lw *logWriter) Write(data []byte) (int, error) {
	index := bytes.Index(data, []byte{'\n'})
	if index != -1 {
		lw.buffer.Write(data[:index])
		lw.l.Debug(string(lw.buffer.Bytes()))
		lw.buffer.Reset()
		if index == len(data) {
			return len(data), nil
		}
		data = data[index+1:]
	}

	lw.buffer.Write(data)

	return len(data), nil
}

func (r *Runner) Start(ctx context.Context, token string) error {
	if err := r.setupInterface(ctx); err != nil {
		if err := r.destroyInterface(ctx); err != nil {
			return fmt.Errorf("failed to destroy interface: %w", err)
		}
		return fmt.Errorf("failed to create network interface: %w", err)
	}

	cfg, err := r.createConfig(ctx)
	if err != nil {
		if err := r.destroyInterface(ctx); err != nil {
			return fmt.Errorf("failed to destroy interface: %w", err)
		}
		return fmt.Errorf("failed to create vm configuration: %w", err)
	}

	if r.Interactive {
		cfg.JailerCfg.Stdin = os.Stdin
		cfg.JailerCfg.Stdout = os.Stdout
		cfg.JailerCfg.Stderr = os.Stderr
	}

	m, err := firecracker.NewMachine(ctx, *cfg, firecracker.WithLogger(logrus.NewEntry(r.logrus)))
	if err != nil {
		if err := r.destroyInterface(ctx); err != nil {
			return fmt.Errorf("failed to destroy interface: %w", err)
		}
		return fmt.Errorf("failed to create vm machine: %w", err)
	}

	r.machine = m

	zeroAddr := netip.Addr{}
	if r.bridgeIPv6 == zeroAddr {
		r.logger.Info("starting runner", "ipv4", r.ipv4.String(), "ipv6", "disabled", "id", r.id)
	} else {
		r.logger.Info("starting runner", "ipv4", r.ipv4.String(), "ipv6", r.ipv6.String(), "id", r.id)
	}
	if err := m.Start(ctx); err != nil {
		r.cleanup(ctx)
		return fmt.Errorf("failed to start microvm: %w", err)
	}

	if r.Interactive {
		go func() {
			if err := m.Wait(context.Background()); err != nil {
				r.logger.Error("failed to wait for shutdown")
			}
			r.exitCh <- r.cleanup(context.Background())
		}()
	}

	metadata := map[string]map[string]map[string]string{
		"latest": {
			"meta-data": {
				"organization": r.organization,
				"token":        token,
				"labels":       strings.Join(r.labels, ","),
				"group":        r.group,
				"ephemeral":    fmt.Sprintf("%t", r.ephemeral),
			},
		},
	}

	if err := m.SetMetadata(ctx, metadata); err != nil {
		// stop already started vm
		r.Stop(ctx)
		r.destroyInterface(ctx)
		return fmt.Errorf("failed to set metadata for microvm: %w", err)
	}

	return nil
}

func createDiskImage(ctx context.Context, path string, size int64, uid int, gid int) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create disk image: %w", err)
	}
	defer f.Close()

	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("failed to chown overlay fs: %w", err)
	}

	err = f.Truncate(size)
	if err != nil {
		return fmt.Errorf("failed to truncate disk image: %w", err)
	}

	out, err := exec.CommandContext(ctx, "mkfs.ext4", "-F", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute mkfs.ext4: %s: %w", out, err)
	}

	return err
}

func (r *Runner) createConfig(ctx context.Context) (*firecracker.Config, error) {
	bootArgs := fmt.Sprintf("console=ttyS0 reboot=k panic=1 pci=off init=/sbin/overlay-init -- %s %s %s", r.id, r.ipv4, r.bridgeIPv4)
	zeroAddr := netip.Addr{}
	if r.ipv6 == zeroAddr {
		bootArgs = fmt.Sprintf("%s %s %s", bootArgs, r.ipv6, r.bridgeIPv6)
	}

	socketPath := "firecracker.socket"
	rootDriveID := "root"

	var interfaces firecracker.NetworkInterfaces
	interfaces = append(interfaces, firecracker.NetworkInterface{
		AllowMMDS: true,
		StaticConfiguration: &firecracker.StaticNetworkConfiguration{
			MacAddress:  r.mac,
			HostDevName: r.iface,
		},
	})

	uid := 123
	gid := 100

	logWriter := &logWriter{l: r.logger}

	cfg := &firecracker.Config{
		SocketPath:      socketPath,
		KernelImagePath: r.kernel,
		KernelArgs:      bootArgs,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  &r.CpuCount,
			MemSizeMib: &r.MemorySize,
			Smt:        &r.SMT,
		},
		Drives: []models.Drive{
			{
				DriveID:      &rootDriveID,
				IsRootDevice: firecracker.Bool(true),
				IsReadOnly:   firecracker.Bool(true),
				PathOnHost:   &r.filesystem,
			},
		},
		NetworkInterfaces: interfaces,
		MmdsVersion:       firecracker.MMDSv2,
		JailerCfg: &firecracker.JailerConfig{
			UID:            &uid,
			GID:            &gid,
			ID:             r.id,
			Daemonize:      false,
			NumaNode:       firecracker.Int(0),
			ChrootBaseDir:  "/srv/jailer",
			ChrootStrategy: NewOverlayChrootStrategy(r),
			ExecFile:       r.firecrackerBinary,
			JailerBinary:   r.jailerBinary,
			CgroupVersion:  "2",
			Stdout:         logWriter,
			Stderr:         logWriter,
		},
	}

	return cfg, nil
}

const (
	OverlayLinkFilesToRootFSHandlerName = "fcinit.OverlayLinkFilesToRootFS"
	rootfsFolderName                    = "root"
)

func (s *OverlayChrootStrategy) OverlayLinkFilesHandler() firecracker.Handler {
	return firecracker.Handler{
		Name: OverlayLinkFilesToRootFSHandlerName,
		Fn: func(ctx context.Context, m *firecracker.Machine) error {
			if m.Cfg.JailerCfg == nil {
				return firecracker.ErrMissingJailerConfig
			}

			// assemble the path to the jailed root folder on the host
			rootfs := filepath.Join(
				m.Cfg.JailerCfg.ChrootBaseDir,
				filepath.Base(m.Cfg.JailerCfg.ExecFile),
				m.Cfg.JailerCfg.ID,
				rootfsFolderName,
			)

			// link kernel image to root fs
			kernelImageName := filepath.Base(m.Cfg.KernelImagePath)
			kernelPathOnHost := filepath.Join(rootfs, kernelImageName)
			if err := os.Link(
				m.Cfg.KernelImagePath,
				kernelPathOnHost,
			); err != nil {
				return err
			}
			m.Cfg.KernelImagePath = kernelImageName

			// link all drives to the root fs
			for i, drive := range m.Cfg.Drives {
				sourceFilesystemPath := firecracker.StringValue(drive.PathOnHost)
				driveFilename := filepath.Base(sourceFilesystemPath)

				drivePath := filepath.Join(rootfs, driveFilename)
				if err := os.Link(
					sourceFilesystemPath,
					drivePath,
				); err != nil {
					return err
				}

				m.Cfg.Drives[i].PathOnHost = firecracker.String(driveFilename)
			}

			// create or reuse overlay fs of disk size
			overlayDriveFilename := "overlay.ext4"
			overlayPathOnHost := filepath.Join(rootfs, overlayDriveFilename)
			if _, err := os.Stat(overlayPathOnHost); errors.Is(err, os.ErrNotExist) {
				err := createDiskImage(ctx, overlayPathOnHost, s.runner.DiskSize, *m.Cfg.JailerCfg.UID, *m.Cfg.JailerCfg.GID)
				if err != nil {
					return err
				}
			}

			// add additional drive for overlay fs
			m.Cfg.Drives = append(m.Cfg.Drives, models.Drive{
				DriveID:      firecracker.String("overlay"),
				IsRootDevice: firecracker.Bool(false),
				IsReadOnly:   firecracker.Bool(false),
				PathOnHost:   firecracker.String(overlayDriveFilename),
			})

			for _, fifoPath := range []*string{&m.Cfg.LogFifo, &m.Cfg.MetricsFifo} {
				if fifoPath == nil || *fifoPath == "" {
					continue
				}

				fileName := filepath.Base(*fifoPath)
				if err := os.Link(
					*fifoPath,
					filepath.Join(rootfs, fileName),
				); err != nil {
					return err
				}

				if err := os.Chown(filepath.Join(rootfs, fileName), *m.Cfg.JailerCfg.UID, *m.Cfg.JailerCfg.GID); err != nil {
					return err
				}

				// update fifoPath as jailer works relative to the chroot dir
				*fifoPath = fileName
			}

			return nil
		},
	}

}

type OverlayChrootStrategy struct {
	runner *Runner
}

func NewOverlayChrootStrategy(runner *Runner) OverlayChrootStrategy {
	return OverlayChrootStrategy{
		runner: runner,
	}
}

func (s OverlayChrootStrategy) AdaptHandlers(handlers *firecracker.Handlers) error {
	if !handlers.FcInit.Has(firecracker.CreateLogFilesHandlerName) {
		return firecracker.ErrRequiredHandlerMissing
	}

	handlers.FcInit = handlers.FcInit.AppendAfter(
		firecracker.CreateLogFilesHandlerName,
		s.OverlayLinkFilesHandler(),
	)

	handlers.FcInit = handlers.FcInit.Swap(firecracker.Handler{
		Name: firecracker.SetupKernelArgsHandlerName,
		Fn: func(ctx context.Context, m *firecracker.Machine) error {
			return nil
		},
	})

	return nil
}
