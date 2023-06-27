Secure and isolated GitHub Actions runs without a headache.

# What is Flint?
Flint is an open source coordinator for GitHub Actions that is built to run isolated and secured actions on custom hosted runners.
It runs said runners within empheral VMs managed through [firecracker](https://github.com/firecracker-microvm/firecracker).

# Stability

Expect bugs! Flint is very early in it's development and did not have a stable release for now.

# Getting Started

To get started with Flint compile it from source via:

```sh
git clone https://github.com/tobiaskohlbau/flint
cd flint
make build
````

In order to build a working go toolchain is required. After sucessfull compilation put the binary in a folder like for
e.g. `/root/flint/`.

## Filesystem and kernel
A linux kernel and rootfs is required in order to work. A sample kernel and rootfs can be built by (docker, dd, mkfs.ext4 are required):

```sh
make filesystem
make kernel
```

This builts a filesystem, kernel in `build/rootfs/rootfs.ext4` and `build/kernel/linux/vmlinux`. Additionally
[firecracker](https://github.com/firecracker-microvm/firecracker) and it's jailer binary are needed.
For more information have a look into `scripts/filesystem.sh` and `scripts/kernel.sh`.

Copy the filesystem, kernel, firecracker and jailer to a directory like for e.g. `/root/flint/`. Make sure `rootfs.ext4`
has owner uid 123 and group id 100.

`chown 123:100 /root/flint/rootfs.ext4`

### Additional dependencies

In addition to firecracker the following runtime dependencies are needed:

- `mkfs.ext4`
- `ip`

## Network configuration

Flint for now requires a preconfigured bridge interface. It can be setup with the help of the following commands:

```sh
ip link add name br-flint type bridge
ip addr add 10.0.0.1/24 dev br-flint
ip addr add fd3b:5cee:6e4c:2a55:1::2/80 dev br-flint
ip link set dev br-flint up

sysctl -w net.ipv6.conf.eth0.proxy_ndp=1
ip -6 neighbour add proxy fd3b:5cee:6e4c:2a55:1::2/80 dev eth0
ip -6 route add fd3b:5cee:6e4c:2a55:1::/80 dev br-flint
```

Replace `fd3b:5cee:6e4c:2a55` with your public IPv6 /64 prefix.

## GitHub App

Flint leverages a GitHub App in order to dynamically register spawned runners. GitHub Apps require an organization
account (this does not need to be an payed organization). As a getting started guide see the official [documentation](bhttps://docs.github.com/en/apps/creating-github-apps/creating-github-apps/creating-a-github-app)
on how to create a GitHub App. Configure a webhook URL which points to `https://YOUR_DOMAIN/webhook` and configure
a secret. Additionally a GitHub private key is needed for the application to authenticate.

After sucessfully creating the app go to `Permissions & events` and configure _Read-only_ access for Actions and Metadata.
In addition _Read and write_ permission for Organization _Self-hosted runners_ is required. Save your changes and refresh
the page. It should now exist a configuration section for _Subscribe to events_. In this section _Workflow job_ events
are needed to inform Flint about a new workflow which requires a runner.

Put the `private.pem` file into for e.g. `/root/flint/`

## Launching

Flint can be launched through multiple ways for example running it interactive:

```sh
./flint --jailer=/root/flint/jailer --firecracker=/root/flint/firecracker --kernel=/root/flint/vmlinux --filesystem=/root/flint/rootfs.ext4 --privateKey=/root/flint/private.pem --webhookSecret=ABCDefgh --organization=flint-actions --appID=123456
```

This should launch flint and wait for any event which requires a self-hosted runner. Any action which should run und Flint
can be configured with:


```YAML
runs-on: self-hosted
```


For continous running flint a simple systemd service could be created:

```
[Unit]
Description=flint a fircracker gihtub actions runner service
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
WorkingDirectory=/root/flint
ExecStart=/root/flint/flint --jailer=/root/flint/jailer --firecracker=/root/flint/firecracker --kernel=/root/flint/vmlinux --filesystem=/root/flint/rootfs.ext4 --privateKey=/root/flint/private.pem --webhookSecret=ABCDefgh --organization=flint-actions

[Install]
WantedBy=multi-user.target
```

# Contributing

Contributions are welcome.

# FAQ

1. Q: I tried to run on arm64 and got error XYZ.
   A: Currently Flint is untested on arm64 but in theory everything should work out of the box.

2. Q: Is there an ability do debug an vm image?
   A: Yes with the option `--interactive` Flint spawns a single runner and connects stdout, stderr and stdout to the
      current shell. This allows login into the machine with for e.g. runner:runner (user:password). This disables
      the http server listening for events.
