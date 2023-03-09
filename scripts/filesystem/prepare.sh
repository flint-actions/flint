set -e

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
#  Install build dependencies
apt-get install -yq curl ca-certificates jq unzip sudo

for file in /filesystem/scripts/*
do
  bash "$file"
done

# Install runtime dependencies
apt-get install -yq systemd udev openssh-server iproute2

mkdir -p /etc/systemd/system/sockets.target.wants
mkdir -p /etc/systemd/system/network-online.target.wants
mkdir -p /etc/systemd/system/multi-user.target.wants

ln -s /lib/systemd/system/systemd-networkd.service /etc/systemd/system/dbus-org.freedesktop.network1.service
ln -s /lib/systemd/system/systemd-networkd.service /etc/systemd/system/multi-user.target.wants/systemd-networkd.service
ln -s /lib/systemd/system/systemd-networkd.socket /etc/systemd/system/sockets.target.wants/systemd-networkd.socket
ln -s /lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service

cp /filesystem/runner.service /etc/systemd/system/runner.service
cp /filesystem/runner /usr/bin/runner
ln -s /etc/systemd/system/runner.service /etc/systemd/system/multi-user.target.wants/runner.service

cp /filesystem/overlay-init /sbin/overlay-init

useradd -m -p "\$6\$ShGzK7Sqn\$qWiFNNN.x1KYwOjQo4OICY9Zb7xWIQJgdAAWCkRqFNABPODys14wYfFf7WusQFjBo7fAsW7QKbYb2El/IPfzZ0" -s /bin/bash runner
usermod -a -G sudo runner

# 1Password/load-secrets-action writes it's binary into /usr/local/bin. Therefore this directory needs to be writable by the runner.
# See https://github.com/1Password/load-secrets-action/issues/26 for more information.
chmod -R 777 /usr/local/bin

cd /home/runner/
mkdir actions-runner && cd actions-runner
curl -L -O "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
tar xzf "./actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
rm "./actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
chown -R runner:sudo /home/runner/actions-runner
