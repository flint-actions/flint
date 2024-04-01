ARCH=amd64
OP_CLI_VERSION=v2.0.0

apt-get install -yq curl ca-certificates unzip

curl -sSfo op.zip https://cache.agilebits.com/dist/1P/op2/pkg/${OP_CLI_VERSION}/op_linux_${ARCH}_${OP_CLI_VERSION}.zip \
  && unzip -od /usr/local/bin/ op.zip \
  && rm op.zip

# 1Password/load-secrets-action writes it's binary into /usr/local/bin. Therefore this directory needs to be writable by the runner.
# See https://github.com/1Password/load-secrets-action/issues/26 for more information.
chmod -R 777 /usr/local/bin
