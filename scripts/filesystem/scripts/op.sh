ARCH=amd64
OP_CLI_VERSION=v2.0.0

curl -sSfo op.zip https://cache.agilebits.com/dist/1P/op2/pkg/${OP_CLI_VERSION}/op_linux_${ARCH}_${OP_CLI_VERSION}.zip \
  && unzip -od /usr/local/bin/ op.zip \
  && rm op.zip
