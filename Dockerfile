FROM alpine
RUN apk add util-linux coreutils curl && apk update && apk upgrade
RUN curl -LO https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl
RUN chmod +x kubectl && mv kubectl /bin
WORKDIR /
ADD external-snapshot-metadata-client .
CMD ["tail", "/dev/null"]
