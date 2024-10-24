GOOS ?= linux
GOARCH ?= amd64
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif


IMAGE_REPO_CLIENT ?= prasadg193/external-snapshot-metadata-client
IMAGE_TAG_CLIENT ?= latest

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o external-snapshot-metadata-client ./main.go

image: build
	docker build --platform=linux/amd64 -t $(IMAGE_REPO_CLIENT):$(IMAGE_TAG_CLIENT) -f Dockerfile .

push:
	docker push $(IMAGE_REPO_CLIENT):$(IMAGE_TAG_CLIENT)

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)
