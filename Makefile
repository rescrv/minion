.PHONY: all

export GOPATH=$(shell pwd)/build
export MINIONPATH=${GOPATH}/src/git.rescrv.net/minion

all: pkg/minion/minion pkg/minion/minion-daemon minion.tar.gz

pkg/minion/minion: $(wildcard *.go) $(wildcard */*.go)
	mkdir -p $(shell dirname $@)
	cd ${MINIONPATH}/minion && go build
	cp -f ${MINIONPATH}/minion/minion $@

pkg/minion/minion-daemon: $(wildcard *.go) $(wildcard */*.go)
	mkdir -p $(shell dirname $@)
	cd ${MINIONPATH}/minion-daemon && go build
	cp -f ${MINIONPATH}/minion-daemon/minion-daemon $@

minion.tar.gz: pkg/minion/minion pkg/minion/minion-daemon
	tar czvf $@ -C pkg/ minion
