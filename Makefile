.PHONY: build test install clean disasm render report ghidra-meta ghidra

BINARY := unflutter
SAMPLE ?= libapp.so
SAMPLE_NAME := $(basename $(notdir $(SAMPLE)))
OUT_DIR := out/$(SAMPLE_NAME)
GHIDRA_HOME ?= $(HOME)/ghidra
GHIDRA_PROJECTS ?= /tmp/ghidra-projects

build:
	go build -o $(BINARY) ./cmd/unflutter

test:
	go test ./...

install: build
	install -d ~/.unflutter/ghidra_scripts
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	install -m 644 ghidra_scripts/*.py ~/.unflutter/ghidra_scripts/
	@echo "installed: /usr/local/bin/$(BINARY)"
	@echo "installed: ~/.unflutter/ghidra_scripts/"
	@ls ~/.unflutter/ghidra_scripts/

disasm: build
	./$(BINARY) disasm --libapp $(SAMPLE) --out $(OUT_DIR)

render: build
	./$(BINARY) render --in $(OUT_DIR) --no-dot
	@echo "render output: $(OUT_DIR)/render/"

report: disasm render
	@echo "report complete: $(OUT_DIR)/"

ghidra-meta: build
	./$(BINARY) ghidra-meta --in $(OUT_DIR)

SCRIPT_DIR ?= $(HOME)/.unflutter/ghidra_scripts

ghidra: ghidra-meta
	mkdir -p "$(GHIDRA_PROJECTS)"
	"$(GHIDRA_HOME)/support/analyzeHeadless" \
		"$(GHIDRA_PROJECTS)" unflutter_$(SAMPLE_NAME) \
		-import $(SAMPLE) -overwrite \
		-scriptPath "$(SCRIPT_DIR)" \
		-preScript unflutter_prescript.py \
		-postScript unflutter_apply.py "$(CURDIR)/$(OUT_DIR)/ghidra_meta.json" "$(CURDIR)/$(OUT_DIR)/decompiled" \
		2>&1 | tee $(OUT_DIR)/ghidra_apply.log

clean:
	rm -f $(BINARY)
	go clean ./...
