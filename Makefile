## rbac-therapist Makefile
## Run `make help` to see available targets.

# Project metadata
MODULE      := github.com/rbac-therapist/rbac-therapist
BIN_DIR     := bin
OPERATOR    := $(BIN_DIR)/operator
RBACT       := $(BIN_DIR)/rbact
IMG         ?= rbac-therapist/operator:latest

# Tool versions — pin for reproducible builds
CONTROLLER_TOOLS_VERSION ?= v0.17.2
ENVTEST_VERSION          ?= latest
GOLANGCI_LINT_VERSION    ?= v1.64.5

# Tool paths (local to project, not global)
LOCALBIN    := $(PWD)/bin
CONTROLLER_GEN := $(LOCALBIN)/controller-gen
ENVTEST     := $(LOCALBIN)/setup-envtest
GOLANGCI    := $(LOCALBIN)/golangci-lint

##@ General

.PHONY: help
help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: all
all: generate fmt vet build ## Run generate, fmt, vet, and build

.PHONY: generate
generate: controller-gen ## Generate CRD manifests, RBAC, and deepcopy functions
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONTROLLER_GEN) crd:generateEmbeddedObjectMeta=true paths="./api/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=rbac-therapist-operator paths="./internal/controllers/..." output:rbac:artifacts:config=config/rbac

.PHONY: manifests
manifests: generate ## Alias for generate (creates CRD + RBAC manifests)

.PHONY: fmt
fmt: ## Run gofmt
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint
	$(GOLANGCI) run ./...

.PHONY: tidy
tidy: ## Run go mod tidy
	go mod tidy

##@ Build

.PHONY: build
build: build-operator build-rbact ## Build both operator and rbact CLI

.PHONY: build-operator
build-operator: ## Build the operator binary
	@mkdir -p $(BIN_DIR)
	go build -o $(OPERATOR) ./cmd/operator

.PHONY: build-rbact
build-rbact: ## Build the rbact CLI binary
	@mkdir -p $(BIN_DIR)
	go build -o $(RBACT) ./cmd/rbact

.PHONY: install-rbact
install-rbact: build-rbact ## Install rbact to $GOPATH/bin
	cp $(RBACT) $(GOPATH)/bin/rbact

##@ Testing

.PHONY: test
test: envtest ## Run unit and integration tests
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-path $(LOCALBIN)/k8s -p path)" \
		go test ./... -v -count=1

.PHONY: test-unit
test-unit: ## Run unit tests only (no envtest required)
	go test ./internal/engine/... ./cmd/... -v -count=1

.PHONY: test-bench-parser
test-bench-parser: ## Run parser performance benchmarks
	go test ./internal/engine/parser -bench BenchmarkParse -benchmem -run '^$$'

.PHONY: test-bench-parser-guard
test-bench-parser-guard: ## Run parser benchmark regression guard (CI-equivalent)
	bash hack/ci/benchmark_parser.sh

.PHONY: test-integration
test-integration: envtest ## Run integration tests with envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-path $(LOCALBIN)/k8s -p path)" \
		go test ./internal/controllers/... ./internal/integration/... -v -count=1

ENVTEST_K8S_VERSION ?= 1.32.0

##@ Deployment

.PHONY: docker-build
docker-build: ## Build the operator Docker image
	docker build -t $(IMG) -f Dockerfile .

.PHONY: docker-push
docker-push: ## Push the operator Docker image
	docker push $(IMG)

.PHONY: install
install: generate ## Install CRDs into the cluster pointed at by $KUBECONFIG
	kubectl apply -f config/crd/bases/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the cluster
	kubectl delete -f config/crd/bases/ --ignore-not-found

.PHONY: deploy
deploy: ## Deploy the operator to the cluster
	kubectl apply -f config/default/

.PHONY: undeploy
undeploy: ## Undeploy the operator from the cluster
	kubectl delete -f config/default/ --ignore-not-found

##@ Tools

.PHONY: controller-gen
controller-gen: ## Download controller-gen if not present
	@[ -f $(CONTROLLER_GEN) ] || { \
		mkdir -p $(LOCALBIN); \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION); \
	}

.PHONY: envtest
envtest: ## Download setup-envtest if not present
	@[ -f $(ENVTEST) ] || { \
		mkdir -p $(LOCALBIN); \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION); \
	}

.PHONY: golangci-lint
golangci-lint: ## Download golangci-lint if not present
	@[ -f $(GOLANGCI) ] || { \
		mkdir -p $(LOCALBIN); \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LOCALBIN) $(GOLANGCI_LINT_VERSION); \
	}

##@ Examples

.PHONY: examples
examples: build-rbact ## Generate example manifests using rbact
	$(RBACT) generate -f examples/rbact-config.yaml -o examples/generated/
