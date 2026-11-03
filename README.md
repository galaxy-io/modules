# galaxy-io/modules

[![CI](https://github.com/galaxy-io/modules/actions/workflows/ci.yaml/badge.svg)](https://github.com/galaxy-io/modules/actions/workflows/ci.yaml)

Shared Go building blocks for Galaxy apps. Each module is versioned on its own.

| Module | Description | |
| --- | --- | --- |
| [`identity`](identity) | Authentication with Keycloak, Zitadel, or a trusted gateway. | [![Go Reference](https://pkg.go.dev/badge/github.com/galaxy-io/modules/identity.svg)](https://pkg.go.dev/github.com/galaxy-io/modules/identity) [![Version](https://img.shields.io/github/v/tag/galaxy-io/modules?filter=identity/*&label=version)](https://github.com/galaxy-io/modules/tags) |
| [`secret`](secret) | Resolves secret refs to values, scoped per tenant. | [![Go Reference](https://pkg.go.dev/badge/github.com/galaxy-io/modules/secret.svg)](https://pkg.go.dev/github.com/galaxy-io/modules/secret) [![Version](https://img.shields.io/github/v/tag/galaxy-io/modules?filter=secret/*&label=version)](https://github.com/galaxy-io/modules/tags) |

## Install

```sh
go get github.com/galaxy-io/modules/{name}@latest
```

## Development

Install Go, [`just`](https://github.com/casey/just), and [`golangci-lint`](https://golangci-lint.run), then:

```sh
just work
just tidy
just format
just lint
just test
```
