<div align="center">

[![CI](https://github.com/galaxy-io/modules/actions/workflows/ci.yaml/badge.svg)](https://github.com/galaxy-io/modules/actions/workflows/ci.yaml)

</div>

# Modules

Shared Go building blocks for Galaxy apps. Each module is versioned on its own.

| Module | Description |
| --- | --- |
| [`secret`](secret) | Resolves secret refs to values, scoped per tenant. |

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
