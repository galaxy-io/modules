default:
    @just --list

# run cmd in every Go module
_each cmd:
    for dir in $(find . -name go.mod -exec dirname {} \;); do (cd "$dir" && {{ cmd }}) || exit 1; done

# gofumpt + goimports across every Go module (settings in .golangci.yaml); `just format check` verifies without writing
format mode="fix": (_each ("golangci-lint fmt " + (if mode == "check" { "--diff " } else { "" }) + "./..."))

# Go linters across every Go module; `just lint check` runs without fixing
lint mode="fix": (_each ("golangci-lint run " + (if mode == "check" { "" } else { "--fix " }) + "./..."))
