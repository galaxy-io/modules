default:
    @just --list

# run cmd in every Go module
_each cmd:
    for dir in $(find . -name go.mod -exec dirname {} \;); do (cd "$dir" && {{ cmd }}) || exit 1; done

# write the gitignored go.work: every module, with each version one module requires of another replaced by its local copy, so they build together before they're tagged
work:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f go.work go.work.sum
    go work init
    for dir in $(find . -name go.mod -exec dirname {} \; | sort); do
        go work use "$dir"
        path=$(awk '/^module /{print $2}' "$dir/go.mod")
        for version in $(grep -ho "$path v[^ ]*" $(find . -name go.mod) | awk '{print $2}' | sort -u); do
            go work edit -replace "$path@$version=$dir"
        done
    done

# go mod tidy in every Go module; `just tidy check` verifies without writing. tidy ignores
# go.work, so sibling modules are replaced by their local copies for the run and dropped after.
tidy mode="fix":
    #!/usr/bin/env bash
    set -euo pipefail
    root=$PWD
    for dir in $(find . -name go.mod -exec dirname {} \; | sort); do
        (
            cd "$dir"
            replaced=()
            trap 'for r in ${replaced[@]+"${replaced[@]}"}; do go mod edit -dropreplace "$r"; done' EXIT
            for sibling in $(find "$root" -name go.mod -exec dirname {} \;); do
                path=$(awk '/^module /{print $2}' "$sibling/go.mod")
                for version in $(grep -o "$path v[^ ]*" go.mod | awk '{print $2}' | sort -u); do
                    go mod edit -replace "$path@$version=$sibling"
                    replaced+=("$path@$version")
                done
            done
            go mod tidy {{ if mode == "check" { "-diff" } else { "" } }}
        )
    done

# run tests in every Go module
test: (_each "go test ./...")

# gofumpt + goimports across every Go module (settings in .golangci.yaml); `just format check` verifies without writing
format mode="fix": (_each ("golangci-lint fmt " + (if mode == "check" { "--diff " } else { "" }) + "./..."))

# Go linters across every Go module; `just lint check` runs without fixing
lint mode="fix": (_each ("golangci-lint run " + (if mode == "check" { "" } else { "--fix " }) + "./..."))
