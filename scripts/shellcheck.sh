#!/usr/bin/env bash

set -eu

is_bash() {
    [[ $1 == *.sh ]] && return 0
    [[ $(file -b --mime-type "$1") == text/x-shellscript ]] && return 0
    return 1
}

while IFS= read -r -d $'' file; do
    if is_bash "$file"; then
        shellcheck -W0 -s bash "$file" || continue
    fi
done < <(find . -type f \! \( -path "./.git/*" -o -path "./build/*" \) -print0)

