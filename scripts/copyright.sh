#!/bin/bash

find . -type f -name '*.go' -print0 | while read -r -d $'\0' file
do
  if ! grep -q Copyright "$file"
  then
    cat scripts/copyright.txt "$file" > "$file.new" && mv "$file.new" "$file"
  fi
done
