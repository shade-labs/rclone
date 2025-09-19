#!/bin/bash

RCLONE_BIN="./rclone"
MAX_PARALLEL_JOBS=1
CSV_FILE="pairs.csv"

# Run for a single source/dest pair
run_copy() {
  local src="$1"
  local dst="$2"
  echo "Starting: $src -> $dst"
  "$RCLONE_BIN" copy "$src" "$dst" -v --ignore-existing --transfers 5	
  echo "Finished: $src -> $dst"
}

export -f run_copy
export RCLONE_BIN

# Read CSV line by line
while IFS=, read -r src dst; do
  # Skip empty lines or comment lines
  [[ -z "$src" || -z "$dst" || "$src" =~ ^# ]] && continue

  # Run in background
  run_copy "$src" "$dst" &

  # Limit concurrency
  while (( $(jobs -r | wc -l) >= MAX_PARALLEL_JOBS )); do
    sleep 10
  done
done < "$CSV_FILE"

wait
echo "All transfers completed."
