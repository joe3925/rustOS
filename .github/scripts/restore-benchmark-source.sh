set -euo pipefail

commit="$1"
destination="$2"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
download="$(mktemp -d "$RUNNER_TEMP/rustos-benchmark-source.XXXXXX")"

for artifact_name in "kernel-benchmark-source-v${BENCH_ENV_VERSION}-${commit}" kernel-benchmarks; do
  gh api --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${artifact_name}&per_page=100" \
    > "$download/artifacts.json"
  jq -sr --arg commit "$commit" --arg name "$artifact_name" '
    [.[].artifacts[] | select(.name == $name and .expired == false and .workflow_run.head_sha == $commit)]
    | sort_by(.created_at, .id) | reverse | .[].id
  ' "$download/artifacts.json" > "$download/candidates.txt"
  while read -r artifact_id; do
    source_dir="$download/$artifact_id"
    gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip" > "$source_dir.zip"
    unzip -q "$source_dir.zip" -d "$source_dir"
    if [[ "$artifact_name" == kernel-benchmarks ]]; then
      boot_image="$(find "$source_dir" -path '*/head/boot.img' -print -quit)"
      [[ -n "$boot_image" ]] || continue
      source_dir="$(dirname "$boot_image")"
      [[ -f "$source_dir/environment-version" ]] || continue
      [[ "$(<"$source_dir/environment-version")" == "$BENCH_ENV_VERSION" ]] || continue
      mkdir -p "$destination"
      cp "$source_dir/boot.img" "$source_dir/environment-version" "$destination/"
      if [[ -f "$source_dir/source.json" ]]; then
        jq -e --arg commit "$commit" '.commit == $commit' "$source_dir/source.json" >/dev/null
        cp "$source_dir/source.json" "$destination/"
      fi
    else
      jq -e --arg commit "$commit" --arg environment "$BENCH_ENV_VERSION" '
        .schema == 1 and .commit == $commit and .environment_version == $environment
        and .platform == "x86_64-uefi" and .profile == "release"
      ' "$source_dir/source.json" >/dev/null
      jq -e --arg commit "$commit" --slurpfile source "$source_dir/source.json" '
        .source_commit == $commit and .merged == true and .profiles.kernel != null
        and .compiler == $source[0].compiler and .platform == $source[0].platform
        and .profile == $source[0].profile
      ' "$source_dir/profiles/profiles.json" >/dev/null
      (
        cd "$source_dir"
        sha256sum --check checksums.sha256
      )
      mkdir -p "$destination"
      cp -r "$source_dir/." "$destination/"
    fi
    echo "Restored PGO image for $commit from artifact $artifact_id."
    exit 0
  done < "$download/candidates.txt"
done

echo "No saved PGO image is available for $commit."
