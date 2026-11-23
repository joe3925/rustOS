set -euo pipefail

# Resolve tools from the current checkout's compiler, including older baselines.
rustup component add llvm-tools-preview
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
llvm_bin="$sysroot/lib/rustlib/$host/bin"
for tool in llvm-profdata llvm-ar; do
  if [[ ! -x "$llvm_bin/$tool" ]]; then
    echo "::error::Missing $tool for the active Rust toolchain: $llvm_bin/$tool"
    exit 1
  fi
  "$llvm_bin/$tool" --version
done
