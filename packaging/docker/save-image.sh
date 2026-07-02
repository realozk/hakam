#!/usr/bin/env bash
# Build the Hakam core image for one or more arches and save portable, offline
# tarballs a reviewer can `docker load` — no source build on their side
# (~15 min saved), no registry account, works without booth wifi.
#
#   ./packaging/docker/save-image.sh                 # both amd64 + arm64 (default)
#   ARCH=amd64 ./packaging/docker/save-image.sh      # just one
#
# Cross-arch builds emulate the *other* arch via QEMU (binfmt) and are SLOW — the
# Rust + LLVM + bpf-linker compile can take an hour+ under emulation. The arch
# matching your build host is native and fast; that's the one to build first.
# Requires buildx/binfmt for the non-native arch (`docker run --privileged --rm
# tonistiigi/binfmt --install all` sets it up). Ship each tarball next to
# packaging/docker/{REVIEW.md,run.sh}.
set -euo pipefail

cd "$(dirname "$0")/../.."

TAG="hakam:latest"
ARCHES="${ARCH:-amd64 arm64}"

for arch in $ARCHES; do
    out="hakam-${arch}.tar.gz"
    echo "==> building ${TAG} for linux/${arch} (native ~15 min; emulated arch much longer)…"
    docker build --platform "linux/${arch}" -f packaging/docker/Dockerfile -t "$TAG" .
    echo "==> saving ${out}…"
    docker save "$TAG" | gzip > "$out"
    echo "    wrote ${out} ($(du -h "$out" | cut -f1))"
done

echo
echo "  done. each tarball carries the tag ${TAG}, so run.sh works unchanged."
echo "  reviewer loads their arch with:  gunzip -c hakam-<arch>.tar.gz | docker load"
echo "  then follows packaging/docker/REVIEW.md"
