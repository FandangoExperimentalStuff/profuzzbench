#!/bin/bash
# Builds the images of every subject: the base image first, then its StateAFL and Fandango images side by side,
# BUILD_JOBS subjects at a time (default 4). MAKE_OPT goes to make in the builds (default: all CPUs but one, split
# over the BUILD_JOBS subjects),
# NO_CACHE="--no-cache" rebuilds every layer, SUBJECTS="SMTP/Exim:exim ..." builds only those. Each build logs to build-logs/<image>.log.

export PFBENCH=${PFBENCH:-$(cd "$(dirname "$0")/../.." && pwd)}
BUILD_JOBS=${BUILD_JOBS:-4}
MAKE_JOBS=$(( ($(nproc) - 1) / BUILD_JOBS ))
export MAKE_OPT=${MAKE_OPT:--j$(( MAKE_JOBS > 0 ? MAKE_JOBS : 1 ))}
export NO_CACHE=${NO_CACHE:-}
export BUILD_LOGS=$PFBENCH/build-logs

SUBJECTS=${SUBJECTS:-"FTP/LightFTP:lightftp FTP/BFTPD:bftpd FTP/ProFTPD:proftpd FTP/PureFTPD:pure-ftpd SMTP/Exim:exim
DNS/Dnsmasq:dnsmasq RTSP/Live555:live555 SIP/Kamailio:kamailio SSH/OpenSSH:openssh TLS/OpenSSL:openssl
DTLS/TinyDTLS:tinydtls DICOM/Dcmtk:dcmtk DAAP/forked-daapd:forked-daapd"}

build_image() {
  local image=$1
  shift
  if docker build . -t "$image" --build-arg MAKE_OPT $NO_CACHE "$@" > "$BUILD_LOGS/$image.log" 2>&1; then
    echo "OK    $image"
  else
    echo "FAIL  $image (see $BUILD_LOGS/$image.log)"
    return 1
  fi
}

build_subject() {
  local directory=${1%%:*}
  local name=${1#*:}
  cd "$PFBENCH/subjects/$directory" || return 1
  build_image "$name" --build-context fandango-workspace="$PFBENCH/.." || return 1
  build_image "$name-stateafl" -f Dockerfile-stateafl &
  local stateafl=$!
  build_image "$name-fandango" -f Dockerfile-fandango --build-context fandango-workspace="$PFBENCH/.." &
  local fandango=$!
  wait "$stateafl"
  local stateafl_status=$?
  wait "$fandango" || return 1
  return $stateafl_status
}

export -f build_image build_subject
mkdir -p "$BUILD_LOGS"
printf '%s\n' $SUBJECTS | xargs -P "$BUILD_JOBS" -I{} bash -c 'build_subject "$1"' _ {}
