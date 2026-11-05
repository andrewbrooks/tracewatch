#!/bin/sh
# Traced workload: real curl against real servers. usage: curl_workload.sh RESULTS_DIR   (env HAVE_* gate services)
R=$1; mkdir -p "$R"
req() { n=$1; shift; curl -sS -m 60 -o "$R/$n.body" -w '%{json}' "$@" > "$R/$n.meta" 2> "$R/$n.err"; echo $? > "$R/$n.rc"; }
req example https://example.com/
req http1 --http1.1 https://example.com/
req plainhttp http://example.com/
if [ "$HAVE_HTTPBIN" = 1 ]; then
  req gzip --compressed https://httpbin.org/gzip
  req deflate --compressed https://httpbin.org/deflate
  req brotli --compressed https://httpbin.org/brotli
  req redirect -L https://httpbin.org/redirect/2
  req post -X POST https://httpbin.org/post -H "Authorization: Bearer CANARYrealbearer0123456789" \
      -d "user=bob&password=CANARYrealpw0123456789&note=VISMARKreal"
  req drip "https://httpbin.org/drip?duration=3&numbytes=6&code=200&delay=0"
  args=""; i=0; while [ $i -lt 20 ]; do i=$((i+1)); args="$args -o /dev/null https://httpbin.org/anything/par$i"; done
  req parallel --parallel --parallel-max 10 $args
fi
[ "$HAVE_CFBR" = 1 ] && req cfbr -H 'Accept-Encoding: br' https://developers.cloudflare.com/
[ "$HAVE_OVH" = 1 ] && req big https://proof.ovh.net/files/10Mb.dat
[ "$HAVE_BADSSL" = 1 ] && req expired https://expired.badssl.com/ && req selfsigned https://self-signed.badssl.com/
req nohost https://no-such-host.invalid/
