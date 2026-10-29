# Tunnelling proxy only: tinyproxy 1.11.2 from Alpine 3.22 (digest resolved 2026-10-29). No shell access is needed at runtime.
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
RUN apk add --no-cache tinyproxy=1.11.2-r0
USER tinyproxy
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
