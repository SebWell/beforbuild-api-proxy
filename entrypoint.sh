#!/bin/sh
# Force Cloudflare DNS (bypass Docker DNS resolver issues with IPv6 AAAA timeouts)
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
exec node server.js
