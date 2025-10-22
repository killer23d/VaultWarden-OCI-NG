# Cloudflare Integration

**Edge security with WAF/DDoS and trusted proxy configuration**

## Why Cloudflare

- Global anycast edge, free DDoS protection
- WAF rules and bot protection
- Hide origin IP and filter traffic

## Setup Steps

1. Proxy your domain through Cloudflare (orange-cloud)
2. Create API Token with Zone:Read + DNS:Edit
3. Populate secrets via `./tools/edit-secrets.sh`
4. Update firewall rules and trusted IPs

```bash
./tools/update-cloudflare-ips.sh
```

## Caddy Configuration

- Trust Cloudflare IPs
- Preserve real client IP via `CF-Connecting-IP`

```caddyfile
{
  email {$ADMIN_EMAIL}
  import /etc/caddy/cloudflare-ips.caddy
}

https://{$DOMAIN} {
  trusted_proxies @cloudflare

  @admin path /admin*
  rate_limit @admin 5r/m
  basicauth @admin {
    admin {$ADMIN_BASIC_AUTH_HASH}
  }

  handle @admin {
    reverse_proxy vaultwarden:8080 {
      header_up X-Real-IP {http.request.header.CF-Connecting-IP}
    }
  }

  handle {
    reverse_proxy vaultwarden:8080 {
      header_up X-Real-IP {http.request.header.CF-Connecting-IP}
    }
  }
}
```

## Firewall with Cloudflare IPs

```bash
# Pull latest Cloudflare IP list
./tools/update-cloudflare-ips.sh

# Enable UFW defaults
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow only Cloudflare to 80/443 (script adds these)
sudo ufw status numbered
```

## Tips

- Enable Bot Fight Mode (free) and WAF managed rules
- Use Cloudflare Access (Zero Trust) for admin during incidents
- Monitor threat activity in Cloudflare dashboard
