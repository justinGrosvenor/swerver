# Feature Request: POST settlement reports to platform API

## Summary

After `facilitatorSettle` succeeds, swerver should POST a settlement record to the platform API so revenue is tracked and payouts can be triggered.

## Context

The platform API already serves `settlement_url` and `gateway_id` in the bulk config response (under each gateway's `x402` block). The settlement endpoint is live and expects a simple JSON body. Swerver currently calls the facilitator and logs on failure, but never reports the result back to the platform.

## Config changes

The bulk config (`GET /config`) now includes two new fields per gateway in the `x402` object:

```json
{
  "x402": {
    "enabled": true,
    "facilitator_url": "https://facilitator.x402.org",
    "settlement_url": "https://api.swerver.net/v1/settlements",
    "gateway_id": "uuid-here",
    "price": "1000000",
    "asset": "USDC",
    "network": "base-sepolia",
    "pay_to": "0x...",
    "scheme": "exact",
    "max_timeout_seconds": 60
  }
}
```

New fields to parse:
- `settlement_url` (string) - full URL to POST to
- `gateway_id` (string, UUID) - the gateway that earned this payment

## What to POST

After `facilitatorSettle` returns success, fire a non-blocking POST to `settlement_url`:

```
POST {settlement_url}
Authorization: Bearer {service_key}
Content-Type: application/json

{
  "gatewayId": "{gateway_id}",
  "txHash": "0x{64 hex chars}",
  "network": "eip155:{chain_id}",
  "asset": "0x{40 hex chars}",
  "amount": "{atomic units as string}"
}
```

Fields come from:
- `gatewayId` - from the route's x402 config (`gateway_id`)
- `txHash` - from the facilitator settle response (the on-chain tx hash)
- `network` - from the route's x402 config (`network`, already in `eip155:` format)
- `asset` - from the route's x402 config (`asset` - but note: config currently says `"USDC"`, API expects a contract address like `0x...`. Need to either pass contract address from config or map the symbol in swerver)
- `amount` - from the x402 payment header (the `price` field, atomic units)

## Auth

The POST requires a service auth header: `Authorization: Bearer {service_key}`. This is the same key swerver uses for config fetch. Add a config field `service_key` (or reuse existing if already present for config auth).

## Implementation notes

- **Non-blocking**: Don't delay the response to the client. Fire the POST after the proxy response is sent (or in a background thread/async context). If it fails, log a warning but don't retry inline.
- **Idempotent**: The API deduplicates on `txHash` (unique index), so retries are safe.
- **Failure tolerance**: If the POST fails (network error, 5xx), log it. A future reconciliation job can fill gaps by querying on-chain events. Don't let settlement reporting failures affect request latency.

## Location in code

`src/server/dispatch.zig` lines 989-998 (and similar block in `src/router/router.zig` lines 861-869):

```zig
if (proxy_result.resp.status >= 200 and proxy_result.resp.status < 300) {
    if (x402_result == .allow and x402_result.allow.needs_settlement) {
        if (server.app_router.facilitator) |fac| {
            const settle = x402_mod.facilitatorSettle(fac, ...);
            if (!settle.success) {
                std.log.warn("x402 proxy settlement failed: {s}", .{settle.error_reason});
            }
            // NEW: if settle.success, POST to settlement_url
        }
    }
}
```

The settle result likely contains the tx hash. The amount and asset/network are available from the x402 policy struct on the route.

## Asset field mismatch

The API expects `asset` as a contract address (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` for USDC on Base). The current config outputs the symbol `"USDC"`. Either:

1. Change the API config output to emit the contract address instead of the symbol, OR
2. Add a lookup table in swerver that maps symbol+network to contract address

Option 1 is simpler. The API knows the contract address (or can default it per network).
