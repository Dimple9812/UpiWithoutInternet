# MeshPay — offline UPI-style payments over a device mesh

A prototype of offline payments: a phone with no internet signs and encrypts a
payment, nearby phones relay it hop by hop, and whichever phone reaches the
internet first uploads it to this backend for settlement. It is a **simulation** —
no real bank or NPCI integration — but the protocol is built so a reviewer cannot
steal money, double-spend, or replay a payment.

> **Status:** Phase 1 (backend protocol + tests) and Phase 2 (mesh simulator
> dashboard) are done. Next: Phase 3 Android app, Phase 4 full docs (diagram,
> threat model, one-command compose).

## How it works

```
ONLINE (once)                         OFFLINE                                  ONLINE (any relay)
─────────────                         ───────                                  ──────────────────
phone ── register device key ──▶      sender signs PaymentInstruction          bridge ── POST /api/v1/bridge/ingest
       ◀─ server keys                 with its device key (ECDSA P-256),             (bearer token)
phone ── load offline wallet ──▶      encrypts {instruction, signature}              │
       ◀─ signed WalletCertificate    to the server key (RSA-OAEP + AES-GCM)         ▼
          (money RESERVED on server)       │                                   hash → idempotency claim (Redis)
                                           ├──▶ receiver: OfflineIou,          → DB backstop → decrypt by keyId
                                           │    verified offline               → verify device signature
                                           └──▶ MeshPacket gossiped            → freshness → wallet row lock
                                                phone → phone → bridge         → counter reuse → limits
                                                                               → settle + signed receipt
```

## What the protocol guarantees

| Threat | Defence |
|---|---|
| Relay reads or edits a payment | Sign-then-encrypt. AES-GCM detects any change; the `keyId` is bound into the AAD. |
| Someone spends another person's money | Every payment must carry a valid signature from a device registered to the sender. The server's encryption key being public no longer matters. |
| Same packet uploaded by many bridges | SHA-256 of the ciphertext bytes → atomic Redis claim (`PROCESSING/SETTLED/REJECTED/RETRYABLE`), plus `UNIQUE(packet_hash)` in Postgres. |
| Replay after Redis or server restart | DB unique constraints are the backstop; server keys persist (wrapped by a master key), so in-flight packets still decrypt. |
| Offline double-spend | Money is reserved into an offline wallet before going offline; settlement draws only from that reserve. `UNIQUE(device_id, counter)` for settled payments catches cloned wallets and flags the device. |
| Overspending the reserve | Local wallet checks on the phone, and the server checks per-txn cap and remaining reserve under a row lock. |
| Old packets | Freshness window (`packet-max-age`, default 72h) and wallet expiry. |
| Transient DB failure | Packet goes to `RETRYABLE`, bridge gets `503 + Retry-After`, the next copy settles. No money moves on failure. |
| Fake bridge / flooding | Bearer token per bridge (identity comes from the token) and a per-bridge rate limit. |

## Run it

Requirements: Java 21, Docker (for Postgres and Redis).

```bash
docker compose up -d
SPRING_PROFILES_ACTIVE=demo ./mvnw spring-boot:run
# open http://localhost:8080  (demo users alice/bob/carol/dave @demo, PIN 1234)
```

The `demo` profile adds the simulator page, its endpoints and seeded accounts.

### The simulator

Eleven phones wander around a basement with no signal; the right edge of the map has
4G. Four of them belong to demo users (Alice, Bob, Carol, Dave), six are strangers who
relay for free, and one is Mallory, an attacker.

- **Pay offline** on the left phone. The receiver's phone checks the payment offline
  (server-signed wallet certificate + device signature) and shows it as *Pending*.
- **Run** the mesh. Phones in radio range exchange data pairwise: receipts first, then
  packets by binary **spray-and-wait** (8 copies; with one copy left a phone only hands
  it to someone with 4G). Buffers are capped at 12 packets (oldest stranger packet is
  evicted, never the phone's own), packets expire after 300 ticks, and **battery-aware
  scanning** makes low-battery phones scan one tick in three and turns the radio off
  when almost flat. 4G is also where phones recharge.
- A phone that reaches 4G uploads through the real ingestion pipeline. The signed
  **receipt** spreads back through the mesh: every phone that sees it drops the packet,
  and the receiver's status flips to *Settled* when the receipt reaches it.
- **Try to break it**: tamper with a relayed packet, forge a sender, replay a settled
  payment, clone a wallet, or overspend with a modified app. Each attack builds real
  packets; the table shows what was expected next to what the server decided.

Every payment in the simulation is a genuine signed and encrypted packet, so the
simulator exercises exactly the same code a real bridge would.
Without it, only the production API is exposed. Outside demo you must set
`MESHPAY_MASTER_KEY` (`openssl rand -base64 32`) and bridge tokens
(`MESHPAY_BRIDGE_TOKENS_<ID>=<token>`). Use `SPRING_PROFILES_ACTIVE=prod` for JSON logs.

## API (v1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/keys` | Active encryption key + all signing public keys |
| POST | `/api/v1/devices` | Register a device public key (`vpa, deviceId, publicKey, pin`) |
| POST | `/api/v1/devices/{id}/revoke` | Lost or stolen phone |
| POST | `/api/v1/wallets` | Reserve money into an offline wallet, returns a signed certificate |
| GET | `/api/v1/wallets/{certId}` | Fetch a certificate |
| POST | `/api/v1/bridge/ingest` | Upload a mesh packet (`Authorization: Bearer <bridge token>`) |
| GET | `/api/v1/receipts/{packetHash}` | Signed settlement receipt |
| GET | `/actuator/metrics`, `/actuator/prometheus` | `meshpay.ingest`, `meshpay.delivery.latency`, `meshpay.packet.hops` |

The phone side of the protocol is implemented in plain Java in
`com.demo.upimesh.sim` (`PhoneClient`, `OfflineVerifier`) as the reference for the
Android port.

## Tests

43 tests, most against real PostgreSQL and Redis via Testcontainers:

```bash
./mvnw test
```

No Docker? Point the tests at running instances instead:

```bash
MESHPAY_TEST_DB_URL=jdbc:postgresql://localhost:5432/meshpay_test ./mvnw test
```

They cover three bridges uploading at once, a 20-upload duplicate storm,
tampered ciphertext, a rewritten `keyId`, a forged sender, a foreign wallet,
revoked devices, stale and future-dated packets, re-encrypted duplicates,
sequential and concurrent counter forks, out-of-order delivery, over-limit
spends, per-txn caps, replay after restart, a transient DB lock timeout and
retry, encryption and signing key rotation, and wallet expiry with refund. The mesh
engine has deterministic unit tests (spray-and-wait, wait-phase delivery, receipt
purging, buffer eviction, expiry, battery, retry, malicious relays), and the simulator
test runs every attack end to end through the real pipeline.
