# Swift Tesla BLE

Pure-Swift package for talking to Tesla vehicles directly over Bluetooth LE. One `TeslaVehicleClient` actor handles scanning, connection, per-domain session handshake, signed command dispatch, and structured state/query responses — no Go toolchain, no `gomobile`, no xcframework.

## Capabilities

- **BLE transport.** CoreBluetooth-based scanning, connect, MTU-aware framer.
- **End-to-end crypto.** P-256 ECDH session handshake, AES-GCM-128 message encryption, HMAC-SHA-256 authenticated metadata, sliding replay window. Byte-identical with Tesla's Go reference implementation (fixture-verified).
- **Two signed domains.** VCSEC (body controller: locks, closures, whitelist) and Infotainment (drivetrain, climate, media, charging).
- **Complete command surface.** Every command exposed by the upstream `pkg/vehicle` Go library is implemented — 75 action commands plus 4 structured-response queries. Grouped by domain in a nested `Command` enum.
- **State fetching.** Full vehicle snapshot or drive-only fast path via `fetch(_:)` / `fetchDrive()`, returning Swift-native model types that never leak protobuf through public API.
- **Key management.** Pluggable `TeslaKeyStore` protocol with a default `KeychainTeslaKeyStore` implementation (P-256 keys stored per-VIN, device-only, no iCloud sync).
- **Pairing bootstrap.** First-time `addKey` flows through the unsigned VCSEC whitelist path; the vehicle then waits for an existing owner key to tap the center console.

## Requirements

- iOS 17+ deployment target (primary platform)
- macOS 13+ (test host only — no CoreBluetooth validation has been done on macOS)
- Swift 6.2 toolchain
- Xcode 16 or newer

CoreBluetooth requires an `NSBluetoothAlwaysUsageDescription` entry in your app's `Info.plist`.

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/<org>/swift-tesla-ble.git", branch: "main"),
]
```

Then add `"TeslaBLE"` to the relevant target.

### Local path

```swift
.package(path: "../swift-tesla-ble"),
```

## Usage

### First-time pairing

```swift
import TeslaBLE

let vin = "5YJ..."
let keyStore = KeychainTeslaKeyStore(service: "com.example.teslaBLE")

// 1. Load or generate a P-256 keypair for this VIN and persist it.
let privateKey: P256.KeyAgreement.PrivateKey
if let existing = try keyStore.loadPrivateKey(forVIN: vin) {
    privateKey = existing
} else {
    privateKey = KeyPairFactory.generateKeyPair()
    try keyStore.savePrivateKey(privateKey, forVIN: vin)
}
let publicKey = KeyPairFactory.publicKeyBytes(of: privateKey)

// 2. Connect in pairing mode — scans and connects without negotiating sessions.
let client = TeslaVehicleClient(vin: vin, keyStore: keyStore)
try await client.connect(mode: .pairing)

// 3. Send the unsigned addKey request. This returns once the request is on
//    BLE; authorization still completes asynchronously after the user taps an
//    existing owner key (NFC card) on the center console.
try await client.send(.security(.addKey(
    publicKey: publicKey,
    role: .owner,
    formFactor: .iosDevice
)))

// 4. Disconnect, then reconnect in normal mode to verify the key is active.
await client.disconnect()
```

### Daily use

```swift
let client = TeslaVehicleClient(vin: "5YJ...", keyStore: keyStore)

// Observe connection state transitions.
Task {
    for await state in client.stateStream {
        print("state →", state)
    }
}

try await client.connect()                         // scans, connects, handshakes VCSEC + Infotainment
try await client.send(.security(.unlock))           // VCSEC domain
try await client.send(.climate(.on))                // Infotainment domain
try await client.send(.charge(.setLimit(percent: 80)))

let snapshot = try await client.fetch(.all)
print("Battery:", snapshot.charge?.batteryLevel ?? 0, "%")
print("Inside:", snapshot.climate?.insideTempCelsius ?? 0, "°C")

let drive = try await client.fetchDrive()           // 2-second fast path
print("Speed:", drive.speedMph ?? 0, "mph")

await client.disconnect()
```

### Structured queries

Queries return typed payloads instead of a `Void` acknowledgement. Use `query(_:)` for VCSEC whitelist inspection, body-controller state (answerable even when Infotainment is asleep), and nearby Supercharger lookup.

```swift
switch try await client.query(.keySummary) {
case .keySummary(let info):
    print("Whitelisted slots:", info.keyCount)
default: break
}

switch try await client.query(.bodyControllerState) {
case .bodyControllerState(let status):
    print("Locked:", status.vehicleLockState)
default: break
}
```

## Command surface

Commands are grouped by functional domain. Each group is its own nested enum; `CommandEncoder` routes every case to the correct BLE domain under the hood.

| Group              | Domain               | Highlights                                                                                                                                                                                                      |
| ------------------ | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.security(_)`     | VCSEC + Infotainment | Lock/unlock, wake, remote drive, trunk/frunk, tonneau, actuate trunk, add/remove keys, sentry mode, valet mode, erase guest data, speed limit, PIN-to-drive, guest mode                                         |
| `.charge(_)`       | Infotainment         | Start/stop, max/standard range, limit %, amps, port open/close, low-power mode, charge and precondition schedules (add/remove/batch), schedule departure, scheduled charging                                    |
| `.climate(_)`      | Infotainment         | On/off, temperature, steering wheel heater, keeper mode (off/on/dog/camp), preconditioning max, bioweapon defense, cabin overheat protection (+ temp level), seat heater/cooler (per seat), auto seat & climate |
| `.actions(_)`      | Infotainment         | Honk, flash lights, windows (close/vent), Homelink, sunroof                                                                                                                                                     |
| `.media(_)`        | Infotainment         | Play/pause, next/prev track, volume (absolute + up/down), next/previous favorite                                                                                                                                |
| `.infotainment(_)` | Infotainment         | Schedule / cancel software update, set vehicle name                                                                                                                                                             |

Full type details live in [`Sources/TeslaBLE/Commands/Command.swift`](Sources/TeslaBLE/Commands/Command.swift). Inspect the file in Xcode for DocC-rendered summaries of every case.

## Architecture

```
Sources/TeslaBLE/
  Client/     — TeslaVehicleClient public actor, ConnectionState
  Commands/   — Command enum, VehicleQuery, StateQuery, encoders, ResponseDecoder
  Crypto/     — P256ECDH, SessionKey, CounterWindow, MetadataHash, MessageAuthenticator
  Session/    — VehicleSession actor, SessionNegotiator, OutboundSigner, InboundVerifier
  Dispatcher/ — Dispatcher actor, RequestTable, MessageTransport protocol
  Transport/  — BLETransport (CoreBluetooth), MessageFramer
  Keys/       — TeslaKeyStore protocol, KeychainTeslaKeyStore, KeyPairFactory
  Model/      — TeslaVehicleSnapshot, per-section state types, VehicleSnapshotMapper
  Support/    — TeslaBLEError, TeslaBLELogger, VINHelper
  Generated/  — protoc-gen-swift outputs from Vendor/tesla-vehicle-command
```

Key invariants:

- `TeslaVehicleClient` is an actor. Each instance represents one session with one vehicle (keyed by VIN).
- Session state is per-domain; `connect(mode: .normal)` negotiates both VCSEC and Infotainment in sequence.
- `VehicleSnapshotMapper` is the only file in `Sources/` that sees `CarServer_*` protobuf types; everything else works with Swift-native model types.
- Crypto lives entirely in CryptoKit. The SHA-1 truncation in session-key derivation is a Tesla wire-compat requirement, not a recommended KDF.

## Testing

```bash
swift test
```

178 tests covering the crypto primitives (with fixture vectors dumped from Tesla's Go reference), session sign/verify round-trips, dispatcher scenarios, every command encoder and query decoder, and the snapshot mapper. All deterministic — no real BLE or hardware required.

```bash
make format   # swiftformat + prettier (Vendor/ and Generated/ excluded)
make build
make test
```

## Regenerating `Sources/TeslaBLE/Generated/*.pb.swift`

The nine `*.pb.swift` files are produced from `.proto` sources in the `Vendor/tesla-vehicle-command` submodule.

```bash
brew install protobuf swift-protobuf
git submodule update --init
./scripts/generate-protos.sh
```

After regenerating, run `swift build && swift test`. Any compile error is most likely an encoder chasing an upstream field rename.

## Caveats

- **Hardware validation is the user's responsibility.** Every layer is fixture-tested against the Go reference, and all 141 unit tests pass, but BLE + vehicle + real cryptographic rotation against a parked Model 3/Y/S/X is the only thing that proves end-to-end correctness. Plug this package into an example iOS app, pair against your own vehicle, and file issues for anything that misbehaves.
- **iOS-first.** macOS 13 is supported only as a test host for the pure-logic suite. CoreBluetooth semantics on macOS have not been validated against real Tesla hardware.
- **No Fleet API.** This package is deliberately BLE-only. `KeyRole` exposes `.owner` and `.driver`; fleet-manager / charging-manager / vehicle-monitor roles are intentionally not available.
- **Key loss = pairing loss.** `KeychainTeslaKeyStore` uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Keys do not sync to iCloud and are not included in device backups. Restoring to a new device requires re-pairing.
- **Unsigned `addKey` is the only command that can be sent before a session exists.** All other commands require `connect(mode: .normal)` to complete the handshake first.
- **Concurrent clients.** One `TeslaVehicleClient` per VIN. Discard and recreate to switch vehicles; do not share instances across vehicles.

## License

MIT. See `LICENSE`.
