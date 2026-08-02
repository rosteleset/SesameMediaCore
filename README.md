# SesameMediaCore

Shared Rust media primitives used by SesameAgent and SesameDVR.

The workspace contains:

- `sesame_cmaf_cbcs`: CMAF inspection and CBCS packaging;
- `sesame_encrypted_cmaf_wire`: encrypted CMAF transport framing and ACK/NACK messages;
- `sesame_media_timing`: timestamp normalization, duration estimation and live pacing;
- `sesame_sframe_wire`: SFrame packet framing shared by publisher and receiver.

## Consumers

SesameAgent and SesameDVR include this repository as a Git submodule and pin an
exact commit. They use local Cargo path dependencies, so builds do not need
Gitap credentials inside Cargo or Docker containers.

Clone a consumer with its pinned MediaCore revision:

```bash
git clone --recurse-submodules <consumer-url>
```

For an existing checkout:

```bash
git submodule sync --recursive
git submodule update --init --recursive
```

## Compatibility

Wire-format changes must remain backward compatible or introduce an explicit
protocol version. Before updating a consumer gitlink, run the MediaCore tests
and the native tests in both SesameAgent and SesameDVR.

```bash
cargo test --workspace
```

## License

SesameMediaCore is distributed under GPL-3.0-only.
