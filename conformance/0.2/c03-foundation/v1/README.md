# RFC 0021 C03 Foundation Offline Slice 1

Profile: `rfc0021_c03_foundation_offline_slice_1`

This directory contains private, offline characterization inputs for the bounded
public Rust surfaces listed in the accepted [RFC 0021 contract](../../../../docs/rfc/0021-c03-foundation-offline-characterization-contract.md).
The Rust integration test embeds every input at compile time and performs no
dynamic file, network, process, environment, daemon, Store, runtime, Gateway,
adapter, SDK, migration, or owner access.

Run the focused characterization:

```sh
cargo test -p splendor-types --test c03_foundation_offline_slice_1
```

Run the owning package tests:

```sh
cargo test -p splendor-types
```

The fixture formats are private test inputs. They are not public schemas,
registered schema IDs, generated surfaces, compatibility decisions, live
dispositions, authorization results, retained reports, or release evidence.
Successful comparisons are described only as `matched`. `FND-006`, issue 225,
and C03 remain incomplete. G00 and G72 remain `specified_not_implemented` /
`not_exercised` as stated by RFC 0021.
