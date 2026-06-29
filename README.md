# fsubid

[![Language: C](https://img.shields.io/badge/language-C-00599C)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-333333)](https://kernel.org)
[![Build: make](https://img.shields.io/badge/build-make-2f7d32)](#build)
[![Concurrency: locked](https://img.shields.io/badge/concurrency-locked-1f6feb)](#concurrency-model)
[![State model: explicit](https://img.shields.io/badge/state-reserved%20%7C%20committed%20%7C%20released%20%7C%20expired-6f42c1)](#reservation-state-model)

Subordinate UID/GID allocator for Linux automation with reservation and commit workflows.

fsubid is designed for orchestrators, provisioning pipelines, and control planes that need to allocate subuid/subgid safely under concurrency.

## Why This Exists

This project is not trying to replace account management tools such as `usermod`.

It targets a different problem: allocation as a service for external automation, with pre-commit reservation.

Practical value it provides:

1. Dry allocation without mutating system files.
2. Short-lived reservation to prevent duplicate picks before commit.
3. Script-friendly output for orchestrators and control planes.
4. Decoupled workflow: allocate now, commit later.

## What Is Included

This implementation includes the full solution scope:

1. Commit helper mode.
2. Idempotency and introspection commands.
3. Strong concurrency contract.
4. Reservation state model and explicit error codes.

## Features

1. `allocate`: picks the next free range and writes a reservation.
2. `commit`: validates and writes to `/etc/subuid` and `/etc/subgid` under lock.
3. `release`: explicitly releases a reservation.
4. `list-reservations`: lists active reservations with metadata.
5. `validate-range`: verifies whether a candidate range is currently valid.
6. `who-owns-range`: shows owners overlapping a given id.
7. `status`: reports reservation/range state.
8. `version`: prints the program version.
9. Automatic stale reservation garbage collection by TTL.

## Build

```sh
make
sudo make install
```

Build output binary path: `bin/fsubid`.

## Install on Ubuntu (PPA)

```sh
sudo add-apt-repository -y ppa:amen8/fsubid
sudo apt update
sudo apt install fsubid
```

Supported Ubuntu versions:

1. `24.04 LTS`
2. `26.04 LTS`

Other Ubuntu versions are currently untested.

## Quick Start

Allocate a range for a user:

```sh
sudo fsubid allocate myuser
# output: START:UID_SIZE:GID_SIZE
```

Creating a range always requires the explicit `allocate` command. A bare
username (for example `fsubid myuser`) does **not** allocate anything; it
reports an unknown command. This prevents accidental allocations when probing
for a subcommand that does not exist.

Commit the allocated start:

```sh
sudo fsubid commit --start START myuser
```

Release a reservation without commit:

```sh
sudo fsubid release --start START
```

Inspect active reservations:

```sh
sudo fsubid list-reservations
```

Validate a proposed range:

```sh
sudo fsubid validate-range --start START --uid-range 65536 --gid-range 65536
```

Find owners overlapping a specific id:

```sh
sudo fsubid who-owns-range --start 100000
```

Check state:

```sh
sudo fsubid status --start START
```

Print the version:

```sh
fsubid version
```

## CLI

```text
fsubid allocate [options] [username]
fsubid commit [options] [username]
fsubid release [options]
fsubid list-reservations
fsubid validate-range --start <N> [--uid-range <N>] [--gid-range <N>]
fsubid who-owns-range --start <N>
fsubid status --start <N>
fsubid version
```

Common options:

1. `-r, --range <N|UID:GID>`
2. `--uid-range <N>`
3. `--gid-range <N>`
4. `--start <N>`
5. `--print-reservation-path`
6. `-v, -V, --version`

## Reservation State Model

fsubid records range lifecycle state under `/run/fsubid/state`.

States:

1. `reserved`: allocation created and reservation file exists.
2. `committed`: reservation successfully written to `/etc/subuid` and `/etc/subgid`.
3. `released`: reservation explicitly released.
4. `expired`: reservation removed by TTL garbage collection.

## Concurrency Model

fsubid serializes critical sections with a global lock at `/run/fsubid/fsubid.lock`.

While the lock is held, it performs allocation and commit validation/writes to prevent duplicate assignment windows.

Reservations are stored in `/run/fsubid/reservations` and are considered live until committed, released, or expired.

## Configuration

`/etc/fsubid.conf` is optional.

Supported keys:

1. `UID_RANGE`
2. `GID_RANGE`

Example:

```ini
UID_RANGE=70000
GID_RANGE=70000
```

Default values if config is missing:

1. `UID_RANGE=70000`
2. `GID_RANGE=70000`
3. reservation TTL: 300 seconds

## License

MIT

## Notes

1. This tool is focused on local file-based subordinate id management.
2. It does not implement remote subid backends.
3. `/run` is tmpfs; reservation/state files are intentionally ephemeral.
