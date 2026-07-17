# SQLite budget-VM benchmark

This directory reproduces the July 2026 AuthOS SQLite experiment on a locally
virtualized server shaped like a sub-USD-10 VPS: one vCPU, 1 GiB assigned RAM,
and a 25 GiB disk. The preserved evidence was generated from AuthOS commit
`79e5a9440846f94dd31221c17b9b64930ec489bc` and binary SHA-256
`e3386a969271e4060f2ffdb2199e27b3276021b1cfa9be87f0787355c9ef884f`.

This is an experiment, not a supported capacity limit. The guest used an Intel
i7-1265U thread and local NVMe storage. Matching a provider's advertised vCPU,
RAM, and disk quantities does not reproduce its shared-CPU scheduler, storage,
network, regional latency, or noisy neighbours.

## Workload

Each k6 virtual user performs one seeded random business operation and waits
one second:

- 70% authenticated `GET /api/subscription`;
- 20% OAuth device authorization, comprising `POST /auth/device/code` and one
  `POST /auth/token`; and
- 10% authenticated `GET /api/user`.

The expected token-poll result is HTTP 400 with `DEVICE_CODE_PENDING`. Any
other token-poll result, unexpected status, or failed operation check counts as
an operation failure. Because the device operation makes two HTTP requests,
operations per second and HTTP requests per second are deliberately separate.

## Files

- `workload.js` is the exact k6 workload.
- `seed.sql` contains only synthetic benchmark identities and configuration.
- `prepare-seed.sh` migrates a fresh SQLite database, applies the fixture, and
  validates the benchmark login without retaining its access token.
- `run-server.sh` restores the same seed for each case and starts AuthOS with
  the measured database and file-descriptor settings.
- `run-case.sh` records the selected load, AuthOS commit, k6 version, console,
  exit status, and JSON summary in a new result directory.
- `vm/` contains the cloud-init network/user templates and the exact QEMU
  1-vCPU, 1-GiB, 25-GiB launcher. It contains no private key.
- `evidence/2026-07-17/` contains the selected results and compressed raw
  output from the original run.

Generated databases, keys, VM disks, logs, and local result directories are
ignored by Git.

## Required tools

- the Rust toolchain pinned by this checkout;
- `openssl`, `sqlite3`, `curl`, and GNU `base64`;
- k6 v2.1.0 for an exact client-version match; and
- for the VM run, QEMU 10.2.1 with KVM, `cloud-localds`, Python 3, and host
  permission to create a TAP interface.

## Build and prepare the fixture

To reproduce the published evidence exactly while keeping this newer harness
available, build the pinned AuthOS revision in a temporary worktree. For a new
measurement, build the commit being qualified and record its digest instead.

```bash
git worktree add /tmp/authos-benchmark-source \
  79e5a9440846f94dd31221c17b9b64930ec489bc
cargo build --release --locked \
  --manifest-path /tmp/authos-benchmark-source/api/Cargo.toml \
  --bin sso_sqlite
export AUTHOS_BINARY=/tmp/authos-benchmark-source/api/target/release/sso_sqlite
AUTHOS_BINARY="$AUTHOS_BINARY" \
  api/benchmarks/sqlite-budget-vm/prepare-seed.sh
```

The script writes its disposable database and generated RSA keys under `.work/`
and prints the seed database SHA-256. Do not reuse the fixed benchmark
encryption and device-trust values outside this disposable experiment.

For a local smoke test, start AuthOS in one terminal:

```bash
api/benchmarks/sqlite-budget-vm/run-server.sh
```

Then run one virtual user from another terminal:

```bash
api/benchmarks/sqlite-budget-vm/run-case.sh 1 15s smoke
```

## Create the measured VM shape

The preserved run used the Ubuntu 26.04 release image at
`https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img`
with SHA-256
`0826c5005ebc70edcfc4519e5d65eca766782f16426231c4c3e92b811ba8df0b`.

Create a temporary key and host TAP interface:

```bash
ssh-keygen -t ed25519 -N '' -f /tmp/authos-benchmark-key
sudo ip tuntap add dev tap-authos mode tap user "$USER"
sudo ip addr add 192.168.76.1/24 dev tap-authos
sudo ip link set tap-authos up
```

Launch the guest:

```bash
AUTHOS_VM_IMAGE=/path/to/ubuntu-26.04-server-cloudimg-amd64.img \
AUTHOS_VM_PUBLIC_KEY=/tmp/authos-benchmark-key.pub \
api/benchmarks/sqlite-budget-vm/vm/launch.sh
```

Copy the pinned binary, prepared fixture, generated keys, and server runner to
the guest:

```bash
ssh -i /tmp/authos-benchmark-key benchmark@192.168.76.2 \
  'mkdir -p /home/benchmark/authos/work'
scp -i /tmp/authos-benchmark-key \
  "$AUTHOS_BINARY" \
  api/benchmarks/sqlite-budget-vm/run-server.sh \
  api/benchmarks/sqlite-budget-vm/.work/seed.db \
  api/benchmarks/sqlite-budget-vm/.work/private.pem \
  api/benchmarks/sqlite-budget-vm/.work/public.pem \
  benchmark@192.168.76.2:/home/benchmark/authos/
ssh -i /tmp/authos-benchmark-key benchmark@192.168.76.2 \
  'mv /home/benchmark/authos/{seed.db,private.pem,public.pem} /home/benchmark/authos/work/'
```

Start the guest server with an explicit 65,535 file-descriptor limit:

```bash
ssh -i /tmp/authos-benchmark-key benchmark@192.168.76.2 \
  'chmod 700 /home/benchmark/authos/sso_sqlite /home/benchmark/authos/run-server.sh && \
   AUTHOS_BINARY=/home/benchmark/authos/sso_sqlite \
   AUTHOS_BENCH_WORK_DIR=/home/benchmark/authos/work \
   AUTHOS_BENCH_HOST=0.0.0.0 \
   AUTHOS_BENCH_PUBLIC_URL=http://192.168.76.2:3301 \
   /home/benchmark/authos/run-server.sh'
```

Keep that SSH session open. The server runner restores the pristine seed on
every start.

## Run the load matrix

For high-load cases, the original run assigned 91 source addresses to the host
TAP so AuthOS's per-IP device governor observed independent clients rather than
one synthetic NAT address:

```bash
for octet in $(seq 10 100); do
  sudo ip addr add "192.168.76.${octet}/32" dev tap-authos
done
export K6_LOCAL_IPS=192.168.76.10-192.168.76.100
export AUTHOS_BENCH_BASE_URL=http://192.168.76.2:3301
```

Restart `run-server.sh` before each case, then run the matrix from the host:

```bash
api/benchmarks/sqlite-budget-vm/run-case.sh 100 30s ramp-0100
api/benchmarks/sqlite-budget-vm/run-case.sh 500 45s ramp-0500
api/benchmarks/sqlite-budget-vm/run-case.sh 1000 60s ramp-1000
api/benchmarks/sqlite-budget-vm/run-case.sh 2000 60s ramp-2000
api/benchmarks/sqlite-budget-vm/run-case.sh 3000 60s ramp-3000-1
api/benchmarks/sqlite-budget-vm/run-case.sh 3000 60s ramp-3000-2
api/benchmarks/sqlite-budget-vm/run-case.sh 3000 60s ramp-3000-3
api/benchmarks/sqlite-budget-vm/run-case.sh 4000 60s ramp-4000-1
api/benchmarks/sqlite-budget-vm/run-case.sh 4000 60s ramp-4000-2
api/benchmarks/sqlite-budget-vm/run-case.sh 4000 60s ramp-4000-3
api/benchmarks/sqlite-budget-vm/run-case.sh 5000 60s ramp-5000
api/benchmarks/sqlite-budget-vm/run-case.sh 2000 300s soak-2000-5m
api/benchmarks/sqlite-budget-vm/run-case.sh 3000 300s soak-3000-5m
```

Run `vmstat -w 1` and process RSS sampling inside the guest, and sample the QEMU
process from the host, if comparing resource telemetry with the preserved raw
archive. Keep the load generator off the guest and verify that it does not
saturate.

## Preserved result

The five-minute 2,000-VU soak completed 592,497 operations at 1,968
operations/s and 2,361 HTTP requests/s, with 154 ms aggregate HTTP p99, zero
observed failures, about 68% guest CPU, and 196 MiB peak AuthOS RSS. At 3,000
VUs for five minutes, CPU averaged 95% and p99 rose to 1.06 seconds. The
4,000-VU repeats and 5,000-VU case established the throughput knee.

The first 1,000-VU diagnostic retained a 1,024 file-descriptor limit and failed
7.09% of operations with `Too many open files`; the 65,535-limit repeat had no
failures. A separate single-source-IP 4,000-VU diagnostic produced only
device-route HTTP 429 responses. Both diagnostics remain in the evidence.

These observations apply only to the pinned build, fixture, host, guest shape,
and workload. They do not establish production readiness, month-long
reliability, or a supported MAU limit.

## Teardown

Stop QEMU using the PID written under `.work/vm/`, then remove the TAP and
temporary key:

```bash
kill "$(cat api/benchmarks/sqlite-budget-vm/.work/vm/qemu.pid)"
sudo ip link del tap-authos
rm -f /tmp/authos-benchmark-key /tmp/authos-benchmark-key.pub
git worktree remove /tmp/authos-benchmark-source
```
