# Capacity qualification and resource-sizing method

AuthOS does not publish a supported capacity limit or universal resource size.
The repository includes a bounded qualification harness and one dated
[SQLite budget-VM experiment](../../api/benchmarks/sqlite-budget-vm/README.md).
That experiment is evidence for its pinned build, fixture, topology, and mixed
workload; it is not a service-level claim. Operators must measure the exact
release, topology, database, dataset, and journeys they intend to run before
making a sizing or service-level claim.

## Repository harness

`scripts/authos-capacity.py` sends bounded HTTP workloads described by
`deploy/qualification/capacity-scenarios.json`. The committed scenarios cover
password authentication, token refresh, organization membership reads, SAML
metadata, and SCIM user listing. They are starting points, not a representative
traffic mix or an assertion that each endpoint should receive equal load.

The runner:

- rejects unknown scenario fields, absolute request URLs, credentials in the
  base URL, literal sensitive headers, excessive concurrency, request counts,
  timeouts, aggregate requests, or aggregate worst-case duration;
- permits loopback targets by default and requires each non-loopback hostname
  through an exact `--allow-host` argument;
- refuses to follow redirects, disables inherited HTTP proxy settings, and
  rejects `Host`, forwarding, and hop-by-hop header overrides, so a target
  cannot silently reroute the reviewed request;
- obtains request bodies and sensitive headers from named environment
  variables and never writes headers, bodies, URLs, or response bodies to an
  artifact;
- excludes warm-up requests from measurements and records client-observed
  latency, status, error class, and success only;
- writes versioned JSONL raw results and a JSON summary with raw-file, scenario,
  and normalized selected-configuration digests, release/topology/database
  labels, detected client environment, latency distribution, throughput, and
  error rate; refuses the evidence write if the scenario changes during a run;
  and
- deliberately applies no SLO or pass/fail threshold.

Validate the scenario and harness without sending a request:

```bash
npm run check:capacity
```

For a disposable loopback deployment:

```bash
export AUTHOS_CAPACITY_LOGIN_BODY='read from a protected generated fixture'
export AUTHOS_CAPACITY_REFRESH_BODY='read from a protected generated fixture'
export AUTHOS_CAPACITY_MANAGEMENT_AUTHORIZATION='Bearer value-from-secret-manager'
export AUTHOS_CAPACITY_SCIM_AUTHORIZATION='Bearer value-from-secret-manager'
python3 scripts/authos-capacity.py \
  --scenarios deploy/qualification/capacity-scenarios.json \
  --base-url http://127.0.0.1:8080 \
  --output evidence/capacity/run-01 \
  --release exact-commit-or-artifact-digest \
  --topology documented-topology-name \
  --database sqlite
```

For a non-loopback disposable target, pass its exact hostname separately:

```bash
python3 scripts/authos-capacity.py \
  --scenarios deploy/qualification/capacity-scenarios.json \
  --base-url https://capacity.example.test \
  --allow-host capacity.example.test \
  --output evidence/capacity/run-01
```

Do not put credentials in a scenario, command line, URL, release label, or
output-directory name. Treat generated fixtures and result artifacts as
sensitive even though the runner omits request and response content.

## Reproducible environment record

Before a run, record outside the runner summary:

- exact AuthOS artifact digest and configuration, with secret values omitted;
- operating-system and container/runtime versions, CPU model and allocation,
  memory limit, storage type, filesystem, and volume configuration;
- database engine/version, topology, pool settings, connection limits, and
  whether the database is local, remote, or managed;
- proxy/load-balancer path, TLS termination, network latency, and client-host
  placement;
- tenant, user, membership, role, session, SAML, and SCIM fixture cardinality;
- enabled workers, logging/metrics configuration, and external dependencies;
  and
- scenario file digest, selected workload, run order, and the untouched raw
  and summary artifact digests.

Keep the load generator off the AuthOS host for reference measurements and
measure whether the generator itself saturates. Run one workload at a time
before testing a reviewed mixed workload. Repeat measurements after the system
reaches a stable starting state, and retain every run rather than only the best
one.

## Deriving resource guidance

Resource guidance must be derived from measurements, not from the committed
scenario defaults:

1. Define the required journeys, traffic distribution, data cardinality,
   latency/error objectives, and expected burst duration.
2. Increase offered concurrency in bounded runs while observing AuthOS CPU and
   memory, database CPU/connections/locks, storage latency and growth, job
   depth, and client-side errors.
3. Locate the point where added load stops producing proportional useful
   throughput or causes an objective to fail. Record the limiting resource and
   repeat enough times to distinguish a stable constraint from noise.
4. Choose operating headroom and failover reserve as explicit operator policy.
   Do not infer either from a single saturation run.
5. Re-run after release, schema, database, topology, proxy, or material workload
   changes. Publish guidance only with the environment record and raw artifacts.

This method can produce defensible sizing evidence. The committed SQLite
budget-VM experiment demonstrates the evidence shape and one narrow result.
Capacity remains unqualified across releases, production hosts, other database
backends, other journeys, and supported deployment topologies.
