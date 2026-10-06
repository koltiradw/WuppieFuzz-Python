# WuppieFuzz-Python — sys.monitoring backend

This backend gathers Python coverage through the built-in
[`sys.monitoring`](https://docs.python.org/3/library/sys.monitoring.html) API
(introduced in Python 3.12) and exposes it to WuppieFuzz as a raw coverage map
over a TCP connection. Unlike the [coverage.py backend](../coveragepy/README.md)
it has no third-party dependencies and tracks branch coverage, which is a
natural fit for coverage-guided fuzzing. It also collects line coverage and can
write an LCOV tracefile that includes uncovered lines, so `genhtml` can render a
full HTML report.

It is shipped as a `sitecustomize.py` that Python imports automatically when
placed on the `site-packages` path.

## Requirements

- Python 3.12 or newer (`sys.monitoring` is required). On older versions the
  module prints a message and exits.

## How it works

When `WUPPIE_COVERAGE_AGENT_START` is set, the module:

1. Registers a `sys.monitoring` callback (tool id `COVERAGE_ID`) for `JUMP` and
   `BRANCH` events. On Python 3.14+ it subscribes to `BRANCH_LEFT` and
   `BRANCH_RIGHT`; on 3.12–3.13 it subscribes to `BRANCH`.
2. Maintains a fixed-size coverage map (`Covmap`, a `bytearray` of
   `WUPPIE_COVMAP_SIZE` bytes, default 16384). Every byte is an edge hit count,
   capped at 255.
3. For each monitored instruction transition it records branch coverage:
   `location = hash(code.co_filename + str(next_instruction_offset)) % MAP_SIZE`,
   then `map[prev_location ^ location] += 1` and advances
   `prev_location = location // 2`.
4. Optionally restricts coverage to a set of source path prefixes
   (`WUPPIE_COVERAGE_INCLUDE`, `os.pathsep`-separated); code objects outside
   those prefixes are skipped (the decision is cached per code object).
5. Starts a TCP server (default port 1337, `WUPPIE_COVERAGE_PORT`) in a
   background daemon thread that serves the coverage map to WuppieFuzz.
6. When `WUPPIE_COLLECT_LCOV` is set, collects line coverage in a **line
   baseline**: at startup the agent walks the `WUPPIE_COVERAGE_INCLUDE`
   prefixes (or the working directory when unset) and `compile()`s every `*.py`
   file to find its executable lines, seeding the baseline with a zero counter
   for each. LINE events only increment the counters, so uncovered lines and
   never-executed files stay visible. Files first seen at runtime get their
   baseline computed lazily; files that fail to compile are skipped. Without
   `WUPPIE_COLLECT_LCOV` no LINE events are registered and the agent tracks
   branch coverage only.
7. When `WUPPIE_COLLECT_LCOV` is set, writes an LCOV tracefile to that path each
   time the TCP client disconnects: one record per file with
   `DA:<line>,<count>` entries (uncovered executable lines carry count 0),
   `LH:`/`LF:` totals and `end_of_record`.


### Wire protocol

The agent speaks a simple length-prefixed binary protocol over a persistent TCP
connection. Each frame is:

```
| Magic (4) | Version (1) | Type (1) | Length (4, LE) | Payload (Length) |
```

- **Magic:** `"WGCA"` (`57 47 43 41`) — identifies the protocol on every frame.
- **Version:** `0x01`.
- **Types:** `0x01 REQUEST_DUMP` (payload = 1-byte reset flag) from the consumer;
  `0x02 RESPONSE_DUMP` (payload = the coverage map) from the agent.
- The map size is carried by `Length`; there is no separate `size` field.

## Usage

### Setup

Determine the location of your `site-packages` for the Python executable that
runs the PUT:

```console
$ python3.12 -m site --user-site
/home/wupwup/.local/lib/python3.12/site-packages
```

Copy `sitecustomize.py` there:

```console
$ cp sys-monitoring/sitecustomize.py <path to site-packages>
```

### Starting the PUT

Run the PUT with `WUPPIE_COVERAGE_AGENT_START` set (the value only needs to be
truthy — coverage collection will not start otherwise):

```
WUPPIE_COVERAGE_AGENT_START=1 python3.12 <your regular python commands>
```

For quick local testing, putting this directory on `PYTHONPATH` also works:
Python's `site` module imports `sitecustomize` from there at startup.

### Environment variables

| variable                  | default  | description                                                  |
|---------------------------|----------|--------------------------------------------------------------|
| `WUPPIE_COVERAGE_AGENT_START` | (unset) | Must be set to enable the coverage agent.                |
| `WUPPIE_COVERAGE_PORT`    | `1337`   | TCP port the coverage server listens on.                     |
| `WUPPIE_COVMAP_SIZE`      | `16384`  | Size of the coverage map in bytes.                           |
| `WUPPIE_COVERAGE_INCLUDE` | (unset)  | `os.pathsep`-separated path prefixes to include in coverage. |
| `WUPPIE_COLLECT_LCOV`     | (unset)  | Path to write the LCOV line-coverage tracefile to on TCP client disconnect; setting it enables line-coverage collection. |
| `WUPPIE_DEBUG_PYTHON`     | (unset)  | If set, enables debug logging.                               |


## Credits

PT Labs, Ivan Kapranov.
