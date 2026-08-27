# WuppieFuzz

TNO developed WuppieFuzz, a coverage-guided REST API fuzzer developed on top of
LibAFL, targeting a wide audience of end-users, with a strong focus on
ease-of-use, explainability of the discovered flaws and modularity. WuppieFuzz
supports all three settings of testing (black box, grey box and white box).

## WuppieFuzz-Python

WuppieFuzz-Python adds Python target support to WuppieFuzz by running a small
coverage monitor inside the Python process under test (PUT). The monitor
collects coverage while the PUT runs and exposes it to WuppieFuzz over a TCP
connection, so coverage can be gathered from long-running services without
waiting for the process to exit.

Two coverage backends are provided, each in its own directory:

- [`coveragepy/`](coveragepy/README.md) — builds on the
  [coverage.py](https://coverage.readthedocs.io/) package and serves coverage in
  LCOV format. Works with older Python versions. See
  [coveragepy/README.md](coveragepy/README.md) for setup and usage.
- [`sys-monitoring/`](sys-monitoring/README.md) — uses Python 3.12+'s built-in
  [`sys.monitoring`](https://docs.python.org/3/library/sys.monitoring.html) API
  to track branch coverage in a shared coverage map. No third-party
  dependencies. See [sys-monitoring/README.md](sys-monitoring/README.md) for
  details on how it works and how to use it.

Both backends are shipped as a `sitecustomize.py` that Python imports
automatically when placed on the `site-packages` path; coverage collection only
starts when the `COVERAGE_PROCESS_START` environment variable is set, so there
are no side-effects for regular Python invocations.
