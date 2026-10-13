# Fandango: Specification-Based Fuzzing of Stateful Network Protocols

Fandango generates protocol sessions from a `.fan` specification of the protocol. The fandango driver (`../fandango-driver`) lets Fandango talk to a server under test as one party of the specification. It runs the server under AFL's fork server, reads AFL's coverage map, and writes its results in the AFLNet layout (`replayable-queue`, `fuzzer_stats`, ...), so the results are analyzed like those of the other fuzzers.

# Running Fandango with ProFuzzBench

Every target includes a `Dockerfile-fandango` that builds on top of the default Dockerfile for the target. It installs Fandango and the driver with the versions locked in `uv.lock` of the workspace, and replaces the run and coverage scripts of the image with `fandango-run.sh` and `fandango-cov_script.sh`. The server under test is the AFL-instrumented build of the default image, and coverage is measured with the same gcov build and `aflnet-replay` as for the other fuzzers.

To build a target for Fandango:
```bash
cd $PFBENCH
cd subjects/FTP/LightFTP
docker build . -t lightftp
docker build . -f Dockerfile-fandango -t lightftp-fandango --build-context fandango-workspace=$PFBENCH/..
```

The script [profuzzbench_build_all.sh](scripts/execution/profuzzbench_build_all.sh) builds the Fandango images of all targets that support Fandango.

The Fandango specification of a target is stored with the target, like its seeds, in `subjects/<protocol>/<target>/fan-specs/` (e.g., `subjects/FTP/LightFTP/fan-specs/ftp.fan`). `Dockerfile-fandango` copies it into the image at `/home/ubuntu/experiments/fan-specs/`, and sets the values the specification reads from the environment for this server (e.g., the FTP credentials). `OPTS[<target>,fandango]` in [jobs.conf](jobs.conf) passes it to the driver with `--spec`.

To run a campaign:
```bash
cd $PFBENCH
FUZZERS=fandango TARGETS="lightftp proftpd" ./launch.sh
```

To run a single fuzzing run:
```bash
cd $PFBENCH
./run_one.sh lightftp fandango 1
```

Every target has a `fan-specs/` directory and an entry `OPTS[<target>,fandango]` in [jobs.conf](jobs.conf), which names the specification the target expects (`<protocol>.fan`, e.g., `dns.fan` for Dnsmasq). To run Fandango on a target, put the specification into its `fan-specs/` directory and rebuild its Fandango image. The run is limited to the fuzzing time with `timeout`, as for AFLNet and StateAFL. A server that does not answer a message within `TEST_TIMEOUT` counts as hanging (`--response-timeout`).

Live555 and forked-daapd additionally need a dedicated build of the server for Fandango and are not supported yet.

Please see the main [README.md](README.md) for more information about how to analyze experiments with ProFuzzBench.
