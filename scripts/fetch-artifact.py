#!/usr/bin/env python3
"""Fetch a GitHub Actions artifact zip with parallel range requests.

Single-connection curl to GitHub's blob storage is slow here; the server does
support Range requests, so split the file into N chunks and fetch them
concurrently, then verify the archive before anyone trusts it.
"""
import os
import subprocess
import sys
import threading
import urllib.request
import zipfile

WORKERS = 8


def token() -> str:
    return subprocess.check_output(["gh", "auth", "token"], text=True).strip()


def main(artifact_id: str, out_path: str) -> int:
    url = f"https://api.github.com/repos/kilisk/Aevan/actions/artifacts/{artifact_id}/zip"
    auth = {"Authorization": f"Bearer {token()}", "Accept": "application/vnd.github+json"}

    # Resolve the redirect with curl: it drops the Authorization header on a
    # cross-host hop, which is exactly what GitHub's signed blob URL needs.
    resolved = subprocess.run(
        ["curl", "-sIL", url, "-H", f"Authorization: Bearer {token()}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    locations = [line.split(":", 1)[1].strip() for line in resolved.splitlines()
                 if line.lower().startswith("location:")]
    sizes = [line.split(":", 1)[1].strip() for line in resolved.splitlines()
             if line.lower().startswith("content-length:")]
    if not locations or not sizes:
        print("could not resolve the artifact URL", file=sys.stderr)
        return 1
    final_url = locations[-1]
    size = int(sizes[-1])

    part = size // WORKERS + 1
    chunks = [(i * part, min(size - 1, (i + 1) * part - 1)) for i in range(WORKERS)]
    chunks = [c for c in chunks if c[0] <= c[1]]
    errors: list[str] = []

    def fetch(index: int, start: int, end: int) -> None:
        path = f"{out_path}.part{index}"
        request = urllib.request.Request(
            final_url, headers={"Range": f"bytes={start}-{end}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response, open(path, "wb") as sink:
                while True:
                    block = response.read(1 << 20)
                    if not block:
                        break
                    sink.write(block)
            expected = end - start + 1
            actual = os.path.getsize(path)
            if actual != expected:
                errors.append(f"part {index}: {actual} of {expected} bytes")
        except Exception as error:  # noqa: BLE001 - reported, not swallowed
            errors.append(f"part {index}: {error}")

    threads = [
        threading.Thread(target=fetch, args=(index, start, end), daemon=True)
        for index, (start, end) in enumerate(chunks)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    with open(out_path, "wb") as sink:
        for index in range(len(chunks)):
            with open(f"{out_path}.part{index}", "rb") as part_file:
                sink.write(part_file.read())
    for index in range(len(chunks)):
        os.remove(f"{out_path}.part{index}")

    try:
        archive = zipfile.ZipFile(out_path)
        bad = archive.testzip()
    except Exception as error:  # noqa: BLE001
        print(f"archive unusable: {error}", file=sys.stderr)
        return 1
    if bad is not None:
        print(f"corrupt member: {bad}", file=sys.stderr)
        return 1

    print(f"ok: {out_path} ({os.path.getsize(out_path)} bytes, {len(archive.namelist())} members)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
