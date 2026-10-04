"""Resume a pinned official archive using four bounded HTTP range workers."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[1]


def fetch(name):
    if name not in ("loki","grafana"): raise ValueError("unknown pinned runtime")
    spec=json.loads((ROOT/"deployment/runtime-lock.json").read_text(encoding="utf-8"))[name]
    folder=Path(os.environ["LOCALAPPDATA"])/"SOCInvestigationLab/runtime"
    folder.mkdir(parents=True,exist_ok=True)
    archive=folder/f"{name}-{spec['version']}.{spec['format']}"
    if archive.exists():
        with archive.open("rb") as stream: digest=hashlib.file_digest(stream,"sha256").hexdigest()
        if digest!=spec["sha256"]: raise ValueError("existing archive hash mismatch")
        return
    with urlopen(Request(spec["url"],method="HEAD"),timeout=30) as response:
        size=int(response.headers["Content-Length"])
        ranges=response.headers.get("Accept-Ranges")=="bytes"
    if not ranges: raise ValueError("server does not advertise resumable byte ranges")
    parts=folder/f"{name}-{spec['version']}.parts"
    parts.mkdir(exist_ok=True)
    def worker(number):
        start,end=size*number//4,size*(number+1)//4-1
        path=parts/f"{number}.part"
        existing=path.stat().st_size if path.exists() else 0
        if existing>end-start+1: raise ValueError("partial segment exceeds expected range")
        if existing==end-start+1: return
        failures=0
        while existing < end-start+1:
            piece_start=start+existing
            piece_end=min(end,piece_start+2*1024*1024-1)
            request=Request(spec["url"],headers={"Range":f"bytes={piece_start}-{piece_end}"})
            deadline=time.monotonic()+120
            try:
                with urlopen(request,timeout=30) as response, path.open("ab") as output:
                    if response.status!=206 or response.headers.get("Content-Range")!=f"bytes {piece_start}-{piece_end}/{size}": raise ValueError("unexpected server range response")
                    remaining=piece_end-piece_start+1
                    while remaining:
                        if time.monotonic()>deadline: raise TimeoutError("segment transfer stalled")
                        block=response.read1(min(64*1024,remaining))
                        if not block: raise OSError("incomplete segment")
                        output.write(block);remaining-=len(block);existing+=len(block)
                failures=0
            except OSError:
                failures+=1
                if failures>5: raise
                existing=path.stat().st_size if path.exists() else 0
                time.sleep(min(failures,5))
    with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(worker,range(4)))
    temporary=folder/f"{name}-{spec['version']}.assembled"
    digest=hashlib.sha256()
    with temporary.open("wb") as output:
        for number in range(4):
            with (parts/f"{number}.part").open("rb") as source:
                while block:=source.read(1024*1024): digest.update(block);output.write(block)
    if digest.hexdigest()!=spec["sha256"]: raise ValueError("official runtime digest mismatch")
    temporary.rename(archive)
    print(f"Verified {name} {spec['version']}: {size} bytes",flush=True)


if __name__=="__main__":fetch(sys.argv[1])
