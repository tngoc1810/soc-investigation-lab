"""Measure isolated offline runs; memory is the whole worker's peak working set."""

import argparse
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def peak_memory_bytes():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        size_t = ctypes.c_size_t
        class Counters(ctypes.Structure):
            _fields_ = [("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)] + [(name,size_t) for name in (
                "PeakWorkingSetSize","WorkingSetSize","QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage","QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage")]
        kernel = ctypes.WinDLL("kernel32",use_last_error=True)
        psapi = ctypes.WinDLL("psapi",use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = Counters(); counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize
    import resource
    value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == "darwin" else value*1024


def worker(source):
    from soclab.store import ingest
    from soclab.report import analyze
    with tempfile.TemporaryDirectory(prefix="soclab-benchmark-") as temp:
        root=Path(temp); started=perf_counter()
        imported=ingest(source,root/"evidence.sqlite")
        ingest_seconds=perf_counter()-started
        started=perf_counter()
        manifest=analyze(root/"evidence.sqlite",ROOT/"rules/windows.json",root/"analysis")
        analyze_seconds=perf_counter()-started
        result={"event_count":imported["events"],"findings_by_rule":manifest["findings_by_rule"],
                "ingest_seconds":round(ingest_seconds,6),"analyze_seconds":round(analyze_seconds,6),
                "peak_working_set_bytes":peak_memory_bytes()}
        print(json.dumps(result))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("source",type=Path)
    parser.add_argument("--worker",action="store_true")
    parser.add_argument("--runs",type=int,default=3)
    parser.add_argument("--out",type=Path,default=Path("evidence/benchmark.json"))
    args=parser.parse_args()
    if args.worker:return worker(args.source)
    if not 1<=args.runs<=10:parser.error("runs must be 1..10")
    source=args.source.resolve()
    samples=[]
    for _ in range(args.runs):
        result=subprocess.run([sys.executable,str(Path(__file__).resolve()),str(source),"--worker"],capture_output=True,text=True,encoding="utf-8",check=True)
        samples.append(json.loads(result.stdout))
    import hashlib
    with source.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    report={"validation_date":"2026-10-04","python":platform.python_version(),"platform":platform.system(),
            "source_sha256":digest,"source_bytes":source.stat().st_size,"runs":samples,
            "median_ingest_seconds":statistics.median(s["ingest_seconds"] for s in samples),
            "median_analyze_seconds":statistics.median(s["analyze_seconds"] for s in samples),
            "max_peak_working_set_mib":round(max(s["peak_working_set_bytes"] for s in samples)/(1024**2),2),
            "scope":"Three fresh isolated processes on this Windows host; includes Python, SQLite and output generation. Not total laptop RAM, live latency or a large-scale guarantee."}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":main()
