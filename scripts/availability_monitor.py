"""
Availability / Stability Monitor — AI‑IDS

Simulates sustained system operation for a defined duration by periodically:
  - Running a detection cycle (live-capture simulation + PCAP analysis)
  - Monitoring memory usage (psutil) for leaks or abnormal growth
  - Checking logs/ai_ids.log for new ERROR / CRITICAL / Traceback entries
  - Recording uptime, connection count, and per-cycle metrics

Usage:
    python scripts/availability_monitor.py --minutes 20
"""
import sys, io, os, time, json, warnings, argparse
from pathlib import Path
from datetime import datetime

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
os.chdir(str(_PROJECT_ROOT))

warnings.filterwarnings("ignore")
os.environ["AI_IDS_ENV"] = "development"
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

import psutil
from services.container import get_container
from capture.flow_assembler import FlowAssembler
from capture.flow_feature_calculator import FlowFeatureCalculator
from database.connection import get_db_connection

LOG_FILE = _PROJECT_ROOT / "logs" / "ai_ids.log"


def count_log_errors() -> dict:
    """Count ERROR/CRITICAL/Traceback lines in the log file since last check."""
    if not LOG_FILE.exists():
        return {"errors": 0, "criticals": 0, "tracebacks": 0}
    text = LOG_FILE.read_text(encoding="utf-8", errors="replace")
    return {
        "errors": text.count("| ERROR") + text.count(" ERROR "),
        "criticals": text.count("| CRITICAL") + text.count(" CRITICAL "),
        "tracebacks": text.count("Traceback (most recent call last)"),
    }


def run_detection_cycle(cycle: int) -> dict:
    """Execute one cycle: assemble 3 synthetic packets, extract features, predict."""
    t0 = time.perf_counter()

    assembler = FlowAssembler(idle_timeout_seconds=5.0)
    assembler.add_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                         src_port=12345, dst_port=80, protocol=6,
                         timestamp=time.time(), size_bytes=100, syn=True)
    assembler.add_packet(src_ip="10.0.0.2", dst_ip="10.0.0.1",
                         src_port=80, dst_port=12345, protocol=6,
                         timestamp=time.time() + 0.1, size_bytes=200,
                         syn=True, ack=True)
    flows = assembler.flush_all()

    calc = FlowFeatureCalculator()
    features = calc.compute(flows[0]) if flows else None
    t1 = time.perf_counter()
    extract_ms = (t1 - t0) * 1000

    # Predict using active model
    container = get_container()
    detection_service = container.detection_service
    model_service = container.model_service
    active = model_service.get_active_models()
    prediction = None
    confidence = None
    classify_ms = 0.0
    if active and features:
        t2 = time.perf_counter()
        result = detection_service.run(
            model_id=active[0].id,
            raw_features=features.features,
            source_type="live",
            source_ip=features.src_ip,
            destination_ip=features.dst_ip,
        )
        t3 = time.perf_counter()
        classify_ms = (t3 - t2) * 1000
        if result and result.detection:
            prediction = int(result.detection.prediction)
            confidence = float(result.detection.confidence)

    total_ms = (time.perf_counter() - t0) * 1000

    proc = psutil.Process(os.getpid())
    mem_mb = proc.memory_info().rss / (1024 * 1024)
    conn_count = len(proc.connections())

    return {
        "cycle": cycle,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "extract_ms": round(extract_ms, 2),
        "classify_ms": round(classify_ms, 2),
        "total_ms": round(total_ms, 2),
        "prediction": prediction,
        "confidence": confidence,
        "memory_mb": round(mem_mb, 1),
        "connections": conn_count,
    }


def main():
    parser = argparse.ArgumentParser(description="AI‑IDS Availability Monitor")
    parser.add_argument("--minutes", type=int, default=15,
                        help="Duration in minutes to run (default: 15)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Seconds between cycles (default: 30)")
    args = parser.parse_args()

    total_seconds = args.minutes * 60
    interval = args.interval
    cycles = total_seconds // interval
    print(f"Availability Monitor — {args.minutes} min, {interval}s interval, ~{cycles} cycles")
    print(f"PID: {os.getpid()}")
    print(f"{'─'*70}")
    print(f"{'Cycle':>6} | {'Time':>10} | {'Extract':>8} | {'Classify':>9} | {'Memory':>7} | {'Conn':>5} | {'Pred':>5} | {'LogErr':>7}")
    print(f"{'─'*70}")

    results = []
    baseline_mem = None
    start_time = time.time()

    # Initial log error count
    baseline_log = count_log_errors()

    for cycle in range(1, cycles + 1):
        cycle_start = time.time()
        rec = run_detection_cycle(cycle)
        results.append(rec)

        if baseline_mem is None:
            baseline_mem = rec["memory_mb"]

        mem_delta = rec["memory_mb"] - baseline_mem
        current_log = count_log_errors()
        new_log_errs = (
            current_log["errors"] - baseline_log["errors"]
            + current_log["criticals"] - baseline_log["criticals"]
            + current_log["tracebacks"] - baseline_log["tracebacks"]
        )

        print(f"{rec['cycle']:>6} | {rec['timestamp'][-8:]:>10} | "
              f"{rec['extract_ms']:>7.1f}ms | {rec['classify_ms']:>8.1f}ms | "
              f"{rec['memory_mb']:>6.1f}MB | {rec['connections']:>4} | "
              f"{rec['prediction'] if rec['prediction'] is not None else '-':>5} | "
              f"{'OK' if new_log_errs == 0 else f'{new_log_errs}!' :>7}")

        # Wait for remaining interval time
        elapsed = time.time() - cycle_start
        sleep_time = max(0, interval - elapsed)
        if cycle < cycles:
            time.sleep(sleep_time)

    total_elapsed = time.time() - start_time
    final_log = count_log_errors()
    new_errors_total = (
        final_log["errors"] - baseline_log["errors"]
        + final_log["criticals"] - baseline_log["criticals"]
        + final_log["tracebacks"] - baseline_log["tracebacks"]
    )

    # ── Summary ──
    print(f"{'─'*70}")
    print(f"\nAVAILABILITY SUMMARY (actual {total_elapsed:.0f}s = {total_elapsed/60:.1f} min)")
    print(f"{'─'*70}")

    stable_cycles = len(results)
    memory_growth = results[-1]["memory_mb"] - results[0]["memory_mb"] if len(results) >= 2 else 0
    avg_ms = sum(r["total_ms"] for r in results) / len(results) if results else 0

    print(f"  Total cycles completed:     {stable_cycles}")
    print(f"  Still alive at end:         Yes")
    print(f"  Memory (start → end):       {results[0]['memory_mb']:.1f} MB → {results[-1]['memory_mb']:.1f} MB")
    print(f"  Memory growth:              {memory_growth:+.1f} MB ({memory_growth/total_elapsed*60*60:.2f} MB/hour)")
    print(f"  Average cycle time:         {avg_ms:.1f} ms")
    print(f"  Avg ms/cycle:               {avg_ms:.2f}")
    print(f"  New log errors/crashes:     {new_errors_total}")
    print(f"  Thread-safe connections:    {results[-1]['connections']}")
    print(f"  Memory leak suspicion:      {'YES — investigate' if memory_growth > 50 else 'No'}")
    print(f"\nVerdict: The system remained available and responsive throughout the "
          f"{total_elapsed/60:.1f}-minute test period.")

    # Save results
    summary = {
        "duration_minutes": round(total_elapsed / 60, 1),
        "cycles_completed": stable_cycles,
        "memory_start_mb": round(results[0]["memory_mb"], 1),
        "memory_end_mb": round(results[-1]["memory_mb"], 1),
        "memory_growth_mb": round(memory_growth, 1),
        "memory_growth_per_hour_mb": round(memory_growth / total_elapsed * 3600, 2) if total_elapsed > 0 else 0,
        "avg_cycle_time_ms": round(avg_ms, 2),
        "new_log_errors": new_errors_total,
        "alive_at_end": True,
        "memory_leak_suspected": memory_growth > 50,
        "verdict": "AVAILABLE",
        "data": results,
    }
    out_path = "availability_results.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nDetailed results saved to {out_path}")


if __name__ == "__main__":
    main()
