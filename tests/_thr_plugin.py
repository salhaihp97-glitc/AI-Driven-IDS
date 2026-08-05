import sys, threading, traceback, os
import psutil

_proc = None

def _stack_for(t):
    frames = sys._current_frames()
    if t.ident in frames:
        return "".join(traceback.format_stack(frames[t.ident]))
    return "(no frame)"

def _safe(msg):
    try:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()
    except Exception:
        pass

def _check_lock(item):
    global _proc
    try:
        import tempfile
        if _proc is None:
            _proc = psutil.Process()
        # find temp db paths owned by the test fixture
        db_paths = set()
        for f in _proc.open_files():
            p = f.path.replace("/", "\\")
            if "test_ai_ids.db" in p:
                db_paths.add(p)
        if not db_paths:
            return
        for p in sorted(db_paths):
            locked = True
            try:
                with open(p, "a+b"):
                    locked = False
            except Exception:
                locked = True
            if locked:
                _safe(f"[LOCK] db={p} locked at teardown of {item.nodeid}")
                for t in threading.enumerate():
                    if t.is_alive() and t is not threading.current_thread():
                        _safe(f"[LOCK] thread {t.name}:\n{_stack_for(t)}")
                for f in _proc.open_files():
                    if "test_ai_ids.db" in f.path:
                        _safe(f"[LOCK] open handle: {f.path} (fd={f.fd})")
    except Exception as e:
        _safe(f"[PLUGIN-ERR] {e!r}")

def pytest_runtest_teardown(item, nextitem):
    try:
        _check_lock(item)
    except Exception:
        pass
