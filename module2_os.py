import os
import threading
from collections import deque

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    import fcntl
    HAS_MSVCRT = False

file_access_semaphore = threading.BoundedSemaphore(3)
critical_section_lock = threading.Lock()
page_lock = threading.Lock()
PAGE_SIZE_KB = 4
virtual_page_table = {}
page_fault_counter = 0


def get_os_process_info():
    pid = os.getpid()
    if HAS_PSUTIL:
        process = psutil.Process(pid)
        memory_mb = process.memory_info().rss / (1024 * 1024)
        return f"Process ID: {pid} | Threads: {process.num_threads()} | Memory: {memory_mb:.2f} MB"
    return f"Process ID: {pid} | Memory tracking unavailable"


def verify_os_file_permissions(filepath):
    if not os.path.exists(filepath):
        return False, f"File '{filepath}' is missing."
    can_read = os.access(filepath, os.R_OK)
    can_write = os.access(filepath, os.W_OK)
    if not can_read:
        return False, "The operating system denied read permission."
    inode = getattr(os.stat(filepath), "st_ino", "N/A")
    return True, f"OS permission verified | Inode: {inode} | Read: {can_read} | Write: {can_write}"


def secure_os_locked_read(filepath):
    if not os.path.isfile(filepath):
        return f"File '{filepath}' was not found."
    if not file_access_semaphore.acquire(timeout=2):
        return "File reader limit reached; try again shortly."
    try:
        with critical_section_lock:
            descriptor = os.open(filepath, os.O_RDONLY)
            locked = False
            try:
                if HAS_MSVCRT:
                    if os.path.getsize(filepath):
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        locked = True
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    locked = True
                content = os.read(descriptor, 100).decode("utf-8", errors="replace").strip()
                return f"Kernel synchronized read: {content[:35]}..."
            finally:
                if locked:
                    if HAS_MSVCRT:
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
    except Exception as error:
        return f"OS file lock error: {error}"
    finally:
        file_access_semaphore.release()


def secure_os_read_stream(filepath, chunk_size=64 * 1024):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)
    if not os.access(filepath, os.R_OK):
        raise PermissionError("OS native read permission denied")
    if not file_access_semaphore.acquire(timeout=2):
        raise TimeoutError("The file reader limit was reached.")

    try:
        file_handle = open(filepath, "rb")
        locked = False
        try:
            if HAS_MSVCRT:
                if os.path.getsize(filepath):
                    msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
            else:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_SH)
                locked = True
        except Exception:
            file_handle.close()
            raise
    except Exception:
        file_access_semaphore.release()
        raise

    class LockedFileStream:
        def _init_(self):
            self.closed = False

        def _iter_(self):
            return self

        def _next_(self):
            if self.closed:
                raise StopIteration
            try:
                chunk = file_handle.read(chunk_size)
                if chunk:
                    return chunk
                self.close()
                raise StopIteration
            except Exception:
                self.close()
                raise

        def close(self):
            if self.closed:
                return
            self.closed = True
            try:
                if locked:
                    if HAS_MSVCRT:
                        file_handle.seek(0)
                        msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
            finally:
                try:
                    file_handle.close()
                finally:
                    file_access_semaphore.release()

    return LockedFileStream()


def execute_deadlock_safe_task(resource_a_lock, resource_b_lock, task_name):
    if not resource_a_lock.acquire(timeout=2):
        return f"Deadlock avoided for {task_name}: Resource A timed out."
    try:
        if not resource_b_lock.acquire(timeout=2):
            return f"Deadlock avoided for {task_name}: Resource B timed out."
        try:
            return f"Deadlock-safe task completed: {task_name}."
        finally:
            resource_b_lock.release()
    finally:
        resource_a_lock.release()


def simulate_demand_paging(file_size_kb):
    global page_fault_counter
    required_pages = max(1, int(file_size_kb // PAGE_SIZE_KB) + 1)
    with page_lock:
        frames = []
        for page_number in range(required_pages):
            if page_number not in virtual_page_table:
                page_fault_counter += 1
                virtual_page_table[page_number] = f"Frame_{page_number % 8}"
            frames.append(virtual_page_table[page_number])
        return f"Demand paging: pages={required_pages}, page faults={page_fault_counter}, frames={frames[:3]}"


def simulate_process_scheduling(task_list):
    queue = deque(task_list)
    quantum_ms = 10
    execution_order = []
    while queue:
        execution_order.append(queue.popleft())
    return f"Round-robin: {len(execution_order)} tasks, quantum={quantum_ms} ms, order={execution_order}"


def run_os_concept_demo(filepath):
    print("\n--- OS PROCESS, FILE, AND SYNCHRONIZATION DEMO ---")
    print(get_os_process_info())
    print(verify_os_file_permissions(filepath))
    print(secure_os_locked_read(filepath))
    print(execute_deadlock_safe_task(threading.Lock(), threading.Lock(), "OS demo"))
    print(simulate_demand_paging(os.path.getsize(filepath) / 1024))
    print(simulate_process_scheduling(["Task A", "Task B", "Task C"]))
