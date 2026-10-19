import os
import time
import threading
from collections import deque

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import msvcrt # Windows Kernel Locking
    HAS_MSVCRT = True
except ImportError:
    import fcntl # Linux Kernel Locking
    HAS_MSVCRT = False

# Thread Synchronization Primitives
critical_section_lock = threading.Lock()
file_access_semaphore = threading.Semaphore(3)  # Max 3 concurrent readers

# Simulated Virtual Memory & Page Table Structure
PAGE_SIZE_KB = 4
virtual_page_table = {}
page_fault_counter = 0

# -------------------------------------------------------------
# 1. OS INTRO, SYSTEM CALLS & DIAGNOSTICS
# -------------------------------------------------------------
def get_os_process_info():
    """System Call Wrapper: Process Management & Memory Monitoring"""
    pid = os.getpid()
    if HAS_PSUTIL:
        proc = psutil.Process(pid)
        mem_mb = proc.memory_info().rss / (1024 * 1024)
        threads_count = proc.num_threads()
        return f"Process PID: {pid} | Active Threads: {threads_count} | RSS Memory: {mem_mb:.2f} MB"
    else:
        return f"Process PID: {pid} | System Call Tracking Active (Fallback Mode)"

# -------------------------------------------------------------
# 2. FILE SYSTEM IMPLEMENTATION & PROTECTION
# -------------------------------------------------------------
def verify_os_file_permissions(filepath):
    """File System Protection & Inode-like Metadata Inspection"""
    if not os.path.exists(filepath):
        return False, f"OS File Error: Path '{filepath}' not found on storage device."
    
    # Low-level Native System Check
    can_read = os.access(filepath, os.R_OK)
    can_write = os.access(filepath, os.W_OK)
    
    file_stat = os.stat(filepath)
    inode_info = getattr(file_stat, 'st_ino', 'N/A')
    
    if not can_read:
        return False, "OS Security Violation: Read permission denied by OS ACL."
        
    return True, f"OS Verification OK | Inode: {inode_info} | Permissions R/W: ({can_read}/{can_write})"

# -------------------------------------------------------------
# 3. PROCESS SYNCHRONIZATION & CRITICAL SECTION (SEMAPHORES / MUTEX)
# -------------------------------------------------------------
def secure_os_locked_read(filepath):
    """
    Critical Section Solution: Combines Kernel Lock, Mutex Lock,
    and Semaphore to prevent race conditions during parallel access.
    """
    if not os.path.exists(filepath):
        return f"File '{filepath}' not found on Disk."

    # Semaphore acquire (Limit Concurrent Readers)
    file_access_semaphore.acquire()
    
    try:
        # Mutex Lock for Critical Section Entry
        with critical_section_lock:
            # Native OS System Call Level File Descriptor Read
            fd = os.open(filepath, os.O_RDONLY)
            try:
                if HAS_MSVCRT:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 100)
                    content_bytes = os.read(fd, 100)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 100)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    content_bytes = os.read(fd, 100)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                
                content_str = content_bytes.decode('utf-8', errors='ignore').strip()
                return f"Kernel Synchronized Read Success: {content_str[:35]}..."
            finally:
                os.close(fd)
    except Exception as e:
        return f"OS Critical Section Error: {str(e)}"
    finally:
        file_access_semaphore.release()

# -------------------------------------------------------------
# 4. DEADLOCK HANDLING (Prevention & Avoidance with Timeout)
# -------------------------------------------------------------
def execute_deadlock_safe_task(resource_a_lock, resource_b_lock, task_name):
    """
    Deadlock Prevention: Ordered Acquisition & Timeout Handling
    Avoids Hold-and-Wait / Circular Wait conditions.
    """
    acquired_first = resource_a_lock.acquire(timeout=2.0)
    if not acquired_first:
        return f"⚠️ Deadlock Avoided ({task_name}): Failed to acquire Resource A within timeout."

    try:
        acquired_second = resource_b_lock.acquire(timeout=2.0)
        if not acquired_second:
            return f"⚠️ Deadlock Avoided ({task_name}): Failed to acquire Resource B. Released A cleanly."
        try:
            return f"✅ Deadlock-Safe Task ({task_name}): Both Resources Secured & Processed."
        finally:
            resource_b_lock.release()
    finally:
        resource_a_lock.release()

# -------------------------------------------------------------
# 5. VIRTUAL MEMORY MANAGEMENT (Demand Paging Simulation)
# -------------------------------------------------------------
def simulate_demand_paging(file_size_kb):
    """Simulates Demand Paging, Page Faults, and Frame Allocation"""
    global page_fault_counter
    required_pages = max(1, int(file_size_kb // PAGE_SIZE_KB) + 1)
    allocated_frames = []
    for page_num in range(required_pages):
        if page_num not in virtual_page_table:
            page_fault_counter += 1
            frame_id = f"Frame_{page_num % 8}"  # 8 Physical Frames Allocation
            virtual_page_table[page_num] = frame_id
        allocated_frames.append(virtual_page_table[page_num])
    return f"Paging Alloc: Required Pages={required_pages} | Page Faults={page_fault_counter} | Frames={allocated_frames[:3]}..."

# -------------------------------------------------------------
# 6. MULTITHREADING & SCHEDULING ALGORITHM SIMULATION
# -------------------------------------------------------------
def simulate_process_scheduling(task_list):
    """Simulates Round-Robin Process/Thread Scheduling Execution"""
    queue = deque(task_list)
    quantum_ms = 10
    execution_order = []

    while queue:
        task = queue.popleft()
        execution_order.append(task)
        # Process completed simulated quantum

    return f"Round-Robin Scheduling: Executed {len(execution_order)} Threads with Quantum={quantum_ms}ms"

def secure_os_read_stream(filepath):
    """
    Securely reads a file in chunks while checking its existence
    and OS-level read permissions.
    """
    if not os.path.isfile(filepath):
        return None, f"File not found: {filepath}"

    if not os.access(filepath, os.R_OK):
        return None, "OS Security Violation: Read permission denied."

    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                yield chunk

    except OSError as e:
        yield f"OS Read Error: {e}".encode("utf-8")
