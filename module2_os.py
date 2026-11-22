import os
import time
import threading
import math
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

critical_section_lock = threading.Lock()
file_access_semaphore = threading.Semaphore(3)

PAGE_SIZE_KB = 4
virtual_page_table = {}
page_fault_counter = 0

class AccessControlMatrix:
    def __init__(self):
        self.matrix = {
            'ADMIN': {
                'file_system': {'READ', 'WRITE', 'EXECUTE', 'DELETE'},
                'audit_logs': {'READ', 'WRITE'},
                'vault': {'READ', 'WRITE', 'EXECUTE'}
            },
            'EMPLOYEE': {
                'file_system': {'READ'},
                'audit_logs': set(),
                'vault': set()
            },
            'GUEST': {
                'file_system': set(),
                'audit_logs': set(),
                'vault': set()
            }
        }

    def check_permission(self, role, resource, permission):
        role_perms = self.matrix.get(role, {})
        resource_perms = role_perms.get(resource, set())
        return permission in resource_perms

global_acm = AccessControlMatrix()

class SimulatedFileSystem:
    """
    Free Space Management: 0 = Free Space, 1 = Allocated Memory Block.
    """
    def __init__(self, total_blocks=32, block_size_kb=4):
        self.total_blocks = total_blocks
        self.block_size_kb = block_size_kb
        self.free_space_bit_vector = [0] * total_blocks  # 0 = Free, 1 = Allocated
        self.index_table = {}  
        self.directory_structure = {}  

    def allocate_file_indexed(self, filename, size_kb):
        needed_blocks = math.ceil(size_kb / self.block_size_kb)
        free_indices = [i for i, free in enumerate(self.free_space_bit_vector) if free == 0]

        if len(free_indices) < needed_blocks:
            return False, "Allocation Failed: Insufficient Free Space on Secondary Storage."

        allocated = free_indices[:needed_blocks]
        for idx in allocated:
            self.free_space_bit_vector[idx] = 1  # 1 = Allocated

        self.index_table[filename] = allocated
        self.directory_structure[filename] = {
            'size_kb': size_kb,
            'blocks': allocated,
            'created_at': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return True, f"Allocated '{filename}' across blocks: {allocated}"

    def get_free_space_status(self):
        free_count = self.free_space_bit_vector.count(0)
        allocated_count = self.free_space_bit_vector.count(1)
        return f"Free Storage: {free_count} blocks available ({free_count * self.block_size_kb} KB) | Allocated: {allocated_count} blocks."

simulated_fs = SimulatedFileSystem()

class SecondaryStorageManager:
    def __init__(self, cylinders=200):
        self.cylinders = cylinders
        self.swap_space = {}

    def schedule_disk_fcfs(self, start_head, requests):
        total_movement = 0
        current = start_head
        for req in requests:
            total_movement += abs(req - current)
            current = req
        return total_movement

    def schedule_disk_scan(self, start_head, requests, direction="UP"):
        total_movement = 0
        curr = start_head
        reqs = sorted(requests)
        left = [r for r in reqs if r < start_head]
        right = [r for r in reqs if r >= start_head]

        if direction == "UP":
            for r in right:
                total_movement += abs(r - curr)
                curr = r
            if left:
                total_movement += abs((self.cylinders - 1) - curr)
                curr = self.cylinders - 1
                for r in reversed(left):
                    total_movement += abs(r - curr)
                    curr = r
        return total_movement

storage_manager = SecondaryStorageManager()

def secure_os_locked_read(filepath):
    if not os.path.exists(filepath):
        return f"File '{filepath}' not found on Disk."
    file_access_semaphore.acquire()
    try:
        with critical_section_lock:
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
                return f"Kernel Synchronized Read Success: {content_bytes.decode('utf-8', errors='ignore').strip()[:35]}..."
            finally:
                os.close(fd)
    except Exception as e:
        return f"OS Critical Section Error: {str(e)}"
    finally:
        file_access_semaphore.release()