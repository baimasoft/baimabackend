import os
import re

def in_docker():
    cgroup_files = ["/proc/self/cgroup", "/proc/1/cgroup", "/proc/self/mountinfo"]
    
    for file_path in cgroup_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, "r") as f:
                    if re.search(r"/docker/", f.read()):
                        return True
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
    
    return False