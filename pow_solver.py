#!/usr/bin/env python3
import hashlib
import sys
import time

def find_pow_nonce(content: str, difficulty: int = 4):
    """
    CLI Tool for Singularity Users to compute Proof of Work.
    Since JavaScript is disabled on the platform, users must run this to post.
    """
    target = '0' * difficulty
    nonce = 0
    print(f"[*] Solving Proof of Work (Difficulty: {difficulty} zeros)...")
    start_time = time.time()
    
    while True:
        nonce_str = str(nonce)
        payload = (content + nonce_str).encode('utf-8')
        h = hashlib.sha256(payload).hexdigest()
        
        if h.startswith(target):
            elapsed = time.time() - start_time
            print(f"[+] Solved in {elapsed:.2f} seconds!")
            print(f"[+] Found Nonce: {nonce_str}")
            print(f"[+] Hash: {h}")
            return nonce_str
        
        nonce += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pow_solver.py \"<your_post_content>\"")
        sys.exit(1)
    
    content = sys.argv[1]
    find_pow_nonce(content)
