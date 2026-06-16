#!/usr/bin/env python3
"""
Full evaluation pipeline: generate test data → batch inference → analyze → report.
All local model inference on single GPU (cuda:0).
"""
import os, sys, time, subprocess

SCRIPTS_DIR = "/root/didi_stest/secgpt_finetune/scripts"
TEST_DIR = "/root/didi_stest/secgpt_finetune/test_results"
os.makedirs(TEST_DIR, exist_ok=True)

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def run_step(name, cmd, env=None):
    log(f"=== Step: {name} ===")
    log(f"Command: {cmd}")
    t0 = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env={**os.environ, **(env or {})})
    elapsed = time.time() - t0
    if result.stdout:
        print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout, flush=True)
    if result.stderr:
        # Only show stderr if it has relevant content (not just progress bars)
        stderr_clean = [l for l in result.stderr.split('\n') if 'it/s' not in l and '%|' not in l and '[' not in l]
        if stderr_clean and ''.join(stderr_clean).strip():
            print('\n'.join(stderr_clean[-20:]), flush=True)
    log(f"Completed in {elapsed:.0f}s, exit={result.returncode}")
    if result.returncode != 0:
        log(f"ERROR: Step failed! See output above.")
        sys.exit(1)
    return result

def main():
    log("=" * 60)
    log("SecGPT-7B LoRA 微调评估流水线")
    log("=" * 60)

    # Step 1: Generate test data
    run_step("Generate 500 test entries",
             f"python3 {SCRIPTS_DIR}/generate_test_data.py")

    # Step 2: Batch inference (Base + LoRA on single GPU)
    run_step("Batch inference (single GPU)",
             f"cd /root/didi_stest/secgpt_finetune && conda run -n didienv python {SCRIPTS_DIR}/batch_inference.py")

    # Step 3: Analyze results with LLM
    run_step("LLM analysis",
             f"cd /root/didi_stest/secgpt_finetune && conda run -n didienv python {SCRIPTS_DIR}/analyze_results.py")

    log("=" * 60)
    log("Pipeline complete!")
    log(f"Results in: {TEST_DIR}")
    log(f"Report: /root/didi_stest/secgpt_finetune/lora_optimization_report.md")
    log("=" * 60)

if __name__ == "__main__":
    main()
