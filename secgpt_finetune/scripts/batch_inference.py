"""Batch inference: base model vs LoRA model on test entries (single GPU)."""
import csv, os, json, time, torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

MODEL_PATH = "/root/didi_stest/secgpt_finetune/models/secgpt-7B"
ADAPTER_PATH = "/root/didi_stest/secgpt_finetune/output/lora_adapter"
TEST_CSV = "/root/didi_stest/secgpt_finetune/test_results/api_attack_test_500.csv"
OUT_DIR = "/root/didi_stest/secgpt_finetune/test_results"
os.makedirs(OUT_DIR, exist_ok=True)

BATCH_SIZE = 4
MAX_NEW_TOKENS = 128
SYSTEM = "你是一个网络安全专家，擅长分析API安全漏洞和生成安全报告。"

# Load test questions
questions = []
with open(TEST_CSV, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        questions.append((int(row["id"]), row["category"], row["question"]))

print(f"Loaded {len(questions)} test entries", flush=True)

# Load model
bnb_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
print("Loading model...", flush=True)
base = AutoModelForCausalLM.from_pretrained(MODEL_PATH, quantization_config=bnb_config,
                                            device_map="cuda:0", trust_remote_code=True, torch_dtype=torch.bfloat16)
tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
# Left padding for batch generation
tok.padding_side = "left"
tok.pad_token = tok.eos_token

def batch_generate(model, questions_batch, desc=""):
    """Run batch inference on a list of (id, cat, question) tuples."""
    results = []
    for i in range(0, len(questions_batch), BATCH_SIZE):
        batch = questions_batch[i:i+BATCH_SIZE]
        prompts = []
        for _, _, q in batch:
            msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": q}]
            text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
            prompts.append(text)

        inputs = tok(prompts, padding=True, return_tensors="pt").to("cuda")
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                temperature=0.3,
                top_p=0.9,
                do_sample=True,
                repetition_penalty=1.1,
            )

        for j, (qid, cat, q) in enumerate(batch):
            resp = tok.decode(outputs[j][inputs.input_ids.shape[1]:], skip_special_tokens=True)
            results.append({"id": qid, "category": cat, "question": q, "answer": resp.strip()})

        if (i // BATCH_SIZE + 1) % 25 == 0:
            print(f"  {desc}: {i+len(batch)}/{len(questions_batch)} done", flush=True)

    return results

# === Base model ===
print("\nBase model inference...", flush=True)
base_results = batch_generate(base, questions, "Base")
base_csv = os.path.join(OUT_DIR, "base_model_results.csv")
with open(base_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "category", "question", "answer"])
    w.writeheader()
    w.writerows(base_results)
print(f"Base results saved: {base_csv}", flush=True)

# === LoRA model ===
print("\nLoading LoRA adapter...", flush=True)
lora_model = PeftModel.from_pretrained(base, ADAPTER_PATH)
print("LoRA model inference...", flush=True)
lora_results = batch_generate(lora_model, questions, "LoRA")
lora_csv = os.path.join(OUT_DIR, "lora_model_results.csv")
with open(lora_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "category", "question", "answer"])
    w.writeheader()
    w.writerows(lora_results)
print(f"LoRA results saved: {lora_csv}", flush=True)

print("\nAll inference complete!", flush=True)
