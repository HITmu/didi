"""Test fine-tuned LoRA model with multiple questions."""
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

MODEL_PATH = "/root/didi_stest/secgpt_finetune/models/secgpt-7B"
ADAPTER_PATH = "/root/didi_stest/secgpt_finetune/output/lora_adapter"

bnb_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
print("Loading model...", flush=True)
base = AutoModelForCausalLM.from_pretrained(MODEL_PATH, quantization_config=bnb_config,
                                            device_map="cuda:0", trust_remote_code=True, torch_dtype=torch.bfloat16)
print("Loading adapter...", flush=True)
model = PeftModel.from_pretrained(base, ADAPTER_PATH)
tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)

SYSTEM = "你是一个网络安全专家，擅长分析API安全漏洞和生成安全报告。"

questions = [
    "什么是XSS攻击？如何防范？",
    "RESTful API设计有哪些最佳实践？",
    "端口扫描的原理是什么？",
    "如何防范暴力破解攻击？",
]

for q in questions:
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": q}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to("cuda")
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=200, temperature=0.3, top_p=0.9,
                             do_sample=True, repetition_penalty=1.1)
    resp = tok.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    print(f"\n{'='*60}")
    print(f"Q: {q}")
    print(f"A: {resp.strip()}")
