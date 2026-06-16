"""Local SecGPT-7B LoRA detector — replaces LLM API with local model inference."""

import os, re, torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

MODEL_PATH = "/root/didi_stest/secgpt_finetune/models/secgpt-7B"
ADAPTER_PATH = "/root/didi_stest/secgpt_finetune/output/lora_adapter"
ATTACK_TYPES_ORDER = [
    "directory traversal attack",
    "cross-site scripting attack",
    "unauthorized access attack",
    "injection attack",
    "performance issue",
    "sensitive data leakage",
    "invalid item value",
]

def _load_system_prompt() -> str:
    from prompts.manager import get_prompt_manager
    return get_prompt_manager().system_prompt("security_expert")


class LocalSecGPTDetector:
    """使用本地 SecGPT-7B + LoRA 微调模型进行串行攻击类型检测。"""

    def __init__(self, prompt_builder):
        self.prompt_builder = prompt_builder
        self.model = None
        self.tokenizer = None

    def _ensure_model(self):
        if self.model is not None:
            return
        print("  [LocalModel] Loading SecGPT-7B + LoRA adapter...", flush=True)
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        base = AutoModelForCausalLM.from_pretrained(
            MODEL_PATH,
            quantization_config=bnb_config,
            device_map="cuda:0",
            trust_remote_code=True,
            torch_dtype=torch.bfloat16,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
        self.tokenizer.padding_side = "left"
        self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = PeftModel.from_pretrained(base, ADAPTER_PATH)
        self.model.eval()
        print(f"  [LocalModel] Loaded. VRAM: {torch.cuda.memory_allocated()/1024**3:.1f}GB", flush=True)

    def _get_attack_types_in_order(self):
        available = list(self.prompt_builder.prompt_templates.keys())
        return [t for t in ATTACK_TYPES_ORDER if t in available]

    def detect_serial(self, log_data, log_id, similar_events_map):
        """对一条日志执行所有攻击类型的串行检测（同步调用）。"""
        self._ensure_model()
        attack_types = self._get_attack_types_in_order()
        if not attack_types:
            return (log_id, "normal", "", "No prompt templates available")

        print(f"  Serial detection for log {log_id}: {len(attack_types)} attack types")
        for idx, attack_type in enumerate(attack_types, 1):
            print(f"    Step {idx}/{len(attack_types)}: checking {attack_type}...", flush=True)
            prompt = self.prompt_builder.build_targeted_prompt(
                [log_data], log_id, similar_events_map, attack_type
            )

            msgs = [
                {"role": "system", "content": _load_system_prompt()},
                {"role": "user", "content": prompt},
            ]
            text = self.tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)

            inputs = self.tokenizer(text, return_tensors="pt").to("cuda")
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=128,
                    temperature=0.1,
                    top_p=0.9,
                    do_sample=False,
                    repetition_penalty=1.1,
                    pad_token_id=self.tokenizer.pad_token_id,
                )

            resp = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()
            resp = resp.split("\n")[0].strip()
            result = self._parse_output(resp, log_id, attack_type)

            if result and result[1] == "anomaly":
                print(f"    => ANOMALY: {attack_type} (conf={result[3]})", flush=True)
                return result
            elif result and result[1] == "normal":
                print(f"    => normal for {attack_type}", flush=True)
                continue
            else:
                print(f"    => unparsed: {resp[:80]}", flush=True)

        print(f"    => all clear, marking normal", flush=True)
        return (log_id, "normal", "", "")

    def _parse_output(self, content, log_id, attack_type):
        """解析模型输出，支持 log_id|result|type|confidence|reason 格式。

        输入示例：
          142|anomaly|injection attack|0.95|SQL injection detected
          45|normal
        """
        if not content:
            return None

        # Try structured format: log_id|result|...
        parts = content.split("|")
        if len(parts) >= 2:
            result_type = parts[1].strip().lower()
            if result_type == "normal":
                return (log_id, "normal", "", "")
            elif result_type == "anomaly" and len(parts) >= 4:
                anomaly_type = parts[2].strip()
                try:
                    conf = float(parts[3].strip())
                except ValueError:
                    conf = 0.5
                reason = parts[4] if len(parts) >= 5 else ""
                return (log_id, "anomaly", anomaly_type, conf, reason)

        # Fallback: check if content contains keywords
        normal_kw = ["normal", "not an", "no ", "no_", "不存在", "正常"]
        anomaly_kw = ["anomaly", "attack", "traversal", "injection", "xss", "script"]

        if any(kw in content.lower() for kw in anomaly_kw):
            return (log_id, "anomaly", attack_type, 0.5, content[:100])
        elif any(kw in content.lower() for kw in normal_kw):
            return (log_id, "normal", "", "")
        return None
