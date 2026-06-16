"""SecGPT-7B QLoRA 微调脚本 — 单卡 (cuda:0)"""
import os
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

MODEL_PATH = "/root/didi_stest/secgpt_finetune/models/secgpt-7B"
TRAIN_DATA = "/root/didi_stest/secgpt_finetune/data/train.jsonl"
EVAL_DATA = "/root/didi_stest/secgpt_finetune/data/eval.jsonl"
OUTPUT_DIR = "/root/didi_stest/secgpt_finetune/output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============ 1. 4-bit 量化配置 ============
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

# ============ 2. 加载模型 (双卡自动分布) ============
print(f"Loading model from {MODEL_PATH} on single GPU (cuda:0)...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    quantization_config=bnb_config,
    device_map="cuda:0",
    trust_remote_code=True,
    torch_dtype=torch.bfloat16,
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

# ============ 3. 加载 tokenizer ============
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token

# ============ 4. LoRA 配置 ============
peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
    task_type="CAUSAL_LM",
)

# ============ 5. 加载数据集 ============
print("Loading datasets...")
dataset = load_dataset("json", data_files={"train": TRAIN_DATA, "eval": EVAL_DATA})
print(f"Train: {len(dataset['train'])} samples, Eval: {len(dataset['eval'])} samples")

def format_chat(example):
    return tokenizer.apply_chat_template(
        example["messages"], tokenize=False, add_generation_prompt=False
    )

# ============ 6. 训练参数 (SFTConfig) ============
training_args = SFTConfig(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=8,
    learning_rate=2e-4,
    weight_decay=0.01,
    warmup_ratio=0.1,
    lr_scheduler_type="cosine",
    optim="paged_adamw_8bit",
    num_train_epochs=8,
    logging_strategy="steps",
    logging_steps=5,
    save_strategy="steps",
    save_steps=60,
    save_total_limit=3,
    eval_strategy="steps",
    eval_steps=60,
    load_best_model_at_end=True,
    metric_for_best_model="eval_loss",
    greater_is_better=False,
    fp16=False,
    bf16=True,
    max_length=1024,
    gradient_checkpointing=True,
    ddp_find_unused_parameters=False,
    report_to=["tensorboard"],
    remove_unused_columns=False,
    dataloader_num_workers=2,
)

# ============ 7. SFTTrainer ============
trainer = SFTTrainer(
    model=model,
    processing_class=tokenizer,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["eval"],
    formatting_func=format_chat,
    peft_config=peft_config,
)

# ============ 8. 开始训练 ============
print("Starting QLoRA training (2× RTX 4090)...")
trainer.train()

# ============ 9. 保存 LoRA adapter ============
final_path = os.path.join(OUTPUT_DIR, "lora_adapter")
trainer.save_model(final_path)
tokenizer.save_pretrained(final_path)
print(f"LoRA adapter saved to {final_path}")
