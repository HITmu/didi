"""API ↔ 责任人绑定管理。

提供绑定的 CRUD 操作和按 API 端点查找人员功能。
"""

import os
import json
import uuid
from datetime import datetime
from typing import Optional, List
from fnmatch import fnmatch

from .models import ResponsiblePerson, ApiBinding


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
PERSONS_FILE = os.path.join(DATA_DIR, "persons.json")
BINDINGS_FILE = os.path.join(DATA_DIR, "bindings.json")


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(path, default=None):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default or []


def _save_json(path, data):
    _ensure_data_dir()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ==================== 人员 CRUD ====================

def list_persons() -> List[ResponsiblePerson]:
    return [ResponsiblePerson.from_dict(d) for d in _load_json(PERSONS_FILE, [])]


def find_person(person_id: str) -> Optional[ResponsiblePerson]:
    for p in list_persons():
        if p.id == person_id:
            return p
    return None


def add_person(name: str, email: str, phone: str = "",
               role: str = "developer", slack_webhook: str = "") -> ResponsiblePerson:
    persons = list_persons()
    person = ResponsiblePerson(
        id=str(uuid.uuid4())[:8],
        name=name, email=email, phone=phone,
        role=role, slack_webhook=slack_webhook,
        created_at=datetime.now().isoformat()
    )
    persons.append(person)
    _save_json(PERSONS_FILE, [p.to_dict() for p in persons])
    return person


def update_person(person_id: str, **kwargs) -> Optional[ResponsiblePerson]:
    persons = list_persons()
    for p in persons:
        if p.id == person_id:
            for k, v in kwargs.items():
                if hasattr(p, k) and v is not None:
                    setattr(p, k, v)
            _save_json(PERSONS_FILE, [p.to_dict() for p in persons])
            return p
    return None


def delete_person(person_id: str) -> bool:
    persons = list_persons()
    new_list = [p for p in persons if p.id != person_id]
    if len(new_list) < len(persons):
        # 同时移除该人员的绑定
        bindings = list_bindings()
        bindings = [b for b in bindings if b.person_id != person_id]
        _save_json(BINDINGS_FILE, [b.to_dict() for b in bindings])
        _save_json(PERSONS_FILE, [p.to_dict() for p in new_list])
        return True
    return False


# ==================== 绑定 CRUD ====================

def list_bindings() -> List[ApiBinding]:
    return [ApiBinding.from_dict(d) for d in _load_json(BINDINGS_FILE, [])]


def add_binding(api_pattern: str, person_id: str,
                priority: int = 0, description: str = "") -> Optional[ApiBinding]:
    # 验证人员存在
    if not find_person(person_id):
        return None

    bindings = list_bindings()
    binding = ApiBinding(
        id=str(uuid.uuid4())[:8],
        api_pattern=api_pattern,
        person_id=person_id,
        priority=priority,
        description=description,
        created_at=datetime.now().isoformat()
    )
    bindings.append(binding)
    _save_json(BINDINGS_FILE, [b.to_dict() for b in bindings])
    return binding


def remove_binding(binding_id: str) -> bool:
    bindings = list_bindings()
    new_list = [b for b in bindings if b.id != binding_id]
    if len(new_list) < len(bindings):
        _save_json(BINDINGS_FILE, [b.to_dict() for b in new_list])
        return True
    return False


# ==================== 查找 ====================

def find_responsible_for_api(endpoint: str) -> List[tuple[ApiBinding, ResponsiblePerson]]:
    """查找给定 API 端点的所有责任人。

    按绑定优先级排序（最高优先）。
    """
    bindings = list_bindings()
    matched = []
    for b in bindings:
        if b.matches(endpoint):
            person = find_person(b.person_id)
            if person:
                matched.append((b, person))
    # 按优先级降序，然后按模式特异性排序（越长越具体）
    matched.sort(key=lambda x: (-x[0].priority, -len(x[0].api_pattern)))
    return matched


def print_bindings_table():
    """以格式化方式打印所有绑定。"""
    persons = {p.id: p for p in list_persons()}
    bindings = list_bindings()

    if not bindings:
        print("No bindings configured.")
        return

    print(f"{'ID':<10} {'API Pattern':<35} {'Person':<20} {'Priority':<10} {'Description'}")
    print("-" * 90)
    for b in bindings:
        person = persons.get(b.person_id)
        pname = f"{person.name} ({person.email})" if person else "Unknown"
        print(f"{b.id:<10} {b.api_pattern:<35} {pname:<20} {b.priority:<10} {b.description}")

    print(f"\nTotal: {len(bindings)} bindings, {len(persons)} persons")
