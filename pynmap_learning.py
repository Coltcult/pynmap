#!/usr/bin/env python3
"""
PyNmap Learning System - Reinforcement Learning + Payload Evolution
"""

import json
import os
import random
import re
from datetime import datetime

# Color definitions
class Colors:
    RESET = '\033[0m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

# ==============================================================================
# === REINFORCEMENT LEARNER ====================================================
# ==============================================================================

class ReinforcementLearner:
    def __init__(self, memory_file="~/.pynmap_qtable.json"):
        self.memory_file = os.path.expanduser(memory_file)
        self.q_table = self._load_q_table()
        self.alpha = 0.1
        self.gamma = 0.9
        self.epsilon = 0.1
        
    def _load_q_table(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_q_table(self):
        with open(self.memory_file, 'w') as f:
            json.dump(self.q_table, f, indent=2)
    
    def hash_state(self, target_context):
        if not target_context:
            return "default"
        if isinstance(target_context, dict):
            parts = []
            if 'service' in target_context:
                parts.append(target_context['service'])
            if 'port' in target_context:
                parts.append(str(target_context['port']))
            return "_".join(parts) if parts else "default"
        return "default"
    
    def get_optimal_sequence(self, target_context, available_attacks):
        if not available_attacks:
            return []
        state_key = self.hash_state(target_context)
        
        if random.random() < self.epsilon:
            shuffled = available_attacks.copy()
            random.shuffle(shuffled)
            return shuffled
        
        q_values = {}
        for attack in available_attacks:
            attack_name = attack if isinstance(attack, str) else attack.__name__
            q_values[attack_name] = self.q_table.get(f"{state_key}_{attack_name}", 0)
        
        return sorted(available_attacks, key=lambda a: q_values[a if isinstance(a, str) else a.__name__], reverse=True)
    
    def update(self, state, attack, reward):
        if not attack:
            return
        state_key = self.hash_state(state)
        attack_name = attack if isinstance(attack, str) else attack.__name__
        key = f"{state_key}_{attack_name}"
        old_q = self.q_table.get(key, 0)
        new_q = old_q + self.alpha * (reward - old_q)
        self.q_table[key] = new_q
    
    def prioritize_ports(self, ports, target_fingerprint):
        return ports


# ==============================================================================
# === PAYLOAD EVOLUTION ========================================================
# ==============================================================================

class Payload:
    def __init__(self, code, attack_type, fitness=0):
        self.code = code
        self.attack_type = attack_type
        self.fitness = fitness
        self.success_count = 0
        self.failure_count = 0


class PayloadEvolution:
    def __init__(self, memory_file="~/.pynmap_population.json"):
        self.memory_file = os.path.expanduser(memory_file)
        self.population = self._load_population()
        
        self.default_payloads = {
            'sql_injection': ["' OR '1'='1", "' OR 1=1 --", "1' AND '1'='1"],
            'lfi': ["../../../etc/passwd", "../../../../etc/passwd"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'command_injection': ["; cat /etc/passwd", "| cat /etc/passwd"],
        }
    
    def _load_population(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    data = json.load(f)
                    return [Payload(p['code'], p['attack_type']) for p in data]
            except:
                return []
        return []
    
    def save_population(self):
        data = [{'code': p.code, 'attack_type': p.attack_type} for p in self.population]
        with open(self.memory_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_payload(self, attack_type, target_context=None):
        if attack_type in self.default_payloads:
            return random.choice(self.default_payloads[attack_type])
        return None
    
    def update(self, payload_code, result):
        pass


# ==============================================================================
# === SCAN MEMORY ==============================================================
# ==============================================================================

class ScanMemory:
    def __init__(self, memory_file="~/.pynmap_memory.json"):
        self.memory_file = os.path.expanduser(memory_file)
        self.data = self._load_memory()
    
    def _load_memory(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except:
                return {'targets': {}, 'stats': {'total_scans': 0, 'total_vulnerabilities': 0, 'total_flags': 0}}
        return {'targets': {}, 'stats': {'total_scans': 0, 'total_vulnerabilities': 0, 'total_flags': 0}}
    
    def save_memory(self):
        with open(self.memory_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def store_scan_result(self, target, results, duration):
        self.data['stats']['total_scans'] += 1
        self.save_memory()
    
    def record_attack_result(self, attack_name, success):
        if success:
            self.data['stats']['total_vulnerabilities'] += 1
        self.save_memory()
    
    def record_flag(self, flag):
        self.data['stats']['total_flags'] += 1
        self.save_memory()


# ==============================================================================
# === FLAG DETECTOR ============================================================
# ==============================================================================

class FlagDetector:
    FLAG_PATTERNS = [
        (r'CTF\{[^{}]*\}', 'CTF'),
        (r'flag\{[^{}]*\}', 'flag'),
        (r'FLAG\{[^{}]*\}', 'FLAG'),
        (r'[A-Z0-9]{32}', 'MD5'),
        (r'[a-f0-9]{32}', 'md5'),
    ]
    
    @classmethod
    def contains_flag(cls, text):
        text_str = str(text)
        for pattern, _ in cls.FLAG_PATTERNS:
            if re.search(pattern, text_str, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def extract_flags(cls, text):
        text_str = str(text)
        flags = []
        for pattern, flag_type in cls.FLAG_PATTERNS:
            matches = re.findall(pattern, text_str, re.IGNORECASE)
            for match in matches:
                flags.append({'flag': match, 'type': flag_type, 'timestamp': datetime.now().isoformat()})
        return flags
    
    @classmethod
    def print_flags(cls, flags):
        if not flags:
            return
        print(f"\n{Colors.RED}{'='*60}{Colors.RESET}")
        print(f"{Colors.RED}[!] FLAGS FOUND:{Colors.RESET}")
        for flag_info in flags:
            print(f"{Colors.YELLOW}  [{flag_info['type']}] {flag_info['flag']}{Colors.RESET}")
        print(f"{Colors.RED}{'='*60}{Colors.RESET}\n")


# ==============================================================================
# === LEARNING STATISTICS ======================================================
# ==============================================================================

class LearningStats:
    @staticmethod
    def print_stats(learner, evolution, memory):
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}📊 LEARNING STATISTICS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        stats = memory.data.get('stats', {})
        print(f"\n{Colors.GREEN}📈 Overall Statistics:{Colors.RESET}")
        print(f"  Total scans: {stats.get('total_scans', 0)}")
        print(f"  Total vulnerabilities found: {stats.get('total_vulnerabilities', 0)}")
        print(f"  Total flags found: {stats.get('total_flags', 0)}")
        
        print(f"\n{Colors.GREEN}🧠 Q-Table Size:{Colors.RESET}")
        print(f"  {len(learner.q_table)} state-action pairs learned")
        
        print(f"\n{Colors.GREEN}🧬 Payload Population:{Colors.RESET}")
        print(f"  Total payloads: {len(evolution.population)}")
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")

