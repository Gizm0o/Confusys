import os
import yaml
import re

RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')

# Load all rules from YAML files in the rules directory
_rules_cache = []
def load_rules():
    global _rules_cache
    if _rules_cache:
        return _rules_cache
    rules = []
    if not os.path.isdir(RULES_DIR):
        return []
    for fname in os.listdir(RULES_DIR):
        if fname.endswith('.yml') or fname.endswith('.yaml'):
            with open(os.path.join(RULES_DIR, fname), 'r', encoding='utf-8') as f:
                doc = yaml.safe_load(f)
                if doc and 'rules' in doc:
                    for rule in doc['rules']:
                        rule['source'] = fname
                        rules.append(rule)
    _rules_cache = rules
    return rules

def scan_file_with_rules(filename, data):
    """
    Scan the file content (bytes) with all loaded rules.
    Returns a list of findings (dicts).
    """
    rules = load_rules()
    content = data.decode('utf-8', errors='replace')
    findings = []
    for rule in rules:
        pattern = rule.get('search')
        if not pattern:
            continue
        # If the pattern looks like a regex, use re.search, else simple substring
        try:
            if pattern.startswith('image:') or any(c in pattern for c in '^$.*+?[]{}|()'):
                if re.search(pattern, content, re.MULTILINE):
                    findings.append({
                        'id': rule.get('id'),
                        'description': rule.get('description'),
                        'severity': rule.get('severity'),
                        'recommendation': rule.get('recommendation'),
                        'source': rule.get('source'),
                        'match': pattern
                    })
            elif pattern in content:
                findings.append({
                    'id': rule.get('id'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity'),
                    'recommendation': rule.get('recommendation'),
                    'source': rule.get('source'),
                    'match': pattern
                })
        except Exception as e:
            findings.append({'id': rule.get('id'), 'error': str(e), 'source': rule.get('source')})
    return findings 