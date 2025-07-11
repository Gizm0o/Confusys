import os
import yaml
import re
import locale

RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')

# Get system language or default to English
def get_system_language():
    try:
        lang = locale.getdefaultlocale()[0]
        if lang:
            return lang.split('_')[0]  # Get language code without country
    except:
        pass
    return 'en'

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

def _get_localized_field(rule, field_name, language=None):
    """Get localized field value with fallback to base field."""
    if not language:
        language = get_system_language()
    
    # Try language-specific field first
    lang_field = f"{field_name}_{language}"
    if lang_field in rule:
        return rule[lang_field]
    
    # Fallback to base field
    return rule.get(field_name, "")

def _match_pattern(pattern, content, regex=False, case_sensitive=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    if regex:
        return re.search(pattern, content, flags) is not None
    else:
        if not case_sensitive:
            pattern = pattern.lower()
            content = content.lower()
        return pattern in content

def scan_file_with_rules(filename, data, language=None):
    """
    Scan the file content (bytes) with all loaded rules.
    Returns a list of findings (dicts).
    
    Args:
        filename: Name of the file being scanned
        data: File content as bytes
        language: Language code for localized messages (e.g., 'en', 'fr')
    """
    rules = load_rules()
    content = data.decode('utf-8', errors='replace')
    findings = []
    for rule in rules:
        patterns = rule.get('search')
        if not patterns:
            continue
        # Support both string and list for patterns
        if isinstance(patterns, str):
            patterns = [patterns]
        regex = rule.get('regex', False)
        case_sensitive = rule.get('case_sensitive', False)
        for pattern in patterns:
            try:
                if _match_pattern(pattern, content, regex=regex, case_sensitive=case_sensitive):
                    finding = {
                        'id': rule.get('id'),
                        'description': _get_localized_field(rule, 'description', language),
                        'severity': rule.get('severity'),
                        'recommendation': _get_localized_field(rule, 'recommendation', language),
                        'source': rule.get('source'),
                        'match': pattern,
                        'category': _get_localized_field(rule, 'category', language),
                        'tags': rule.get('tags'),
                        'example': _get_localized_field(rule, 'example', language),
                        'reference': rule.get('reference'),
                        'language': language or get_system_language(),
                    }
                    findings.append(finding)
            except Exception as e:
                findings.append({'id': rule.get('id'), 'error': str(e), 'source': rule.get('source')})
    return findings 