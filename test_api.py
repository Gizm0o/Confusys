#!/usr/bin/env python3
"""
Simple test script to check API functionality
"""

import requests
import json

API_BASE_URL = "http://localhost:5000"

def test_login():
    """Test admin login"""
    try:
        response = requests.post(f"{API_BASE_URL}/user/login", 
                               json={"username": "admin", "password": "admin"})
        print(f"Login response status: {response.status_code}")
        print(f"Login response headers: {dict(response.headers)}")
        print(f"Login response content: {response.text[:200]}")
        
        if response.status_code == 200:
            return response.json().get("token")
        else:
            return None
    except Exception as e:
        print(f"Login error: {e}")
        return None

def test_rules_endpoint(token):
    """Test the rules endpoint"""
    if not token:
        print("No token available")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/rules", headers=headers)
        print(f"Rules GET response status: {response.status_code}")
        print(f"Rules GET response headers: {dict(response.headers)}")
        print(f"Rules GET response content: {response.text[:200]}")
        
        if response.status_code == 200:
            rules = response.json()
            print(f"Found {len(rules)} rules")
            for rule in rules:
                print(f"  - {rule.get('filename', 'Unknown')}: {rule.get('description', 'No description')}")
        else:
            print("Failed to get rules")
            
    except Exception as e:
        print(f"Rules endpoint error: {e}")

def test_upload_simple(token):
    """Test a simple rule upload"""
    if not token:
        print("No token available")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create a simple test rule
    test_rule_content = """rules:
  - id: 'TEST001'
    description: 'Test rule'
    search: 'test'
    regex: false
    case_sensitive: false
    severity: 'Medium'
    category: 'Test'
    tags: ['test']
    recommendation: 'Test recommendation'
    example: 'test example'
    reference: 'https://example.com'
"""
    
    files = {"file": ("test_rule.yml", test_rule_content.encode('utf-8'), "application/x-yaml")}
    data = {
        "description": "Test rule for API testing",
        "technologies": ["os_kernel"]
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/rules", headers=headers, files=files, data=data)
        print(f"Upload response status: {response.status_code}")
        print(f"Upload response headers: {dict(response.headers)}")
        print(f"Upload response content: {response.text[:200]}")
        
        if response.status_code == 201:
            print("Upload successful!")
        else:
            print("Upload failed")
            
    except Exception as e:
        print(f"Upload error: {e}")

if __name__ == "__main__":
    print("Testing API functionality...")
    
    # Test login
    token = test_login()
    
    # Test rules endpoint
    test_rules_endpoint(token)
    
    # Test upload
    test_upload_simple(token) 