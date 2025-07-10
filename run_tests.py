#!/usr/bin/env python3
"""
Test runner script for Confusys API
"""
import os
import sys
import subprocess
import argparse

def run_tests(coverage=True, verbose=True):
    """Run the test suite"""
    cmd = ["python", "-m", "pytest"]
    
    if verbose:
        cmd.append("-v")
    
    if coverage:
        cmd.extend(["--cov=api", "--cov-report=term-missing", "--cov-report=html"])
    
    cmd.append("tests/")
    
    print(f"Running tests with command: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode

def main():
    parser = argparse.ArgumentParser(description="Run Confusys API tests")
    parser.add_argument("--no-coverage", action="store_true", help="Disable coverage reporting")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity")
    
    args = parser.parse_args()
    
    # Set up environment variables for testing
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "test-secret-key")
    
    # Run tests
    exit_code = run_tests(coverage=not args.no_coverage, verbose=not args.quiet)
    sys.exit(exit_code)

if __name__ == "__main__":
    main() 