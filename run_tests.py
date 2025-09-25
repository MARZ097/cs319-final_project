#!/usr/bin/env python3
"""
Test runner script for the Access Control System.
"""
import os
import sys
import subprocess


def run_tests():
    """Run the test suite with coverage."""
    print("Running Access Control System Test Suite")
    print("=" * 50)
    
    # Set environment variables for testing
    os.environ['FLASK_ENV'] = 'testing'
    
    try:
        # Run tests with coverage
        cmd = [
            sys.executable, '-m', 'pytest',
            '--cov=app',
            '--cov-report=html',
            '--cov-report=term-missing',
            '-v'
        ]
        
        result = subprocess.run(cmd, check=False)
        
        if result.returncode == 0:
            print("\n" + "=" * 50)
            print("✓ All tests passed!")
            print("Coverage report generated in htmlcov/index.html")
        else:
            print("\n" + "=" * 50)
            print("✗ Some tests failed!")
            return False
            
    except FileNotFoundError:
        print("Error: pytest not found. Make sure to install test dependencies:")
        print("pip install pytest pytest-cov pytest-flask")
        return False
    
    return True


def run_linting():
    """Run code linting."""
    print("\nRunning code linting...")
    print("-" * 30)
    
    try:
        # Run flake8 for linting
        result = subprocess.run([
            sys.executable, '-m', 'flake8',
            'app', 'tests', '--max-line-length=100'
        ], check=False)
        
        if result.returncode == 0:
            print("✓ No linting errors found!")
        else:
            print("✗ Linting errors found!")
            return False
            
    except FileNotFoundError:
        print("Warning: flake8 not found. Install with: pip install flake8")
        return True  # Don't fail if linter not available
    
    return True


def main():
    """Main function."""
    success = True
    
    # Run tests
    if not run_tests():
        success = False
    
    # Run linting
    if not run_linting():
        success = False
    
    if success:
        print("\n🎉 All checks passed!")
        return 0
    else:
        print("\n❌ Some checks failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
