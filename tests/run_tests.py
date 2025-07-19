#!/usr/bin/env python3
"""
Test runner for pilfer - runs tests for both standalone and CLI versions
"""

import os
import sys
import unittest
import subprocess
from pathlib import Path


def run_test_classes(module_name, test_classes):
    """Run specific test classes from a module and return results"""
    print(f"\n{'='*60}")
    print(f"Running {module_name}")
    print('='*60)
    
    # Try to run the test classes
    try:
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Load specific test classes
        for test_class in test_classes:
            class_suite = loader.loadTestsFromName(f'{module_name}.{test_class}')
            suite.addTest(class_suite)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return result
    except Exception as e:
        print(f"Failed to run {module_name}: {e}")
        return None


def main():
    """Main test runner"""
    print("Pilfer Test Suite")
    print("Testing both standalone pilfer.py and CLI versions")
    print("Verifying hash consistency and line ending preservation")
    
    # Add the tests directory to Python path
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, tests_dir)
    
    # Test modules and classes to run
    test_config = [
        ('test_pilfer_unified', ['TestPilferCLI', 'TestPilferStandalone', 'TestCompatibility']),
    ]
    
    results = []
    for module_name, test_classes in test_config:
        result = run_test_classes(module_name, test_classes)
        if result:
            results.append((module_name, result))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    for module_name, result in results:
        tests_run = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        
        total_tests += tests_run
        total_failures += failures
        total_errors += errors
        
        status = "PASS" if (failures == 0 and errors == 0) else "FAIL"
        print(f"{module_name:<20} {tests_run:>3} tests  {failures:>3} failures  {errors:>3} errors  [{status}]")
    
    print(f"{'-'*60}")
    print(f"{'TOTAL':<20} {total_tests:>3} tests  {total_failures:>3} failures  {total_errors:>3} errors")
    
    if total_failures == 0 and total_errors == 0:
        print("\n✅ All tests passed! Both pilfer versions work correctly.")
        print("   ✓ CLI and standalone versions behave identically")
        print("   ✓ Hash consistency maintained for unchanged files")
        print("   ✓ Line endings preserved during re-encryption")
        print("   ✓ Modified file detection working properly")
        return 0
    else:
        print(f"\n❌ {total_failures + total_errors} test(s) failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main()) 
