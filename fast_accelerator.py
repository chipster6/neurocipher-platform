#!/usr/bin/env python3
"""
Fast CPU Accelerator for AuditHound
Speeds up computation using all 8 CPU cores on your M3 MacBook
"""

import os
import time
import multiprocessing as mp
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Any
import psutil

def square_function(x):
    """Simple function for testing parallel processing"""
    return x ** 2

def analyze_file(file_path: str) -> Dict[str, Any]:
    """Analyze a single Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        return {
            'file': file_path,
            'lines': len(lines),
            'loc': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'functions': content.count('def '),
            'classes': content.count('class '),
            'imports': content.count('import ')
        }
    except Exception as e:
        return {'file': file_path, 'error': str(e)}

def scan_file_security(file_path: str) -> Dict[str, Any]:
    """Security scan a single file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        issues = []
        lines = content.split('\n')
        
        # Security patterns
        patterns = {
            'password': ['password=', 'passwd='],
            'api_key': ['api_key=', 'apikey='],
            'secret': ['secret=', 'token='],
            'sql': ['execute(', '% '],
            'path': ['../', '../']
        }
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if pattern in line_lower:
                        issues.append({
                            'type': pattern_type,
                            'line': line_num,
                            'pattern': pattern
                        })
        
        return {
            'file': file_path,
            'issues': issues,
            'issue_count': len(issues)
        }
    except Exception as e:
        return {'file': file_path, 'error': str(e), 'issues': []}

class FastAccelerator:
    """Simple, working CPU accelerator"""
    
    def __init__(self):
        self.cpu_count = mp.cpu_count()
        self.start_time = time.time()
        print(f"🚀 Fast Accelerator Ready: {self.cpu_count} CPU cores available")
    
    def parallel_process(self, func, items: List[Any], max_workers: int = None) -> List[Any]:
        """Process items in parallel using ThreadPoolExecutor"""
        if max_workers is None:
            max_workers = self.cpu_count
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(func, items))
        
        duration = time.time() - start_time
        print(f"⚡ Processed {len(items)} items in {duration:.2f}s using {max_workers} threads")
        
        return results
    
    def multiprocess_compute(self, items: List[int]) -> List[int]:
        """CPU-intensive computation using multiprocessing"""
        start_time = time.time()
        
        with mp.Pool(processes=self.cpu_count) as pool:
            results = pool.map(square_function, items)
        
        duration = time.time() - start_time
        print(f"🔥 Computed {len(items)} squares in {duration:.3f}s using {self.cpu_count} processes")
        
        return results
    
    def fast_file_scan(self, directory: str = ".") -> Dict[str, Any]:
        """Fast parallel file analysis"""
        print(f"🔍 Scanning files in {directory}...")
        
        # Find Python files
        path = Path(directory)
        py_files = [str(f) for f in path.rglob("*.py") if f.is_file()]
        
        if not py_files:
            return {"error": "No Python files found"}
        
        print(f"📁 Found {len(py_files)} Python files")
        
        # Analyze files in parallel
        analysis_results = self.parallel_process(analyze_file, py_files)
        
        # Security scan in parallel
        security_results = self.parallel_process(scan_file_security, py_files)
        
        # Combine results
        total_lines = sum(r.get('lines', 0) for r in analysis_results)
        total_loc = sum(r.get('loc', 0) for r in analysis_results)
        total_functions = sum(r.get('functions', 0) for r in analysis_results)
        total_issues = sum(r.get('issue_count', 0) for r in security_results)
        
        return {
            "files_scanned": len(py_files),
            "total_lines": total_lines,
            "lines_of_code": total_loc,
            "total_functions": total_functions,
            "security_issues": total_issues,
            "analysis_results": analysis_results,
            "security_results": security_results
        }
    
    def benchmark_speed(self):
        """Benchmark CPU performance"""
        print("🧪 Running CPU benchmark...")
        
        # Test different workload sizes
        test_sizes = [1000, 5000, 10000, 50000]
        
        for size in test_sizes:
            print(f"\n📊 Testing with {size} operations:")
            
            # Sequential test
            start = time.time()
            sequential_result = [square_function(x) for x in range(size)]
            sequential_time = time.time() - start
            print(f"   Sequential: {sequential_time:.3f}s")
            
            # Parallel test
            start = time.time()
            parallel_result = self.multiprocess_compute(list(range(size)))
            parallel_time = time.time() - start
            print(f"   Parallel: {parallel_time:.3f}s")
            
            if sequential_time > 0:
                speedup = sequential_time / parallel_time
                print(f"   🚀 Speedup: {speedup:.1f}x")
    
    def accelerate_current_project(self):
        """Accelerate analysis of current AuditHound project"""
        print("🚀 Accelerating AuditHound project analysis...")
        
        # Scan the project
        results = self.fast_file_scan(".")
        
        if "error" in results:
            print(f"❌ {results['error']}")
            return
        
        print(f"\n📊 Project Analysis Results:")
        print(f"   📁 Files: {results['files_scanned']}")
        print(f"   📝 Total Lines: {results['total_lines']:,}")
        print(f"   💻 Lines of Code: {results['lines_of_code']:,}")
        print(f"   ⚙️ Functions: {results['total_functions']}")
        print(f"   🛡️ Security Issues: {results['security_issues']}")
        
        # Show files with most issues
        security_results = results['security_results']
        files_with_issues = [r for r in security_results if r.get('issue_count', 0) > 0]
        
        if files_with_issues:
            print(f"\n🚨 Files with security issues:")
            for result in sorted(files_with_issues, key=lambda x: x.get('issue_count', 0), reverse=True)[:5]:
                file_name = Path(result['file']).name
                print(f"   {file_name}: {result['issue_count']} issues")
        
        return results

def main():
    """Main function for testing"""
    accelerator = FastAccelerator()
    
    # Check current system status
    print(f"💻 System Status:")
    print(f"   CPU Usage: {psutil.cpu_percent(interval=1)}%")
    print(f"   Memory: {psutil.virtual_memory().percent}%")
    print(f"   Available Memory: {psutil.virtual_memory().available // (1024**3)}GB")
    
    import sys
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "benchmark":
            accelerator.benchmark_speed()
        elif command == "scan":
            accelerator.fast_file_scan()
        elif command == "project":
            accelerator.accelerate_current_project()
        else:
            print("Commands: benchmark, scan, project")
    else:
        # Default: accelerate current project
        accelerator.accelerate_current_project()

if __name__ == "__main__":
    main()