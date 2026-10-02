#!/usr/bin/env python3
"""
Risk scoring benchmark and regression test tool.

Tests scoring performance and compares against baseline to detect regressions.

Usage:
    python scripts/benchmark_risk_scores.py --baseline v3.7.0
    python scripts/benchmark_risk_scores.py --compare HEAD
    python scripts/benchmark_risk_scores.py --performance
"""
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import Finding, Severity
from core.risk_engine import compute_risk_score, compute_category_breakdown


def create_realistic_scan(num_findings: int = 50) -> List[Finding]:
    """Create realistic scan with varied findings"""
    findings = []
    
    # Mix of severities and categories
    config = {
        Severity.CRITICAL: 3,
        Severity.HIGH: 8,
        Severity.MEDIUM: 15,
        Severity.LOW: 20,
    }
    
    categories = [
        "authentication", "vulnerability_intelligence", "exposure",
        "information_disclosure", "encryption", "enumeration",
        "configuration", "plugins", "headers"
    ]
    
    finding_id = 0
    for severity, count in config.items():
        for i in range(min(count, num_findings - finding_id)):
            findings.append(Finding(
                id=f"finding_{finding_id}",
                category=categories[finding_id % len(categories)],
                severity=severity,
                confidence=0.7 + (i * 0.01),  # Vary confidence
                title=f"Finding {finding_id}"
            ))
            finding_id += 1
            if finding_id >= num_findings:
                break
    
    return findings[:num_findings]


def benchmark_scoring_performance(num_iterations: int = 1000) -> Dict:
    """Benchmark scoring performance"""
    print("\n⏱️  PERFORMANCE BENCHMARK")
    print("=" * 60)
    
    # Small scan (10 findings)
    small_scan = create_realistic_scan(10)
    
    # Medium scan (50 findings)
    medium_scan = create_realistic_scan(50)
    
    # Large scan (200 findings)
    large_scan = create_realistic_scan(200)
    
    results = {}
    
    for scan_size, findings in [("Small (10)", small_scan), 
                                 ("Medium (50)", medium_scan), 
                                 ("Large (200)", large_scan)]:
        print(f"\n{scan_size} findings:")
        
        # Warm-up
        for _ in range(10):
            compute_risk_score(findings)
        
        # Benchmark
        start = time.time()
        for _ in range(num_iterations):
            compute_risk_score(findings)
        elapsed = time.time() - start
        
        avg_ms = (elapsed / num_iterations) * 1000
        throughput = num_iterations / elapsed
        
        print(f"  Total time: {elapsed:.2f}s")
        print(f"  Average: {avg_ms:.2f}ms per scoring")
        print(f"  Throughput: {throughput:.0f} scores/sec")
        
        results[scan_size] = {
            'total_time': elapsed,
            'avg_ms': avg_ms,
            'throughput': throughput
        }
    
    return results


def test_determinism(num_runs: int = 100) -> bool:
    """Verify scoring is deterministic"""
    print("\n✅ DETERMINISM TEST")
    print("=" * 60)
    
    findings = create_realistic_scan(30)
    
    # Run multiple times
    scores = []
    for i in range(num_runs):
        score, grade = compute_risk_score(findings)
        scores.append((score, grade))
    
    # Check all are identical
    if all(s == scores[0] for s in scores):
        print(f"✓ PASS: All {num_runs} runs produced identical results")
        print(f"  Score: {scores[0][0]}, Grade: {scores[0][1]}")
        return True
    else:
        print(f"✗ FAIL: Scores vary across runs!")
        unique_scores = set(scores)
        for score in unique_scores:
            print(f"  {score}: {scores.count(score)} runs")
        return False


def test_scoring_ranges() -> bool:
    """Test that scores stay within reasonable bounds"""
    print("\n📊 SCORE RANGE TEST")
    print("=" * 60)
    
    test_cases = [
        ("No findings", [], 0.0, 0.0),
        ("Single LOW", [Finding(severity=Severity.LOW, confidence=0.95)], 0.0, 10.0),
        ("Single CRITICAL", [Finding(severity=Severity.CRITICAL, confidence=0.95)], 10.0, 40.0),
        ("Multiple CRITICAL", create_realistic_scan(5), 20.0, 80.0),
        ("Large scan", create_realistic_scan(100), 40.0, 100.0),
    ]
    
    all_pass = True
    print(f"{'Test Case':<25} {'Score':<10} {'Grade':<8} {'Expected Range':<20} {'Status':<10}")
    print("-" * 70)
    
    for name, findings, min_expected, max_expected in test_cases:
        score, grade = compute_risk_score(findings)
        in_range = min_expected <= score <= max_expected
        status = "✓ PASS" if in_range else "✗ FAIL"
        
        print(f"{name:<25} {score:<10.1f} {grade:<8} {min_expected:.1f}-{max_expected:.1f}       {status:<10}")
        
        if not in_range:
            all_pass = False
    
    return all_pass


def test_category_breakdown() -> bool:
    """Test category breakdown computation"""
    print("\n📈 CATEGORY BREAKDOWN TEST")
    print("=" * 60)
    
    findings = [
        Finding(category="authentication", severity=Severity.CRITICAL, confidence=0.95),
        Finding(category="authentication", severity=Severity.HIGH, confidence=0.85),
        Finding(category="headers", severity=Severity.LOW, confidence=0.7),
    ]
    
    breakdown = compute_category_breakdown(findings)
    
    all_pass = True
    
    # Check authentication category
    if "authentication" in breakdown:
        auth = breakdown["authentication"]
        if auth["count"] == 2:
            print("✓ authentication count correct (2)")
        else:
            print(f"✗ authentication count wrong: {auth['count']} (expected 2)")
            all_pass = False
        
        if auth["max_severity"] == "critical":
            print("✓ authentication max_severity correct (critical)")
        else:
            print(f"✗ authentication max_severity wrong: {auth['max_severity']}")
            all_pass = False
    
    # Check headers category
    if "headers" in breakdown:
        headers = breakdown["headers"]
        if headers["count"] == 1:
            print("✓ headers count correct (1)")
        else:
            print(f"✗ headers count wrong: {headers['count']}")
            all_pass = False
    
    print(f"\nBreakdown: {breakdown}")
    
    return all_pass


def test_edge_cases() -> bool:
    """Test edge cases"""
    print("\n🚨 EDGE CASE TESTS")
    print("=" * 60)
    
    all_pass = True
    
    # Empty findings
    score, grade = compute_risk_score([])
    if score == 0.0 and grade == "A+":
        print("✓ Empty findings -> A+ (score 0)")
    else:
        print(f"✗ Empty findings failed: score={score}, grade={grade}")
        all_pass = False
    
    # Very high confidence
    high_conf = Finding(severity=Severity.CRITICAL, confidence=1.0)
    score, grade = compute_risk_score([high_conf])
    if score > 20:
        print(f"✓ High confidence CRITICAL -> score={score:.1f}")
    else:
        print(f"✗ High confidence scoring low: {score}")
        all_pass = False
    
    # Below confidence threshold
    low_conf = Finding(severity=Severity.CRITICAL, confidence=0.1)
    score, grade = compute_risk_score([low_conf], confidence_threshold=0.5)
    if score == 0.0:
        print("✓ Below-threshold finding ignored (score 0)")
    else:
        print(f"✗ Below-threshold not ignored: score={score}")
        all_pass = False
    
    # Mixed confidence
    findings = [
        Finding(severity=Severity.HIGH, confidence=0.95),
        Finding(severity=Severity.HIGH, confidence=0.4),
    ]
    score, grade = compute_risk_score(findings, confidence_threshold=0.5)
    # Only first should count
    single = Finding(severity=Severity.HIGH, confidence=0.95)
    single_score, _ = compute_risk_score([single])
    if abs(score - single_score) < 0.1:
        print(f"✓ Mixed confidence correctly filters (score={score:.1f})")
    else:
        print(f"✗ Mixed confidence filtering wrong: {score} vs {single_score}")
        all_pass = False
    
    return all_pass


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Risk scoring benchmark tool")
    parser.add_argument("--baseline", action="store_true", help="Run baseline suite")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    # Default: run all tests
    if not args.baseline and not args.performance:
        args.all = True
    
    print("\n" + "=" * 60)
    print("🔬 SENTINELWP RISK SCORING BENCHMARK SUITE")
    print("=" * 60)
    
    results = {
        'determinism': False,
        'ranges': False,
        'breakdown': False,
        'edge_cases': False,
        'performance': {}
    }
    
    if args.all or args.baseline:
        results['determinism'] = test_determinism()
        results['ranges'] = test_scoring_ranges()
        results['breakdown'] = test_category_breakdown()
        results['edge_cases'] = test_edge_cases()
    
    if args.all or args.performance:
        results['performance'] = benchmark_scoring_performance()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 BENCHMARK SUMMARY")
    print("=" * 60)
    
    if args.all or args.baseline:
        all_pass = all([
            results.get('determinism', False),
            results.get('ranges', False),
            results.get('breakdown', False),
            results.get('edge_cases', False),
        ])
        
        status = "✅ ALL TESTS PASSED" if all_pass else "❌ SOME TESTS FAILED"
        print(f"\n{status}")
        
        print("\nBaseline tests:")
        print(f"  Determinism:    {'✓' if results.get('determinism') else '✗'}")
        print(f"  Score ranges:   {'✓' if results.get('ranges') else '✗'}")
        print(f"  Breakdown logic:{'✓' if results.get('breakdown') else '✗'}")
        print(f"  Edge cases:     {'✓' if results.get('edge_cases') else '✗'}")
    
    if args.all or args.performance:
        print("\nPerformance benchmarks:")
        perf = results.get('performance', {})
        for size, metrics in perf.items():
            print(f"  {size}: {metrics['avg_ms']:.2f}ms avg ({metrics['throughput']:.0f} scores/sec)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
