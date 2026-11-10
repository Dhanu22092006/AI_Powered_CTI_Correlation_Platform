def calculate_risk(ioc_count: int, source_count: int, has_cve: bool, recency_bonus: int = 0):
    # Transparent heuristic prioritization score, NOT a probability.
    factors = {
        "indicator_count": min(ioc_count * 8, 32),
        "independent_sources": min(max(source_count - 1, 0) * 10, 30),
        "cve_context": 18 if has_cve else 0,
        "recency": min(max(recency_bonus, 0), 20),
    }
    score = min(sum(factors.values()), 100)
    severity = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {"score": score, "severity": severity, "factors": factors, "method": "transparent heuristic; not a probability"}
