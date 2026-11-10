from app.extract import extract_iocs
from app.scoring import calculate_risk

def test_extracts_iocs():
    text = "See CVE-2021-44228, IP 192.0.2.10, domain example.test and SHA256 " + "a"*64
    found = extract_iocs(text)
    values = {x["value"] for x in found}
    assert "CVE-2021-44228" in values
    assert "192.0.2.10" in values
    assert "example.test" in values
    assert "a"*64 in values

def test_risk_is_bounded_and_explained():
    result = calculate_risk(5, 3, True, 10)
    assert 0 <= result["score"] <= 100
    assert result["severity"] in {"low","medium","high","critical"}
    assert "factors" in result
