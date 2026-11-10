import httpx
from .config import settings

async def fetch_nvd(limit: int = 20):
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    params = {"resultsPerPage": min(max(limit, 1), 100)}
    async with httpx.AsyncClient(timeout=25) as client:
        response = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()
    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(metric_key, [])
            if arr:
                data = arr[0].get("cvssData", {})
                cvss = {"score": data.get("baseScore"), "severity": data.get("baseSeverity")}
                break
        results.append({"cve_id": cve.get("id"), "description": desc, "cvss": cvss, "published": cve.get("published"), "source": "NVD"})
    return results

async def fetch_otx(limit: int = 10):
    if not settings.otx_api_key:
        raise ValueError("OTX_API_KEY is not configured")
    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    async with httpx.AsyncClient(timeout=25) as client:
        response = await client.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers, params={"limit": min(limit, 50)})
        response.raise_for_status()
        return response.json()
