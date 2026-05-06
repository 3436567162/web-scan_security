"""CORS (Cross-Origin Resource Sharing) misconfiguration detection."""

from .crawler import fetch


def check_cors(url):
    """Check for CORS misconfigurations."""
    results = []

    # Test 1: Check with arbitrary Origin
    resp = fetch(url, headers={
        "Origin": "https://evil.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    })
    if resp is None:
        return results

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        results.append({
            "type": "medium",
            "title": "CORS配置: 允许任意来源",
            "detail": "Access-Control-Allow-Origin 为 *，允许任意跨域请求",
        })
    elif acao == "https://evil.com":
        if acac.lower() == "true":
            results.append({
                "type": "high",
                "title": "CORS配置: 反射Origin + 允许凭证",
                "detail": (
                    "服务器将任意Origin反射回Access-Control-Allow-Origin，"
                    "且允许携带凭证(Credentials)。攻击者可窃取用户敏感数据。"
                ),
            })
        else:
            results.append({
                "type": "medium",
                "title": "CORS配置: 反射任意Origin",
                "detail": "服务器将请求中的Origin原样反射回Access-Control-Allow-Origin",
            })
    elif acao == "null":
        results.append({
            "type": "medium",
            "title": "CORS配置: 允许null Origin",
            "detail": "Access-Control-Allow-Origin 为 null，来自iframe或本地文件的请求可跨域访问",
        })

    # Test 2: Check with null Origin
    resp_null = fetch(url, headers={"Origin": "null"})
    if resp_null is not None:
        acao_null = resp_null.headers.get("Access-Control-Allow-Origin", "")
        if acao_null == "null":
            results.append({
                "type": "medium",
                "title": "CORS配置: 接受null Origin",
                "detail": "服务器接受 Origin: null 的跨域请求，可从本地文件或sandboxed iframe利用",
            })

    # Test 3: Check with subdomain
    from urllib.parse import urlparse
    parsed = urlparse(url)
    subdomain_origin = f"https://evil.{parsed.netloc}"
    resp_sub = fetch(url, headers={"Origin": subdomain_origin})
    if resp_sub is not None:
        acao_sub = resp_sub.headers.get("Access-Control-Allow-Origin", "")
        if acao_sub == subdomain_origin:
            results.append({
                "type": "low",
                "title": "CORS配置: 接受子域名Origin",
                "detail": f"服务器接受子域名Origin: {subdomain_origin}，可能存在子域名劫持风险",
            })

    if not results:
        # Check if CORS is even configured
        if not acao:
            results.append({
                "type": "pass",
                "title": "CORS检查通过",
                "detail": "未配置CORS或未发现明显配置错误",
            })
        else:
            results.append({
                "type": "pass",
                "title": "CORS配置正常",
                "detail": f"Access-Control-Allow-Origin: {acao}，配置合理",
            })

    return results
