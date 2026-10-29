#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 获取 VPN Gate 原始节点 (官方 api/iphone CSV + GitHub 预解析镜像, 两份合并去重)
     也可用 EXTRA_SSTP 追加额外 host:port 清单
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# 本站 GitHub Pages 基址 (所有生成文件的对外地址都基于它)
PAGES_BASE = os.environ.get("PAGES_BASE", "https://liuy90866-alt.github.io/V2").rstrip("/")

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
# 官方接口失败时的回退数据源: 预解析 JSON 镜像 (字段与官方 CSV 同源)
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (只认本账号自己的 Worker)。
# 主域失败时回退 workers.dev 原地址; CHECK_WORKER 若指向第三方会被忽略。
OWN_WORKER_URL = "https://autumn-sea-4d92.liuy90866.workers.dev/check?sstp=vpn:vpn@"
WORKER_ALLOWED_SUFFIX = os.environ.get("WORKER_ALLOWED_SUFFIX", ".liuy90866.workers.dev")


def _is_own_worker(url):
    """判断 Worker 地址是否属于本账号 (workers.dev 子域或显式允许的后缀)。"""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    suffix = WORKER_ALLOWED_SUFFIX.strip().lower()
    return bool(host) and (host == suffix.lstrip(".") or host.endswith(suffix))


WORKER_CHECK_URLS = []
for _candidate in (os.environ.get("CHECK_WORKER"), OWN_WORKER_URL):
    if not _candidate:
        continue
    if not _is_own_worker(_candidate):
        print(f"[WARN] 忽略非本账号 Worker 地址: {_candidate}", file=sys.stderr)
        continue
    if _candidate not in WORKER_CHECK_URLS:
        WORKER_CHECK_URLS.append(_candidate)
if not WORKER_CHECK_URLS:
    die("没有可用的自有 Worker 地址")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))   # 与 Worker 网页端一致的并发模型
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))          # 单请求客户端超时 (秒)
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时

# 全球节点池 (VPN Gate 滚动池镜像): 只取 Cloudflare Worker 预探测可达的节点
POOL_ENABLED = os.environ.get("POOL_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off")
POOL_PER_COUNTRY = max(0, int(os.environ.get("POOL_PER_COUNTRY", "8")))
POOL_URL = os.environ.get(
    "POOL_URL",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/pool/servers.json",
)
POOL_FALLBACK_URL = os.environ.get(
    "POOL_FALLBACK_URL",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/pool/servers.json",
)

# 节点延迟 = 优选入口域名的实测延迟 (bestcf CSV 的「延迟(ms)」列), 默认只保留 ≤300ms。
# Worker 返回的 SSTP 握手耗时另存为 handshake_ms, 不参与过滤。
MAX_LATENCY_MS = int(os.environ.get("MAX_LATENCY_MS", "300"))
# 优选入口只取最快的 N 个 (0 = 不限)
EDGE_MAX_ENTRIES = max(0, int(os.environ.get("EDGE_MAX_ENTRIES", "300")))
# 最终节点数上限, 按延迟从快到慢保留 (0 = 不限)
MAX_NODES = max(0, int(os.environ.get("MAX_NODES", "300")))
# 优选入口域名自身的延迟上限 (bestcf CSV 的「延迟(ms)」列); 0 = 不限制
MAX_ENTRY_LATENCY_MS = int(os.environ.get("MAX_ENTRY_LATENCY_MS", "300"))

PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
    "BD": "孟加拉国", "PE": "秘鲁", "CR": "哥斯达黎加", "IR": "伊朗", "VE": "委内瑞拉",
    "LA": "老挝", "KH": "柬埔寨", "BN": "文莱", "PK": "巴基斯坦", "NG": "尼日利亚",
    "KE": "肯尼亚", "TZ": "坦桑尼亚", "GH": "加纳", "ET": "埃塞俄比亚", "DZ": "阿尔及利亚",
    "MA": "摩洛哥", "TN": "突尼斯", "JO": "约旦", "KW": "科威特", "QA": "卡塔尔",
    "OM": "阿曼", "BH": "巴林", "LB": "黎巴嫩", "IQ": "伊拉克", "AZ": "阿塞拜疆",
    "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦", "TM": "土库曼斯坦", "AF": "阿富汗",
    "MV": "马尔代夫", "BT": "不丹", "FJ": "斐济", "PG": "巴布亚新几内亚", "GU": "关岛",
    "PR": "波多黎各", "DO": "多米尼加", "GT": "危地马拉", "HN": "洪都拉斯", "SV": "萨尔瓦多",
    "NI": "尼加拉瓜", "PA": "巴拿马", "EC": "厄瓜多尔", "BO": "玻利维亚", "PY": "巴拉圭",
    "UY": "乌拉圭", "CU": "古巴", "JM": "牙买加", "TT": "特立尼达和多巴哥", "BS": "巴哈马",
    "BB": "巴巴多斯", "BZ": "伯利兹", "HT": "海地", "SR": "苏里南", "GY": "圭亚那",
    "LU": "卢森堡", "IS": "冰岛", "MT": "马耳他", "CY": "塞浦路斯", "AL": "阿尔巴尼亚",
    "BA": "波黑", "MK": "北马其顿", "ME": "黑山", "XK": "科索沃", "MO": "澳门",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """返回 (rows, source)。rows: [{host, ip, country_long, country_short, config_b64}]
    官方 API 与 GitHub 镜像各取一份并合并去重 (两边节点重合度很低, 合并后数量约翻倍)。
    只要有一个来源成功就继续; 两个都失败 -> die (exit 1)。"""
    def _fetch_official():
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if not rows:
            raise RuntimeError("官方 API 返回 0 行数据")
        return rows

    def _fetch_mirror():
        log("VPN GATE", f"获取镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if not rows:
            raise RuntimeError("镜像返回 0 行数据")
        return rows

    rows, sources = [], []
    for label, fetch in (("vpngate.net/api/iphone", _fetch_official), ("github-mirror", _fetch_mirror)):
        try:
            got = fetch()
        except Exception as exc:
            log("VPN GATE", f"{label} 获取失败: {exc}")
            continue
        log("VPN GATE", f"{label} 获取到 {len(got)} 个原始节点")
        rows.extend(got)
        sources.append(label)

    if not rows:
        die("VPN Gate 官方 API 与镜像均不可用, 数据源完全失败 (不生成空结果, 本次运行判定失败)")

    merged, seen = [], set()
    for row in rows:
        key = (row["host"].lower(), row["ip"])
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    log("VPN GATE", f"多源合并去重: {len(merged)} 个原始节点 (来源: {' + '.join(sources)})")
    return merged, "+".join(sources)


def fetch_extra_sstp():
    """读取 EXTRA_SSTP 里的额外 SSTP 节点清单 (逗号/换行分隔的 URL 或本地文件)。
    支持 host、host:port、sstp://user:pass@host:port、host:port#名字,
    以及 `=== Japan (JP) - 195 servers ===` 这类国家分组标题。"""
    spec = os.environ.get("EXTRA_SSTP", "").strip()
    if not spec:
        return []
    sources = [s.strip() for s in re.split(r"[,;\n]", spec) if s.strip()]
    nodes, seen = [], set()
    for src in sources:
        try:
            if src.startswith(("http://", "https://")):
                resp = requests.get(src, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                text = resp.text
            elif os.path.isfile(src):
                with open(src, encoding="utf-8-sig", errors="replace") as fh:
                    text = fh.read()
            else:
                log("EXTRA", f"额外节点源不存在, 跳过: {src}")
                continue
        except Exception as exc:
            log("EXTRA", f"读取额外节点源失败 {src}: {exc}")
            continue

        country, code, count = "", "", 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            sec = re.match(r"^=+\s*(.+?)\s*\(([A-Za-z]{2})\)", line)
            if sec:
                country, code = sec.group(1).strip(), sec.group(2).upper()
                continue
            candidate = re.sub(r"^(sstp|https?)://([^@/]*@)?", "", line.split("#", 1)[0].strip(), flags=re.I)
            m = re.match(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9_.\-]*)(?::(\d{1,5}))?", candidate)
            if not m:
                continue
            host = m.group(1).strip("[]").lower()
            port = int(m.group(2) or 443)
            if not host or not (1 <= port <= 65535) or (host, port) in seen:
                continue
            if "." not in host and ":" not in host:
                continue
            seen.add((host, port))
            nodes.append({
                "host": host,
                "port": port,
                "ip": "",
                "country": country,
                "country_code": code,
            })
            count += 1
        log("EXTRA", f"{src} -> {count} 个额外节点")
    if nodes:
        log("EXTRA", f"额外节点合计: {len(nodes)}")
    return nodes


def fetch_pool_nodes():
    """从 VPN Gate 滚动节点池取全球节点, 每个国家最多 POOL_PER_COUNTRY 个。
    只保留 tcp_probe.status == "reachable" 的节点 (已由 Cloudflare Worker 预探测可连),
    因此不会把几千个离线节点全部丢给检测接口。"""
    if not POOL_ENABLED or POOL_PER_COUNTRY <= 0:
        return []
    data = None
    for url in (POOL_URL, POOL_FALLBACK_URL):
        if not url:
            continue
        try:
            log("POOL", f"获取全球节点池: {url}")
            if os.path.isfile(url):
                with open(url, encoding="utf-8") as fh:
                    data = json.load(fh)
            else:
                resp = requests.get(url, timeout=max(HTTP_TIMEOUT, 120), headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                data = resp.json()
            break
        except Exception as exc:
            log("POOL", f"节点池获取失败, 尝试下一个: {exc}")
    if data is None:
        log("POOL", "节点池不可用, 跳过 (不影响其它数据源)")
        return []

    pool = data.get("servers") if isinstance(data, dict) else data
    if not isinstance(pool, list):
        log("POOL", "节点池格式不符, 跳过")
        return []

    by_country = {}
    for item in pool:
        if (item.get("tcp_probe") or {}).get("status") != "reachable":
            continue
        host = str(item.get("hostname") or "").strip().lower()
        if not host or host.count(".") > 1:
            continue
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        port = 0
        for target in item.get("probe_targets") or []:
            try:
                port = int(target.get("port") or 0)
            except (TypeError, ValueError, AttributeError):
                port = 0
            if 0 < port <= 65535:
                break
        if not port:
            continue
        code = str(item.get("country_code") or "").upper()
        name = str(item.get("country_name") or "").strip()
        by_country.setdefault(code, []).append({
            "host": host,
            "port": port,
            "ip": str(item.get("ip") or ""),
            "country": name,
            "country_code": code,
            "_score": int(item.get("score") or 0),
        })

    nodes = []
    for items in by_country.values():
        items.sort(key=lambda n: -n["_score"])
        for node in items[:POOL_PER_COUNTRY]:
            node.pop("_score", None)
            nodes.append(node)
    log("POOL", f"全局节点池: {len(by_country)} 个国家, 取 {len(nodes)} 个 (每国 ≤ {POOL_PER_COUNTRY})")
    return nodes


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    """把原始行转成 SSTP 节点: 解码 OpenVPN 配置, 仅保留 proto tcp + remote 端口。
    host 统一为 <short>.opengw.net 形式; 返回去重前的节点列表。"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # 无 TCP 入口 -> 不是 SSTP 可用节点, 丢弃
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def check_one(node, session):
    """调用 Worker 检测单节点。返回节点+检测结果的合并 dict。
    单节点失败 (网络错误/非 200/坏 JSON) 不会抛出, 统一记 success=False。"""
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    errors = []
    try:
        for worker_url in WORKER_CHECK_URLS:
            url = worker_url + quote(f"{node['host']}:{node['port']}", safe="")
            try:
                r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
                if r.status_code != 200:
                    errors.append(f"{worker_url} -> HTTP {r.status_code}")
                    continue
                break
            except Exception as exc:
                errors.append(f"{worker_url} -> {type(exc).__name__}: {exc}")
        else:
            out["error"] = "; ".join(errors)
            out["worker_error"] = True
            return out

        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    """32 并发 (与网页端一致)。单节点失败不影响整体; 但区分'节点不可用'与'Worker 异常'。"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    def _num(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    success = [r for r in results if r.get("success")]

    # 给每个节点分配优选入口域名 (hosts.txt 里同一节点会用到这几行)。
    # 页面/清单里的「延迟」改用入口域名的实测延迟 (bestcf CSV 的 延迟(ms)),
    # Worker 的 SSTP 握手耗时单独存到 handshake_ms。
    edge = EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    if EDGE_LATENCY:
        measured = sorted((e for e in edge if e in EDGE_LATENCY), key=lambda e: EDGE_LATENCY[e])
        if EDGE_MAX_ENTRIES > 0:
            measured = measured[:EDGE_MAX_ENTRIES]
        if measured:
            edge = measured  # 只用有实测延迟的入口, 保证每个节点延迟都能算出来
    copies = max(1, min(EDGE_COPIES, len(edge)))
    entry_known = bool(EDGE_LATENCY)
    idx = 0
    for node in sorted(success, key=lambda x: (str(x.get("country_code") or "?"), str(x.get("host") or ""))):
        picks = []
        for _ in range(copies):
            picks.append(edge[idx % len(edge)])
            idx += 1
        latencies = [EDGE_LATENCY[e] for e in picks if EDGE_LATENCY.get(e)]
        node["entries"] = picks
        node["entry"] = picks[0]
        node["entry_latency_ms"] = min(latencies) if latencies else None
        node["handshake_ms"] = node.get("latency_ms")
        if latencies:
            node["latency_ms"] = min(latencies)

    available, slow = [], 0
    for r in success:
        lat = _num(r.get("latency_ms"))
        if MAX_LATENCY_MS > 0 and entry_known and (lat is None or lat > MAX_LATENCY_MS):
            slow += 1
            continue
        available.append(r)

    trimmed = 0
    if MAX_NODES > 0 and len(available) > MAX_NODES:
        available.sort(
            key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or "")
        )
        trimmed = len(available) - MAX_NODES
        available = available[:MAX_NODES]

    countries = {}
    for n in available:
        exit_info = n.get("exit") or {}
        c = n["country"] or exit_info.get("country") or "未知"
        code = n["country_code"] or exit_info.get("country_code") or "?"
        countries.setdefault(c, {"code": code, "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(success),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
        "slow_filtered": slow,
        "trimmed": trimmed,
        "max_latency_ms": MAX_LATENCY_MS,
        "max_nodes": MAX_NODES,
        "latency_metric": "entry" if entry_known else "handshake",
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URLS[0],
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", f"{PAGES_BASE}/chains.txt")


def build_chains_text(data):
    """生成 edgetunnel 链式代理清单: 按国家分组, 每国编号固定, 住宅优先, 延迟升序。
    每行 = 「名字 + $sstp://vpn:vpn@host:port」, 名字不变, 指令每 30 分钟自动换。"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (cname if cname and cname != "?" else code)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 入口地址池: 客户端直连 Cloudflare 的优选 IP:端口 (循环分配给每个国家节点当入口)
# 可通过环境变量 EDGE_HOSTS 覆盖 (逗号分隔)
DEFAULT_EDGE_HOSTS = [
    'hy.aaw.qzz.io:8443',
    'dx.doi.org:8443',
    'ali.nonull.pp.ua:443',
    'auto.dolby.dpdns.org:443',
    'cdn.cnno.de:443',
    'saas.sin.fan:443',
    'linkvertise.com:8443',
    'kali.download:8443',
    'sellerlogic.com:8443',
    'www.hugedomains.com:8443',
    'pure.coupert.com:8443',
    'garuda-indonesia.com:8443',
    'resources.biginterview.com:8443',
    'cdnjs.loli.net:8443',
    'js.org:8443',
    'grass.io:8443',
    'db-ip.com:8443',
    'sanctuarywealth.com:8443',
    'informahealthcare.com:8443',
    'buyshoes.shop:8443',
    'ip.sb:8443',
    'duckybot.xyz:8443',
    'i.pages.dev:8443',
    'www.trumpinternationalrealty.com:8443',
    'bitsight.com:8443',
    'centerofthewest.org:8443',
    'leawo.org:8443',
    'www.petronaftco.com:8443',
    'nodejs.org:8443',
    'academy.mastercard.com:8443',
    'funko.com:8443',
    'moondroplab.com:8443',
    'www.trumpgolf.com:8443',
    'rocketreach.co:8443',
    's.bookcdn.com:8443',
    'form.assaabloy.com:8443',
    'zoominfo.com:8443',
    'www.meteorelectrical.com:8443',
    'www.copilot.com:8443',
    'pubs.acs.org:8443',
    'dev.graco.com:8443',
    'fonts.cdnfonts.com:8443',
    'emos.prlo.de:8443',
    'registry.yarnpkg.com:8443',
    'elegantthemes.com:8443',
    'www.jsdelivr.com:8443',
    'www.ox.ac.uk:8443',
    'support.communilink.net:8443',
    'dogechain.info:8443',
    'uptimerobot.com:8443',
    'wallpaperflare.com:8443',
    'alternativeto.net:8443',
    'lose.edu.eu.org:8443',
    'go1.dematic.com:8443',
    'coreweave.com:8443',
    'qoj.ac:8443',
    'www.ventusky.com:8443',
    'www.donaldjtrump.com:8443',
    'registry.npmjs.org:8443',
    'ncc.gov.ng:8443',
    'pt.btschool.club:8443',
    'zen-browser.app:8443',
    'www.stayaka.com:8443',
    'www.apnic.net:8443',
    'iskills.com:8443',
    'hostinger.com:8443',
    'sourceforge.net:8443',
    'hentaiverse.org:8443',
    'encryptedsni.com:8443',
    'dexari.com:8443',
    'www.nomios.com:8443',
    'www.whoer.net:8443',
    'cozylife.app:8443',
    's.ee:8443',
    'codeforces.com:8443',
    'dnew.cc:8443',
    'development.ihg.com:8443',
    'mail.notion.com:8443',
    'a.pub.network:8443',
    'www.roche.com:8443',
    'www.gov.il:8443',
    'glitterx.cloud:8443',
    'ahrefs.com:8443',
    'www.bis.gov:8443',
    'www.visa.com.tw:8443',
    'unpkg.com:8443',
    'singapore.com:8443',
    'www.itedev.com:8443',
    'www.sofi.com:8443',
    'codexradar.com:8443',
    'page.mercer.com:8443',
    '53.fs1.hubspotusercontent-na1.net:8443',
    'serviceshub.samsclub.com:8443',
    'mfa.gov.ua:8443',
    'www.government.is:8443',
    'help.kolet.com:8443',
    'cdn.555586.xyz:8443',
    'cf.468123.xyz:8443',
    'digitalocean.com:8443',
    'jobsdb.com:8443',
    'rankmath.com:8443',
    'www.npmjs.com:8443',
    'www.dwk.com:8443',
    'store.ubisoft.com:8443',
    'www.transgenderdor.org:8443',
    'www.eccu.edu:8443',
    'crinacle.com:8443',
    'i.jpg.dog:8443',
    'kick.com:8443',
    'wppaunz.com:8443',
    'yong.m123.org:8443',
    'hzytjy.cn:8443',
    'clickhouse.com:8443',
    'spirol.com:8443',
    'aftership.com:8443',
    'cf.drxian.dpdns.org:8443',
    'versantstore.pearson.com:8443',
    'www.proxyrarbg.to:8443',
    'www.visa.com.sg:8443',
    'ping.pe:8443',
    'icook.tw:8443',
    'sunkist.com:8443',
    'static.elfsight.com:8443',
    'www.mediafire.com:8443',
    'prizepicks.com:8443',
    'investorrelations.medtronic.com:8443',
    'absen.com:8443',
    'brandstudio.com:8443',
    'example.com:8443',
    'japan.com:8443',
    'www.6i5.com:8443',
    'noc.one:8443',
    'cdn.sketch.com:8443',
    'my.vultr.com:8443',
    'salaryexpert.com:8443',
    'api2-ide.imgnxa.com:8443',
    'www.revechat.com:8443',
    '47bt.com:8443',
    'time.is:8443',
    'stlouiscountymo.gov:8443',
    'builtbybuffalo.com:8443',
    'www.broadcom.com:8443',
    '9mod.com:8443',
    'www.trump.com:8443',
    'hitcon.org:8443',
    'jquery.com:8443',
    'shen6011.pages.dev:8443',
    'markmonitor.com:8443',
    'kaspa.stream:8443',
    'cm.edu.kg:8443',
    'www.5199dy.com:8443',
    'journeys.com:8443',
    'cf2.996616.xyz:8443',
    'xiaoqi.de:8443',
    'www.owlgraphic.com:8443',
    'egov.uscis.gov:8443',
    'www.redboxtools.com:8443',
    'www.mastervolt.com:8443',
    'shabak.gov.il:8443',
    'www.whatismyip.com:8443',
    'bizclikmedia.com:8443',
    'cu.zxy88.eu.org:8443',
    'cloudflare-ip.mofashi.ltd:8443',
    'kickstarter.com:8443',
    'carpt.net:8443',
    'flightradar24.com:8443',
    'www.botafogo.com.br:8443',
    '2x.nz:8443',
    'skk.moe:8443',
    'www.lbl.gov:8443',
    'servo.org:8443',
    'moodle.org:8443',
    'sci-hub.al:8443',
    'mail.murata.com:8443',
    'autz.org:8443',
    'duggal.com:8443',
    'cdnjs.com:8443',
    'fictiv.com:8443',
    'mox.moxing.lol:8443',
    'oxylabs.io:8443',
    'hlevakha.gov.ua:8443',
    'www.timbuktutravel.com:8443',
    'assets.bizclikmedia.net:8443',
    'www.applevis.com:8443',
    'vegasgeek.com:8443',
    'dash.domain.digitalplat.org:8443',
    'aandd.co.jp:8443',
    'vayyar.com:8443',
    'aimagazine.com:8443',
    'ooo.0o0.ooo:8443',
    'scalacube.com:8443',
    'hashi.sbs:8443',
    'nodeloc.cc:8443',
    'vueframework.com:8443',
    'worldvectorlogo.com:8443',
    'snipaste1.speedip.eu.org:8443',
    'neko.cloudd.eu.org:8443',
    'www.sage.com:8443',
    'kwiat.com:8443',
    'easylist.to:8443',
    'www.chess.com:8443',
    'liziye.pages.dev:8443',
    'totoro.im:8443',
    'emos.best:8443',
    'www.doiting.com:8443',
    'esm.run:8443',
    'macked.app:8443',
    'cf.254301.xyz:8443',
    'ovpnspider.com:8443',
    'www.visa.com.au:8443',
    'www.moc.gov.tw:8443',
    'stonexbullion.com:8443',
    'syncfusion.com:8443',
    'bbs.alipansou.com:8443',
    'zabc.net:8443',
    'mogas.com:8443',
    'www.spacex.com:8443',
    'debot.ai:8443',
    'api.producthunt.com:8443',
    'cfip.1323123.xyz:8443',
    'auto.dolby.dpdns.org:8443',
    'ikankeji.com:8443',
    'rarbg.proxyninja.org:8443',
    'smapi.xystem138.com:8443',
    'nist.gov:8443',
    'packtpub.com:8443',
    'envato.com:8443',
    'seo.07yue.com:8443',
    'cf.0sm.com:8443',
    'www.trumpstruth.org:8443',
    'idc.urkeji.com:8443',
    'cdn.204910.best:8443',
    'cdn.7zz.cn:8443',
    'www.elysee.fr:8443',
    'investor.apple.com:8443',
    'www.loc.gov:8443',
    'www.scayle.com:8443',
    'www.acces-maroc.ma:8443',
    'cloudflare.tv:8443',
    'deepseek.com.hk:8443',
    'rargb.to:8443',
    'academy.7shifts.com:8443',
    'networksolutions.com:8443',
    'hubspot.com:8443',
    'zmxf.qzz.io:8443',
    'i.pixiv.re:8443',
    'kernelsu.com:8443',
    'mskcc.org:8443',
    'img.imgdd.com:8443',
    'cdn.nodeimage.com:8443',
    'vps.cheng2001.top:8443',
    'cn.vuejs.org:8443',
    'www.jp.pima.gov:8443',
    'www.wto.org:8443',
    'w3.org:8443',
    'griditapp.com:8443',
    'dl.macked.app:8443',
    'www.canadatype.com:8443',
    'www.pixelexperience.org:8443',
    'mvnrepository.com:8443',
    'neko.cloudflaree.eu.org:8443',
    'dianomi.com:8443',
    'sharray.net:8443',
    'dango.co:8443',
    'helium.computer:8443',
    'www.zendesk.com:8443',
    'www.postman.com:8443',
    'redis.io:8443',
    'cloudflare.idc.rocks:8443',
    'www.epicgames.com:8443',
    'jojolsj.jojojing.top:8443',
    'i.pixiv.nl:8443',
    'gateway.ipfsscan.io:8443',
    'ippure.com:8443',
    'webn.cc:8443',
    'ncdc.gov.ng:8443',
    'de.102198.xyz:8443',
    'moegirl.icu:8443',
    'eii.at:8443',
    'www.mfyx.cn:8443',
    '99.co:8443',
    'c-power.com.cn:8443',
    'saas.sin.fan:8443',
    'cdn.violet.vin:8443',
    'infinitemac.org:8443',
    'api.uniapi.io:8443',
    'www.visa.com.hk:8443',
    'www2.rarbggo.to:8443',
    'api.gzcrtw.com:8443',
    'xn--b6gac.eu.org:8443',
]
edge_hosts_raw = os.environ.get(
    "EDGE_HOSTS",
    ",".join(DEFAULT_EDGE_HOSTS),
)
EDGE_HOSTS = [h.strip() for h in edge_hosts_raw.split(",") if h.strip()]

# 入口域名 -> 实测延迟(ms); 纯文本清单没有延迟数据, 这里就没有对应项
EDGE_LATENCY = {}


def _load_edge_csv():
    """读取优选入口域名清单 (去重, 延迟小的排前面)。
    EDGE_CSV 可传文件路径或 URL, 多个用逗号分隔; 不传则自动找仓库里的
    bestcf*.csv / entries*.txt / edge*.txt。CSV 按「优选域名」列解析,
    纯文本则每行一个 host:port。"""
    spec = os.environ.get("EDGE_CSV", "").strip()
    if spec:
        paths = [p.strip() for p in re.split(r"[,;]", spec) if p.strip()]
    else:
        paths = []
        for pattern in ("bestcf-results*.csv", "bestcf*.csv", "entries*.txt", "edge*.txt"):
            for found in sorted(glob.glob(os.path.join(REPO_DIR, pattern))):
                if found not in paths:
                    paths.append(found)
    entries, seen, order, slow = [], set(), 0, 0
    for path in paths:
        try:
            if path.startswith(("http://", "https://")):
                resp = requests.get(path, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                text = resp.text
            elif os.path.isfile(path):
                with open(path, encoding="utf-8-sig", errors="replace") as fh:
                    text = fh.read()
            else:
                log("EDGE", f"入口域名清单不存在, 跳过: {path}")
                continue
        except Exception as exc:
            log("EDGE", f"读取入口域名清单失败 {path}: {exc}")
            continue

        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        is_csv = "," in first and ("域名" in first or "host" in first.lower() or "ip" in first.lower())
        if is_csv:
            items = []
            for row in csv.DictReader(io.StringIO(text)):
                host = (row.get("优选域名") or "").strip()
                if not host:
                    values = [v for v in row.values() if v]
                    host = (values[0] or "").strip() if values else ""
                try:
                    latency = float(row.get("延迟(ms)") or 0)
                except (TypeError, ValueError):
                    latency = 0.0
                items.append((latency, host))
        else:
            items = [(0.0, ln.split("#", 1)[0].strip()) for ln in text.splitlines()]

        for latency, host in items:
            if host.startswith(("#", "=")):
                continue
            if not host or host in seen or "://" in host or " " in host:
                continue
            if MAX_ENTRY_LATENCY_MS > 0 and latency > 0 and latency > MAX_ENTRY_LATENCY_MS:
                slow += 1
                continue
            seen.add(host)
            order += 1
            entries.append((latency, order, host))
            if latency > 0:
                EDGE_LATENCY[host] = latency
    entries.sort(key=lambda item: (item[0] <= 0, item[0], item[1]))
    if EDGE_MAX_ENTRIES > 0 and len(entries) > EDGE_MAX_ENTRIES:
        log("EDGE", f"只保留最快的 {EDGE_MAX_ENTRIES} 个入口 (共 {len(entries)} 个)")
        entries = entries[:EDGE_MAX_ENTRIES]
    if entries:
        log("EDGE", f"载入优选入口域名: {len(entries)} 个")
    if slow:
        log("EDGE", f"入口延迟 > {MAX_ENTRY_LATENCY_MS}ms 已剔除: {slow} 个")
    return [host for _, _, host in entries]


# 把 bestcf CSV 的入口域名并入候选池 (CSV 实测最快, 排在最前)
EDGE_CSV_HOSTS = _load_edge_csv()
if EDGE_CSV_HOSTS:
    _merged, _seen = list(EDGE_CSV_HOSTS), set(EDGE_CSV_HOSTS)
    for _host in EDGE_HOSTS:
        if _host not in _seen:
            _seen.add(_host)
            _merged.append(_host)
    EDGE_HOSTS = _merged

# 每个 SSTP 节点生成几个入口行 (1 = 旧行为; 数字越大清单行数越多)
EDGE_COPIES = max(1, int(os.environ.get("EDGE_COPIES", "3")))

HOSTS_URL = os.environ.get("HOSTS_URL", f"{PAGES_BASE}/hosts.txt")


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字固定, 底下 SSTP 节点每 30 分钟自动换。"""
    countries = data["countries"]
    # 入口: bestcf CSV + 内置优选域名; 可用 HOSTS_ENTRY 覆盖(逗号分隔)
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    copies = max(1, min(EDGE_COPIES, len(edge)))
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        f"# 入口域名 {len(edge)} 个 (bestcf CSV 优先, 按延迟排序), 每个节点 {copies} 个入口",
        f"# 延迟 = 入口域名实测延迟, 上限 {MAX_LATENCY_MS}ms (握手耗时见 data.json 的 handshake_ms)" if MAX_LATENCY_MS > 0 else "# 延迟 = 入口域名实测延迟 (不限)",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (cname if cname and cname != "?" else code)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 × {copies} 入口 = {int(grp['count']) * copies} 行"
            f" (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            assigned = n.get("entries") or []
            for c in range(copies):
                if c < len(assigned):
                    entry = assigned[c]
                else:
                    entry = edge[idx % len(edge)]
                    idx += 1
                suffix = "" if c == 0 else f"-{c + 1}"
                lines.append(
                    f"{entry}#{zh}-住宅-{i:02d}{suffix}$sstp://vpn:vpn@{n['host']}:{n['port']}"
                )
        for i, n in enumerate(dc_nodes, 1):
            assigned = n.get("entries") or []
            for c in range(copies):
                if c < len(assigned):
                    entry = assigned[c]
                else:
                    entry = edge[idx % len(edge)]
                    idx += 1
                suffix = "" if c == 0 else f"-{c + 1}"
                lines.append(
                    f"{entry}#{zh}-机房-{i:02d}{suffix}$sstp://vpn:vpn@{n['host']}:{n['port']}"
                )
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
EDT_UUID = os.environ.get("EDT_UUID", "1f06f039-94f1-4ec0-9864-b7aaab41fee4")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "muddy-sun-cb31.liuy90866.workers.dev")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", f"{PAGES_BASE}/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    填进 edgetunnel 后台「订阅链接」URL, 客户端定时拉取即可自动轮换。"""
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {SUB_URL}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 链式代理(编码在 path)每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (cname if cname and cname != "?" else code)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel 链式代理清单 (固定 URL, 方案一: 名字不变、指令自动换)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # 可直接粘贴进后台「自定义优选IP」框的清单 (入口地址#名字$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # 完整 vless:// 订阅 (填进后台「订阅链接」URL, 客户端自动轮换)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    # 官方数据里的英文国家名做标准名, 避免同一国家被拆成 "Korea Republic of" / "South Korea"
    name_by_code = {}
    for row in rows:
        code = (row.get("country_short") or "").upper()
        if code and code not in name_by_code:
            name_by_code[code] = (row.get("country_long") or "").strip()
    for label, extra_nodes in (("extra", fetch_extra_sstp()), ("pool", fetch_pool_nodes())):
        if extra_nodes:
            for node in extra_nodes:
                alias = name_by_code.get(node.get("country_code") or "")
                if alias:
                    node["country"] = alias
            sstp_nodes.extend(extra_nodes)
            raw_count += len(extra_nodes)
            source += f"+{label}"
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source)
    if MAX_LATENCY_MS > 0:
        log("RESULT", f"延迟过滤: ≤ {MAX_LATENCY_MS}ms 保留, 丢弃 {data['stats']['slow_filtered']} 个")
    if data["stats"]["trimmed"]:
        log("RESULT", f"节点数超过 {MAX_NODES}, 只保留最快的 {MAX_NODES} 个 (丢弃 {data['stats']['trimmed']} 个)")
    log("RESULT", f"可用节点: {data['stats']['success']}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, chains_path, hosts_path, sub_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(chains_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
