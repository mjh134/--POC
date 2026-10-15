#!/usr/bin/env python3
"""
POC Base Framework
=======================
轻量级 POC/EXP 编写框架的 Python 基类。

框架核心概念:
    ScanSteps     → check() 方法
    ExploitSteps  → exploit() 方法
    Request       → _make_request() HTTP请求
    ResponseTest  → _check_response() 响应断言
    SetVariable   → 实例变量传递 + _replace_variables() 模板替换
"""

import json
import sys
import argparse
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CheckResult:
    """检查结果"""
    def __init__(self, vulnerable: bool, info: str = "", detail: str = ""):
        self.vulnerable = vulnerable
        self.info = info or ("漏洞存在" if vulnerable else "未发现漏洞")
        self.detail = detail

    def __bool__(self):
        return self.vulnerable

    def __str__(self):
        status = "✅ VULNERABLE" if self.vulnerable else "❌ NOT VULNERABLE"
        return f"[{status}] {self.info}\n{self.detail}" if self.detail else f"[{status}] {self.info}"


class ExploitResult:
    """利用结果"""
    def __init__(self, success: bool, output: str = ""):
        self.success = success
        self.output = output

    def __bool__(self):
        return self.success

    def __str__(self):
        status = "✅ EXPLOIT SUCCEEDED" if self.success else "❌ EXPLOIT FAILED"
        return f"[{status}]\n{self.output}" if self.output else f"[{status}]"


class BasePOC:
    """
    POC 基类 — 所有 POC 继承此类

    子类需覆盖:
    - name, description, product, vuln_type 等元信息
    - check() 方法实现检测逻辑
    - exploit() 方法实现利用逻辑 (如有)
    """

    # ============ 漏洞元信息 (子类覆盖) ============
    name: str = ""                      # 漏洞名称
    description: str = ""               # 漏洞描述
    product: str = ""                   # 产品名称
    product_homepage: str = ""          # 产品主页
    vuln_type: str = ""                 # 漏洞类型 (中文)
    vuln_type_en: str = ""              # 漏洞类型 (英文)
    cve: str = ""                       # CVE编号
    cvss_score: str = ""                # CVSS评分
    severity: str = ""                  # 严重程度
    disclosure_date: str = ""           # 公开日期
    entry_point: str = ""               # 漏洞入口点 (URI)
    vuln_principle: str = ""            # 漏洞原理
    impact: str = ""                    # 漏洞影响
    recommendation: str = ""            # 修复建议
    tags: List[str] = []                # 标签
    references: List[str] = []          # 参考链接
    has_exp: bool = False               # 是否有EXP

    def __init__(self, target: str, ssl: bool = False, timeout: int = 15):
        """
        Args:
            target: 目标地址 (IP:port 或 domain:port)
            ssl: 是否使用 HTTPS
            timeout: 请求超时秒数
        """
        self.target = target
        self.ssl = ssl
        self.timeout = timeout
        self.base_url = f"{'https' if ssl else 'http'}://{target}"
        self.session = requests.Session()
        self.variables: Dict[str, str] = {}  # 步骤间变量传递
        self.last_response: Optional[requests.Response] = None
        self.vuln_url: str = ""               # 漏洞入口URL

    # ==================== 核心方法 ====================

    def _make_request(
        self,
        method: str,
        uri: str,
        headers: Optional[Dict[str, str]] = None,
        data: str = "",
        follow_redirect: bool = False,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        发送 HTTP 请求

        Args:
            method: GET/POST/PUT/DELETE 等
            uri: 请求路径
            headers: 请求头
            data: 请求体
            follow_redirect: 是否跟随重定向
            timeout: 超时秒数
        """
        url = self._build_url(uri)
        url = self._replace_variables(url)

        req_headers = headers or {}
        data_body = self._replace_variables(data) if data else data

        method = method.upper()
        timeout = timeout or self.timeout

        try:
            if method == "GET":
                resp = self.session.get(
                    url, headers=req_headers,
                    allow_redirects=follow_redirect,
                    timeout=timeout, verify=False
                )
            elif method == "POST":
                resp = self.session.post(
                    url, headers=req_headers, data=data_body,
                    allow_redirects=follow_redirect,
                    timeout=timeout, verify=False
                )
            elif method == "PUT":
                resp = self.session.put(
                    url, headers=req_headers, data=data_body,
                    allow_redirects=follow_redirect,
                    timeout=timeout, verify=False
                )
            elif method == "DELETE":
                resp = self.session.delete(
                    url, headers=req_headers,
                    allow_redirects=follow_redirect,
                    timeout=timeout, verify=False
                )
            elif method == "PATCH":
                resp = self.session.patch(
                    url, headers=req_headers, data=data_body,
                    allow_redirects=follow_redirect,
                    timeout=timeout, verify=False
                )
            else:
                raise ValueError(f"Unsupported method: {method}")
        except requests.exceptions.Timeout:
            resp = requests.Response()
            resp.status_code = 0
            resp._content = b'{"error": "timeout"}'
            resp.url = url
        except requests.exceptions.ConnectionError:
            resp = requests.Response()
            resp.status_code = 0
            resp._content = b'{"error": "connection refused"}'
            resp.url = url
        except Exception as e:
            resp = requests.Response()
            resp.status_code = 0
            resp._content = f'{{"error": "{str(e)}"}}'.encode()
            resp.url = url

        self.last_response = resp
        return resp

    def _check_response(
        self,
        resp: requests.Response,
        checks: List[Dict[str, Any]],
        operation: str = "AND"
    ) -> bool:
        """
        检查响应是否符合匹配条件

        Args:
            resp: HTTP响应对象
            checks: 检查项列表
                [{"variable": "$code", "operation": "==", "value": "200"},
                 {"variable": "$body", "operation": "contains", "value": "test"}]
            operation: "AND" (全部满足) 或 "OR" (满足任一)
        """
        results = []
        for check in checks:
            variable = check.get("variable", "")
            op = check.get("operation", "==")
            value = check.get("value", "")
            result = self._evaluate_check(resp, variable, op, value)
            results.append(result)

        if not results:
            return True

        if operation.upper() == "AND":
            return all(results)
        else:  # OR
            return any(results)

    def _evaluate_check(
        self,
        resp: requests.Response,
        variable: str,
        operation: str,
        value: str
    ) -> bool:
        """评估单个检查条件"""
        # 获取实际值
        if variable == "$code":
            actual = str(resp.status_code)
        elif variable == "$body":
            actual = resp.text
        elif variable == "$head" or variable == "$header":
            actual = str(dict(resp.headers))
        elif variable == "$lastbody":
            actual = resp.text if resp else ""
        elif variable == "$lastheader":
            actual = str(dict(resp.headers)) if resp else ""
        else:
            actual = ""

        # 执行比较
        if operation == "==":
            return actual == value
        elif operation == "!=":
            return actual != value
        elif operation == "contains":
            return value in actual
        elif operation == "not contains":
            return value not in actual
        elif operation == "regex":
            import re
            return bool(re.search(value, actual))
        elif operation == ">" or operation == "gt":
            try:
                return float(actual) > float(value)
            except (ValueError, TypeError):
                return False
        elif operation == "<" or operation == "lt":
            try:
                return float(actual) < float(value)
            except (ValueError, TypeError):
                return False
        elif operation == ">=":
            try:
                return float(actual) >= float(value)
            except (ValueError, TypeError):
                return False
        elif operation == "<=":
            try:
                return float(actual) <= float(value)
            except (ValueError, TypeError):
                return False
        return False

    def _build_url(self, uri: str) -> str:
        """构建完整 URL"""
        base = self.base_url.rstrip('/')
        if uri.startswith('/'):
            return f"{base}{uri}"
        elif uri.startswith('http'):
            return uri
        else:
            return f"{base}/{uri}"

    def _replace_variables(self, text: str) -> str:
        """
        替换 {{{var}}} 模板变量

        内置变量:
            {{{fixedhostinfo}}}  → 目标地址 (IP:port)
            {{{base_url}}}       → http://IP:port
            {{{CRLF}}}           → \\r\\n
            {{{LF}}}             → \\n
            {{{CR}}}             → \\r
            {{{backquote}}}      → 反引号 `
            {{{lastbody}}}       → 上一次响应体
            {{{lastheader}}}     → 上一次响应头
        """
        if not text:
            return text

        result = text

        # 内置变量
        result = result.replace('{{{fixedhostinfo}}}', self.target)
        result = result.replace('{{{base_url}}}', self.base_url)
        result = result.replace('{{{CRLF}}}', '\r\n')
        result = result.replace('{{{LF}}}', '\n')
        result = result.replace('{{{CR}}}', '\r')
        result = result.replace('{{{backquote}}}', '`')

        if self.last_response:
            result = result.replace('{{{lastbody}}}', self.last_response.text)
            result = result.replace('{{{lastheader}}}', str(dict(self.last_response.headers)))

        # 自定义变量
        for key, val in self.variables.items():
            # 替换 {{{key}}} -> val
            placeholder = '{{{}}}'.format(key)
            result = result.replace(placeholder, str(val))

        return result

    def _set_variable(self, key: str, value: str):
        """设置模板变量"""
        self.variables[key] = value

    # ==================== 漏洞信息展示 ====================

    def show_info(self) -> str:
        """返回完整的漏洞信息文档"""
        lines = []
        lines.append("=" * 70)
        lines.append(f"  {self.name}")
        if self.cve:
            lines.append(f"  CVE: {self.cve}")
        lines.append("=" * 70)
        lines.append("")

        lines.append("【产品信息】")
        lines.append(f"  产品名称: {self.product}")
        lines.append(f"  产品主页: {self.product_homepage}")
        lines.append(f"  公开日期: {self.disclosure_date}")
        lines.append("")

        lines.append("【漏洞信息】")
        lines.append(f"  漏洞类型: {self.vuln_type}")
        lines.append(f"  English:  {self.vuln_type_en}")
        lines.append(f"  严重程度: {self.severity}  (CVSS: {self.cvss_score})")
        lines.append(f"  入口点:   {self.entry_point}")
        lines.append(f"  标签:     {', '.join(self.tags)}")
        lines.append("")

        lines.append("【漏洞原理】")
        for line in self.vuln_principle.strip().split('\n'):
            lines.append(f"  {line.strip()}")
        lines.append("")

        if self.impact:
            lines.append("【漏洞影响】")
            for line in self.impact.strip().split('\n'):
                lines.append(f"  {line.strip()}")
            lines.append("")

        if self.recommendation:
            lines.append("【修复建议】")
            for line in self.recommendation.strip().split('\n'):
                lines.append(f"  {line.strip()}")
            lines.append("")

        if self.references:
            lines.append("【参考链接】")
            for ref in self.references:
                lines.append(f"  - {ref}")
            lines.append("")

        return '\n'.join(lines)

    # ==================== 子类需覆盖的方法 ====================

    def check(self) -> CheckResult:
        """
        检测漏洞是否存在

        Returns:
            CheckResult 对象，包含是否脆弱和信息
        """
        raise NotImplementedError("子类必须实现 check() 方法")

    def exploit(self, **kwargs) -> ExploitResult:
        """
        利用漏洞

        Args:
            **kwargs: 利用参数 (如 filePath, username, passwd 等)

        Returns:
            ExploitResult 对象，包含是否成功和输出
        """
        raise NotImplementedError("子类必须实现 exploit() 方法")

    # ==================== CLI 入口 ====================

    @classmethod
    def run_cli(cls):
        """命令行入口"""
        parser = argparse.ArgumentParser(
            description=f"{cls.name} - Python POC",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "示例:\n"
                f"  python {sys.argv[0]} check http://target:8080\n"
                f"  python {sys.argv[0]} exploit http://target:8080 --params '{{\"key\":\"value\"}}'\n"
            )
        )
        parser.add_argument("action", choices=["check", "exploit", "info"],
                            help="执行的操作: check=检测, exploit=利用, info=漏洞信息")
        parser.add_argument("target", help="目标地址 (IP:port)")
        parser.add_argument("--ssl", action="store_true", help="使用 HTTPS")
        parser.add_argument("--timeout", type=int, default=15, help="超时秒数")
        parser.add_argument("--params", type=str, default="{}",
                            help='利用参数 JSON 字符串 (如: \'{"filePath":"../etc/passwd"}\')')
        parser.add_argument("--verbose", "-v", action="store_true", help="显示详细信息")

        args = parser.parse_args()
        poc = cls(target=args.target, ssl=args.ssl, timeout=args.timeout)

        if args.action == "info":
            print(poc.show_info())
            return

        params = json.loads(args.params) if args.params else {}

        if args.action == "check":
            if args.verbose:
                print(poc.show_info())
                print("-" * 70)
            result = poc.check()
            print(result)

        elif args.action == "exploit":
            if not poc.has_exp:
                print("[-] 此 POC 没有 EXP 功能")
                return
            if args.verbose:
                print(poc.show_info())
                print("-" * 70)
            result = poc.exploit(**params)
            print(result)
