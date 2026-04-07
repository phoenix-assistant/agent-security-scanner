"""
HTML report output for Agent Security Scanner.

Generates a beautiful, interactive HTML report.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional
import html

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.core.scanner import ScanResult


class HtmlOutput:
    """Generates HTML reports."""
    
    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or Path.cwd()
    
    def render(self, result: ScanResult) -> str:
        """Render scan results to HTML."""
        
        # Group findings by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
        }
        
        for finding in result.findings:
            by_severity[finding.severity].append(finding)
        
        # Group by file
        by_file = {}
        for finding in result.findings:
            path = str(finding.file_path)
            if path not in by_file:
                by_file[path] = []
            by_file[path].append(finding)
        
        findings_html = self._render_findings(result.findings)
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Security Scanner Report</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --border: #334155;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: var(--text-dim);
            margin-bottom: 2rem;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat {{
            background: var(--card);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid var(--border);
        }}
        
        .stat.critical {{ border-left-color: var(--critical); }}
        .stat.high {{ border-left-color: var(--high); }}
        .stat.medium {{ border-left-color: var(--medium); }}
        .stat.low {{ border-left-color: var(--low); }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        
        .stat.critical .stat-value {{ color: var(--critical); }}
        .stat.high .stat-value {{ color: var(--high); }}
        .stat.medium .stat-value {{ color: var(--medium); }}
        .stat.low .stat-value {{ color: var(--low); }}
        
        .stat-label {{
            color: var(--text-dim);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .findings {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}
        
        .finding {{
            background: var(--card);
            border-radius: 8px;
            padding: 1.5rem;
            border-left: 4px solid var(--border);
        }}
        
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.75rem;
        }}
        
        .finding-title {{
            font-weight: 600;
            font-size: 1.1rem;
        }}
        
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge.critical {{ background: var(--critical); color: white; }}
        .badge.high {{ background: var(--high); color: white; }}
        .badge.medium {{ background: var(--medium); color: black; }}
        .badge.low {{ background: var(--low); color: white; }}
        
        .finding-meta {{
            color: var(--text-dim);
            font-size: 0.875rem;
            margin-bottom: 0.75rem;
        }}
        
        .finding-meta code {{
            background: var(--bg);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-family: 'SF Mono', Monaco, monospace;
        }}
        
        .finding-description {{
            margin-bottom: 1rem;
        }}
        
        .finding-fix {{
            background: var(--bg);
            padding: 1rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        
        .finding-fix-title {{
            color: var(--text-dim);
            font-size: 0.75rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }}
        
        .finding-fix pre {{
            white-space: pre-wrap;
            font-family: 'SF Mono', Monaco, monospace;
        }}
        
        footer {{
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 0.875rem;
            text-align: center;
        }}
        
        a {{ color: #60a5fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Agent Security Scanner Report</h1>
        <p class="subtitle">
            Scanned {result.files_scanned} files • Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </p>
        
        <div class="summary">
            <div class="stat critical">
                <div class="stat-value">{result.critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{result.high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{result.medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{result.low_count}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(result.findings)}</div>
                <div class="stat-label">Total</div>
            </div>
        </div>
        
        <div class="findings">
            {findings_html}
        </div>
        
        <footer>
            Generated by <a href="https://github.com/phoenix-assistant/agent-security-scanner">Agent Security Scanner</a>
        </footer>
    </div>
</body>
</html>'''
    
    def _render_findings(self, findings: list[Finding]) -> str:
        """Render findings to HTML."""
        
        if not findings:
            return '<p style="text-align: center; color: var(--text-dim);">✅ No security issues found!</p>'
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order[f.severity])
        
        html_parts = []
        for finding in sorted_findings:
            severity_class = finding.severity.value
            
            # Make path relative if possible
            try:
                rel_path = Path(finding.file_path).relative_to(self.base_path)
            except ValueError:
                rel_path = finding.file_path
            
            fix_html = ""
            if finding.fix_suggestion:
                fix_html = f'''
                <div class="finding-fix">
                    <div class="finding-fix-title">Suggested Fix</div>
                    <pre>{html.escape(finding.fix_suggestion)}</pre>
                </div>
                '''
            
            html_parts.append(f'''
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-title">{html.escape(finding.title)}</span>
                    <span class="badge {severity_class}">{severity_class}</span>
                </div>
                <div class="finding-meta">
                    <code>{finding.rule_id}</code> •
                    {html.escape(str(rel_path))}:{finding.line}
                    {f'• CWE-{finding.cwe_id}' if finding.cwe_id else ''}
                    {f'• OWASP {finding.owasp_id}' if finding.owasp_id else ''}
                </div>
                <div class="finding-description">
                    {html.escape(finding.description)}
                </div>
                {fix_html}
            </div>
            ''')
        
        return "\n".join(html_parts)
