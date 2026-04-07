"""Pretty console output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from agent_scanner.core.findings import ScanResult, Severity


class ConsoleOutput:
    """Formats scan results for terminal output."""
    
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
    
    def print_results(self, result: ScanResult, verbose: bool = False):
        """Print scan results to the console."""
        
        # Header
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold]Agent Security Scanner[/bold]\n"
                f"Scanned {result.files_scanned} files in {result.scan_duration_ms:.0f}ms",
                border_style="blue",
            )
        )
        
        if result.errors:
            self.console.print("\n[yellow]Warnings:[/yellow]")
            for error in result.errors:
                self.console.print(f"  ⚠️  {error}")
        
        # Findings
        active_findings = [f for f in result.findings if not f.suppressed]
        
        if not active_findings:
            self.console.print("\n[green]✅ No security issues found![/green]\n")
            return
        
        # Summary table
        self.console.print()
        summary = Table(title="Summary", show_header=True, header_style="bold")
        summary.add_column("Severity", style="dim")
        summary.add_column("Count", justify="right")
        
        if result.critical_count > 0:
            summary.add_row(
                "[red bold]CRITICAL[/red bold]",
                f"[red bold]{result.critical_count}[/red bold]"
            )
        if result.high_count > 0:
            summary.add_row(
                "[red]HIGH[/red]",
                f"[red]{result.high_count}[/red]"
            )
        if result.medium_count > 0:
            summary.add_row(
                "[yellow]MEDIUM[/yellow]",
                f"[yellow]{result.medium_count}[/yellow]"
            )
        if result.low_count > 0:
            summary.add_row(
                "[blue]LOW[/blue]",
                f"[blue]{result.low_count}[/blue]"
            )
        
        self.console.print(summary)
        
        # Group by severity
        by_severity: dict[Severity, list] = {}
        for finding in active_findings:
            by_severity.setdefault(finding.severity, []).append(finding)
        
        # Print findings
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        
        for severity in severity_order:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            
            self.console.print()
            self.console.print(f"[{severity.color}]━━━ {severity.value.upper()} ━━━[/{severity.color}]")
            
            for finding in findings:
                self._print_finding(finding, verbose)
        
        # Footer
        self.console.print()
        if result.has_blocking_issues:
            self.console.print(
                "[red bold]❌ SCAN FAILED[/red bold] - "
                f"{result.critical_count + result.high_count} blocking issues found"
            )
        else:
            self.console.print(
                "[yellow]⚠️  SCAN PASSED with warnings[/yellow] - "
                f"{result.medium_count + result.low_count} non-blocking issues"
            )
        self.console.print()
    
    def _print_finding(self, finding, verbose: bool):
        """Print a single finding."""
        
        # Header line
        location = f"{finding.location.file}:{finding.location.line}"
        confidence = f"({finding.confidence:.0%})" if finding.confidence < 1.0 else ""
        
        self.console.print()
        self.console.print(
            f"  [{finding.severity.color}]{finding.rule_id}[/{finding.severity.color}] "
            f"[bold]{finding.title}[/bold] {confidence}"
        )
        self.console.print(f"  [dim]{location}[/dim]")
        
        # Description
        self.console.print(f"\n  {finding.description}")
        
        # Code snippet
        if finding.location.snippet and verbose:
            self.console.print()
            # Simple code display
            for line in finding.location.snippet.split("\n"):
                if line.startswith("→"):
                    self.console.print(f"  [yellow]{line}[/yellow]")
                else:
                    self.console.print(f"  [dim]{line}[/dim]")
        
        # Fix suggestion
        self.console.print()
        self.console.print(f"  [green]💡 Fix:[/green] {finding.fix_suggestion.split(chr(10))[0]}")
        
        # OWASP/CWE references
        refs = []
        if finding.owasp_id:
            refs.append(f"OWASP {finding.owasp_id}")
        if finding.cwe_id:
            refs.append(finding.cwe_id)
        if refs:
            self.console.print(f"  [dim]References: {', '.join(refs)}[/dim]")
