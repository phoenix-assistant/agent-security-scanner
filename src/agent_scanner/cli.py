"""
Command-line interface for Agent Security Scanner.

Usage:
    agent-scan analyze ./my-agent
    agent-scan analyze ./my-agent --format sarif --output results.sarif
    agent-scan analyze ./my-agent --verbose
    agent-scan init  # Create config file
    agent-scan baseline create  # Create baseline from current findings
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_scanner import __version__
from agent_scanner.core.scanner import Scanner
from agent_scanner.output.console import ConsoleOutput
from agent_scanner.output.sarif import SarifOutput
from agent_scanner.output.json_output import JsonOutput
from agent_scanner.config import ScanConfig, get_default_config_template
from agent_scanner.baseline import Baseline, create_baseline_from_findings


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="agent-scan")
def main():
    """
    Agent Security Scanner - ESLint for AI agents.
    
    Detects security vulnerabilities in LangChain, CrewAI, AutoGPT,
    and other AI agent frameworks.
    
    OWASP LLM Top 10 coverage + secrets detection.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["console", "sarif", "json", "html"]),
    default="console",
    help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file (default: stdout for sarif/json)",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show code snippets and detailed output",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output",
)
@click.option(
    "--fail-on", "-F",
    type=click.Choice(["critical", "high", "medium", "low", "none"]),
    default="high",
    help="Exit with error if issues of this severity or higher are found",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    help="Rule IDs to ignore (can be repeated)",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to config file",
)
@click.option(
    "--baseline", "-b",
    type=click.Path(),
    help="Baseline file to filter known issues",
)
def analyze(
    path: str,
    format: str,
    output: str,
    verbose: bool,
    no_color: bool,
    fail_on: str,
    ignore: tuple,
    config: Optional[str],
    baseline: Optional[str],
):
    """
    Analyze code for security vulnerabilities.
    
    PATH can be a file or directory. Directories are scanned recursively.
    
    Examples:
    
        agent-scan analyze ./my-agent
        
        agent-scan analyze ./my-agent --format sarif -o results.sarif
        
        agent-scan analyze ./my-agent -v --fail-on critical
        
        agent-scan analyze ./my-agent --baseline .agent-scan-baseline.json
    """
    
    target_path = Path(path).resolve()
    
    # Load configuration
    if config:
        scan_config = ScanConfig.load(Path(config).parent)
    else:
        scan_config = ScanConfig.load(target_path if target_path.is_dir() else target_path.parent)
    
    # CLI options override config
    if format != "console":
        scan_config.output_format = format
    if output:
        scan_config.output_file = output
    if verbose:
        scan_config.verbose = True
    if no_color:
        scan_config.no_color = True
    if fail_on != "high":
        scan_config.fail_on = fail_on
    if ignore:
        scan_config.disabled_rules.extend(ignore)
    if baseline:
        scan_config.baseline_file = baseline
    
    # Configure console
    if scan_config.no_color:
        global console
        console = Console(force_terminal=False, no_color=True)
    
    # Load baseline if specified
    baseline_obj = None
    if scan_config.baseline_file:
        baseline_path = Path(scan_config.baseline_file)
        if baseline_path.exists():
            baseline_obj = Baseline.load(baseline_path)
            if scan_config.verbose:
                console.print(f"[dim]Loaded baseline with {len(baseline_obj.entries)} entries[/dim]")
    
    # Run scanner
    scanner = Scanner()
    result = scanner.scan_path(target_path)
    
    # Filter ignored rules
    if scan_config.disabled_rules:
        result.findings = [
            f for f in result.findings 
            if f.rule_id not in scan_config.disabled_rules
        ]
    
    # Filter baselined findings
    baselined_count = 0
    if baseline_obj:
        new_findings, baselined = baseline_obj.filter_findings(result.findings)
        baselined_count = len(baselined)
        result.findings = new_findings
    
    # Output results
    if scan_config.output_format == "console":
        output_handler = ConsoleOutput(console)
        output_handler.print_results(result, verbose=scan_config.verbose)
        if baselined_count > 0:
            console.print(f"\n[dim]({baselined_count} baselined findings hidden)[/dim]")
    
    elif scan_config.output_format == "sarif":
        sarif = SarifOutput(base_path=target_path if target_path.is_dir() else target_path.parent)
        sarif_json = sarif.to_json(result)
        
        if scan_config.output_file:
            Path(scan_config.output_file).write_text(sarif_json)
            console.print(f"SARIF output written to {scan_config.output_file}")
        else:
            click.echo(sarif_json)
    
    elif scan_config.output_format == "json":
        json_out = JsonOutput(base_path=target_path if target_path.is_dir() else target_path.parent)
        json_str = json_out.to_json(result)
        
        if scan_config.output_file:
            Path(scan_config.output_file).write_text(json_str)
            console.print(f"JSON output written to {scan_config.output_file}")
        else:
            click.echo(json_str)
    
    elif scan_config.output_format == "html":
        try:
            from agent_scanner.output.html import HtmlOutput
            html_out = HtmlOutput(base_path=target_path if target_path.is_dir() else target_path.parent)
            html_str = html_out.render(result)
            
            output_file = scan_config.output_file or "agent-scan-report.html"
            Path(output_file).write_text(html_str)
            console.print(f"HTML report written to {output_file}")
        except ImportError:
            console.print("[red]HTML output requires jinja2: pip install jinja2[/red]")
            sys.exit(1)
    
    # Determine exit code based on fail_on
    should_fail = False
    if scan_config.fail_on == "critical":
        should_fail = result.critical_count > 0
    elif scan_config.fail_on == "high":
        should_fail = result.critical_count > 0 or result.high_count > 0
    elif scan_config.fail_on == "medium":
        should_fail = result.critical_count > 0 or result.high_count > 0 or result.medium_count > 0
    elif scan_config.fail_on == "low":
        should_fail = len([f for f in result.findings if not f.suppressed]) > 0
    # fail_on == "none" never fails
    
    if should_fail:
        sys.exit(1)


@main.command()
def rules():
    """List all available security rules."""
    
    from agent_scanner.rules.registry import get_registry
    
    registry = get_registry()
    rule_classes = registry.get_all_rules()
    
    from rich.table import Table
    
    table = Table(title="Available Rules", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("CWE")
    
    # Sort by ID
    rules_list = sorted([r() for r in rule_classes], key=lambda r: r.id)
    
    for rule in rules_list:
        severity_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(rule.severity.value, "")
        
        table.add_row(
            rule.id,
            rule.name,
            f"[{severity_style}]{rule.severity.value.upper()}[/{severity_style}]",
            rule.owasp_id or "-",
            rule.cwe_id or "-",
        )
    
    console.print()
    console.print(table)
    console.print(f"\n[dim]Total: {len(rules_list)} rules[/dim]")
    console.print()


@main.command()
@click.argument("source", type=click.File("r"), default="-")
def check(source):
    """
    Quick check of Python code from stdin or file.
    
    Examples:
    
        echo "exec(user_input)" | agent-scan check
        
        agent-scan check < suspicious.py
    """
    
    code = source.read()
    
    scanner = Scanner()
    findings = scanner.scan_source(code, filename="<stdin>")
    
    if not findings:
        console.print("[green]✅ No issues found[/green]")
        return
    
    for finding in findings:
        console.print(
            f"[{finding.severity.color}]{finding.rule_id}[/{finding.severity.color}] "
            f"Line {finding.line}: {finding.title}"
        )
    
    if any(f.severity.value in ("critical", "high") for f in findings):
        sys.exit(1)


@main.command()
@click.option("--force", "-f", is_flag=True, help="Overwrite existing config")
def init(force: bool):
    """
    Create a configuration file.
    
    Creates .agent-scan.yaml in the current directory.
    """
    
    config_path = Path(".agent-scan.yaml")
    
    if config_path.exists() and not force:
        console.print(f"[yellow]Config file already exists: {config_path}[/yellow]")
        console.print("Use --force to overwrite")
        return
    
    config_path.write_text(get_default_config_template())
    console.print(f"[green]✅ Created {config_path}[/green]")


@main.group()
def baseline():
    """Manage baseline for known issues."""
    pass


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=".agent-scan-baseline.json",
    help="Baseline output file",
)
@click.option(
    "--reason", "-r",
    default="Initial baseline",
    help="Reason for baselining",
)
def baseline_create(path: str, output: str, reason: str):
    """
    Create a baseline from current findings.
    
    This allows you to acknowledge existing findings and only
    alert on new ones.
    
    Examples:
    
        agent-scan baseline create ./my-agent
        
        agent-scan baseline create ./my-agent -o baseline.json -r "Legacy code"
    """
    
    target_path = Path(path).resolve()
    
    # Run scanner
    scanner = Scanner()
    result = scanner.scan_path(target_path)
    
    if not result.findings:
        console.print("[green]No findings to baseline[/green]")
        return
    
    # Create baseline
    baseline_obj = create_baseline_from_findings(result.findings, reason=reason)
    baseline_obj.save(Path(output))
    
    console.print(f"[green]✅ Created baseline with {len(baseline_obj.entries)} findings[/green]")
    console.print(f"Saved to: {output}")


@baseline.command("show")
@click.argument("baseline_file", type=click.Path(exists=True))
def baseline_show(baseline_file: str):
    """Show contents of a baseline file."""
    
    baseline_obj = Baseline.load(Path(baseline_file))
    
    from rich.table import Table
    
    table = Table(title=f"Baseline: {baseline_file}", show_header=True)
    table.add_column("Fingerprint", style="dim")
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Reason")
    
    for fp, entry in baseline_obj.entries.items():
        table.add_row(
            fp[:8] + "...",
            entry.rule_id,
            entry.file_path,
            entry.reason or "-",
        )
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(baseline_obj.entries)} baselined findings[/dim]")


@baseline.command("clear")
@click.argument("baseline_file", type=click.Path(exists=True))
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def baseline_clear(baseline_file: str, yes: bool):
    """Clear all entries from a baseline."""
    
    if not yes:
        if not click.confirm(f"Clear all entries from {baseline_file}?"):
            return
    
    baseline_obj = Baseline()
    baseline_obj.save(Path(baseline_file))
    console.print(f"[green]Cleared {baseline_file}[/green]")


if __name__ == "__main__":
    main()
