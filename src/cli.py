"""Command line interface for AuditHound"""
import click
from .audit import AuditManager

@click.group()
def cli() -> None:
    """AuditHound - Audit and compliance tracking tool"""
    pass

@cli.command()
def status() -> None:
    """Show audit status summary"""
    manager = AuditManager()
    summary = manager.get_summary()
    
    click.echo("=== Audit Status Summary ===")
    for status, count in summary.items():
        click.echo(f"{status.title()}: {count}")

@cli.command()
@click.option('--title', prompt='Finding title', help='Title of the audit finding')
@click.option('--description', prompt='Description', help='Description of the finding')
@click.option('--severity', prompt='Severity', type=click.Choice(['critical', 'high', 'medium', 'low']), help='Severity level')
@click.option('--category', prompt='Category', help='Category of the finding')
def add_finding(title: str, description: str, severity: str, category: str) -> None:
    """Add a new audit finding"""
    manager = AuditManager()
    finding = manager.create_finding(title, description, severity, category)
    click.echo(f"Created finding #{finding.id}: {finding.title}")

@cli.command()
def list_findings() -> None:
    """List all audit findings"""
    manager = AuditManager()
    if not manager.findings:
        click.echo("No findings found.")
        return
    
    for finding in manager.findings:
        click.echo(f"#{finding.id} - {finding.title} [{finding.severity}] - {finding.status}")

if __name__ == '__main__':
    cli()