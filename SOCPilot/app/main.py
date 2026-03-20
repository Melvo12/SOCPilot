from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from app.analyzer import analyze_log

console = Console()

SEVERITY_COLORS = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
    "UNKNOWN":  "dim",
}

def print_result(result: dict):
    severity = result.get("severity", "UNKNOWN")
    color    = SEVERITY_COLORS.get(severity, "white")

    console.print()
    console.print(Panel(
        f"[{color}]{severity}[/{color}]  ·  {result.get('category', 'N/A')}",
        title="[bold]SOCPilot — Analysis Result[/bold]",
        border_style=color,
    ))

    console.print("\n[bold]Observation[/bold]")
    console.print(result.get("observation", "N/A"))

    console.print("\n[bold]Recommended Actions[/bold]")
    for i, action in enumerate(result.get("actions", []), 1):
        console.print(f"  {i}. {action}")

    console.print(f"\n[dim]MITRE: {result.get('mitre_technique', 'N/A')}[/dim]\n")

def main():
    console.print(Panel(
        "[bold green]SOCPilot[/bold green] — On-Prem AI Assistant\n"
        "[dim]Type your security event. Press Enter twice to analyze. Ctrl+C to exit.[/dim]",
        border_style="green"
    ))

    while True:
        try:
            console.print("\n[bold]Paste security event:[/bold]")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)

            log_input = "\n".join(lines).strip()
            if not log_input:
                continue

            with console.status("[bold green]Analyzing...[/bold green]"):
                result = analyze_log(log_input)

            print_result(result)

        except KeyboardInterrupt:
            console.print("\n[dim]Exiting SOCPilot.[/dim]")
            break

if __name__ == "__main__":
    main()