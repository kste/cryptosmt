
import subprocess
import time
import os
import json
import argparse
from typing import Dict, List, Any
from concurrent.futures import ProcessPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Group
from rich import box
import shutil
from typing import Dict, List, Any

def get_solver_version(path: str, args: List[str] = ["--version"]) -> str:
    # If path is just a command name, find it in system PATH
    actual_path = path
    if not os.path.exists(path):
        actual_path = shutil.which(path)
        if not actual_path:
            return "Not found"

    try:
        result = subprocess.run([actual_path] + args, capture_output=True, text=True, timeout=5)
        out = result.stdout.strip() or result.stderr.strip()
        return out.split("\n")[0]
    except Exception:
        return "Unknown Version"


def run_benchmark_task(task_id, name, rounds, wordsize, solver, extra_args):
    cmd = ["python3", "cryptosmt.py", "--cipher", name, "--rounds", str(rounds), 
           "--wordsize", str(wordsize), "--quiet"] + extra_args
    
    if solver == "Bitwuzla": cmd.append("--bitwuzla")
    elif solver == "Boolector": cmd.append("--boolector")
    elif solver == "CVC5": cmd.append("--cvc5")
    elif solver == "STP": cmd.append("--stp")
    
    start = time.time()
    try:
        subprocess.run(cmd, capture_output=True, timeout=600)
        elapsed = time.time() - start
        return (task_id, elapsed)
    except subprocess.TimeoutExpired:
        return (task_id, "TIMEOUT")
    except Exception as e:
        return (task_id, f"ERROR: {e}")

def run_parallel_benchmark(json_output: str = None):
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR, PATH_CVC5
    console = Console()
    
    solvers = {
        "CVC5": PATH_CVC5,
        "Bitwuzla": PATH_BITWUZLA,
        "Boolector": PATH_BOOLECTOR,
        "STP": PATH_STP
    }
    
    available_solvers = [name for name, path in solvers.items() if os.path.exists(path) or shutil.which(path)]
    versions = {name: get_solver_version(solvers[name]) for name in available_solvers}
    
    ciphers = [
        ("simon", 10, 16, []),
        ("speck", 6, 16, []),
        ("rectangle", 1, 16, ["--blocksize", "64"]),
        ("gift", 1, 64, []),
        ("keccak", 2, 8, []),
        ("ascon", 2, 64, []),
    ]
    
    tasks = []
    for c_name, rounds, ws, args in ciphers:
        for s_name in available_solvers:
            tasks.append({
                "id": len(tasks),
                "cipher": c_name,
                "rounds": rounds,
                "wordsize": ws,
                "args": args,
                "solver": s_name,
                "status": "[white]Pending[/white]",
                "time": None
            })

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    overall_task = progress.add_task("[bold blue]Benchmarking...", total=len(tasks))

    def get_summary_table():
        table = Table(box=box.DOUBLE_EDGE, expand=True)
        table.add_column("Cipher (Rounds)", style="bold cyan")
        table.add_column("Solver", style="magenta")
        table.add_column("Status", justify="center")
        table.add_column("Time (s)", justify="right")
        table.add_column("Relative", justify="right")
        
        best_times = {}
        for t in tasks:
            if isinstance(t["time"], float):
                key = (t["cipher"], t["rounds"])
                if key not in best_times or t["time"] < best_times[key]:
                    best_times[key] = t["time"]
        
        last_cipher = None
        for t in tasks:
            current_cipher = f"{t['cipher']} ({t['rounds']}r)"
            if last_cipher and last_cipher != current_cipher:
                table.add_section()
            last_cipher = current_cipher

            time_str = f"{t['time']:.2f}" if isinstance(t["time"], float) else str(t["time"] or "")
            rel_str = ""
            row_style = ""
            
            if isinstance(t["time"], float):
                best = best_times.get((t["cipher"], t["rounds"]))
                if best:
                    ratio = t["time"] / best
                    rel_str = f"{ratio:.2f}x"
                    if ratio <= 1.05:
                        rel_str = f"[bold green]★ {rel_str}[/bold green]"
                        time_str = f"[bold green]{time_str}[/bold green]"
                        row_style = "bold green"
            
            table.add_row(
                current_cipher,
                t["solver"],
                t["status"],
                time_str,
                rel_str,
                style=row_style if "Done" in t["status"] else ""
            )
        return table

    version_str = " | ".join([f"[bold]{s}:[/bold] {v}" for s, v in versions.items()])
    
    layout = Layout()
    layout.split(
        Layout(name="header", size=5),
        Layout(name="main", ratio=1),
        Layout(Panel(progress, border_style="white"), size=3)
    )
    
    header_content = Group(
        Panel("🚀 [bold blue]CryptoSMT Solver Performance Dashboard[/bold blue]", border_style="blue", box=box.SIMPLE),
        Panel(version_str, title="Solver Versions (Static Info)", border_style="cyan", box=box.SIMPLE)
    )
    layout["header"].update(header_content)

    with Live(layout, refresh_per_second=4) as live:
        with ProcessPoolExecutor() as executor:
            future_to_id = {}
            for t in tasks:
                f = executor.submit(run_benchmark_task, t["id"], t["cipher"], t["rounds"], t["wordsize"], t["solver"], t["args"])
                future_to_id[f] = t["id"]
                t["status"] = "[yellow]Running...[/yellow]"
                layout["main"].update(get_summary_table())

            for future in as_completed(future_to_id):
                t_id, result = future.result()
                tasks[t_id]["status"] = "[green]Done[/green]"
                tasks[t_id]["time"] = result
                progress.update(overall_task, advance=1)
                layout["main"].update(get_summary_table())

    # Export to JSON if requested
    if json_output:
        export_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "solvers": {name: versions[name] for name in available_solvers},
            "results": []
        }
        for t in tasks:
            export_data["results"].append({
                "cipher": t["cipher"],
                "rounds": t["rounds"],
                "wordsize": t["wordsize"],
                "solver": t["solver"],
                "time_seconds": t["time"] if isinstance(t["time"], float) else None,
                "error": t["time"] if not isinstance(t["time"], float) else None
            })
        
        with open(json_output, "w") as f:
            json.dump(export_data, f, indent=4)
        console.print(f"\n[bold green]✅ Results exported to {json_output}[/bold green]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel SMT Solver Benchmark for CryptoSMT")
    parser.add_argument("--json", type=str, help="Export results to a JSON file")
    args = parser.parse_args()
    
    run_parallel_benchmark(json_output=args.json)
