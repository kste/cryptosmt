
import time
from typing import Dict, Any, List, Optional
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console, Group
from rich import box

class SearchReporter:
    def __init__(self, parameters: Dict[str, Any]):
        self.parameters = parameters
        self.start_time = time.time()
        self.console = Console()
        self.total_characteristics = 0
        self.recent_trails = [] # List of (weight, time, desc)
        self.current_weight = parameters.get("sweight", 0)
        self.mode = parameters.get("mode", 0)
        self.last_char = None # Store last DifferentialCharacteristic
        self.current_prob = 0.0
        
        # Progress components
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        self.task_id = self.progress.add_task(
            f"Searching...", 
            total=parameters.get("endweight", 1000) - parameters.get("sweight", 0)
        )

    def _make_header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        mode_names = {0: "Min Weight", 1: "Preimage", 2: "Find All", 3: "Best Constants", 4: "Probability"}
        mode_str = mode_names.get(self.mode, str(self.mode))
        
        solver_name = "STP"
        if self.parameters.get("bitwuzla"): solver_name = "Bitwuzla"
        elif self.parameters.get("boolector"): solver_name = "Boolector"
        elif self.parameters.get("cvc5"): solver_name = "CVC5"
        
        grid.add_row(
            f"[bold blue]Cipher:[/bold blue] {self.parameters.get('cipher')} | "
            f"[bold blue]Rounds:[/bold blue] {self.parameters.get('rounds')} | "
            f"[bold blue]Mode:[/bold blue] {mode_str}",
            f"[bold blue]Solver:[/bold blue] {solver_name} | "
            f"[bold blue]Threads:[/bold blue] {self.parameters.get('threads')} | "
            f"[bold blue]Wordsize:[/bold blue] {self.parameters.get('wordsize')}"
        )
        return Panel(grid, title="🛡️ CryptoSMT Search Dashboard", border_style="blue")

    def _make_recent_trails_table(self) -> Table:
        table = Table(title="Recent Weights/Trails", box=box.SIMPLE, expand=True)
        table.add_column("Weight", justify="center")
        table.add_column("Time Found", justify="right")
        table.add_column("Description", justify="left")
        
        for trail in self.recent_trails[-10:]:
            table.add_row(str(trail[0]), f"{trail[1]:.2f}s", str(trail[2]))
        return table

    def _make_stats_panel(self) -> Panel:
        elapsed = time.time() - self.start_time
        stats = f"Elapsed: {elapsed:.2f}s | Cumulative Trails Found: {self.total_characteristics}"
        if self.mode == 4 and self.current_prob > 0:
            import math
            log_prob = math.log(self.current_prob, 2)
            stats += f" | Current Log2(Prob): {log_prob:.2f}"
        return Panel(stats, title="Statistics", border_style="green")

    def get_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(self._make_header(), name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(self._make_stats_panel(), name="footer", size=3)
        )
        
        main_content = []
        main_content.append(self.progress)
        
        if self.last_char:
            main_content.append(self.last_char.get_rich_table())
        else:
            main_content.append(self._make_recent_trails_table())
            
        layout["main"].update(Panel(Group(*main_content), border_style="white"))
        return layout

    def update_weight(self, weight: int):
        self.current_weight = weight
        self.progress.update(self.task_id, completed=weight - self.parameters.get("sweight", 0),
                             description=f"Searching Weight {weight}...")
        if hasattr(self, "update_display"):
            self.update_display()

    def add_trail(self, weight: int, desc: str = "", count: int = 1, characteristic = None, prob: float = 0.0):
        if count > 0:
            self.total_characteristics += count
            self.recent_trails.append((weight, time.time() - self.start_time, desc))
            if characteristic:
                self.last_char = characteristic
            if prob > 0:
                self.current_prob = prob
            if hasattr(self, "update_display"):
                self.update_display()
