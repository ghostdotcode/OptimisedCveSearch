import os
import json
from elasticsearch import Elasticsearch
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Input, Button, DataTable, Static
from textual.binding import Binding


def extract_all_keys(data, parent_key=""):
    """Reusing our exact schema builder logic to flatten the searched CVE"""
    keys = set()
    if isinstance(data, dict):
        for k, v in data.items():
            current_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, (dict, list)):
                keys.update(extract_all_keys(v, current_key))
            else:
                keys.add(current_key)
    elif isinstance(data, list):
        for item in data:
            keys.update(extract_all_keys(item, parent_key))
    else:
        if parent_key:
            keys.add(parent_key)
    return keys


class CVEDashboard(App):
    # CSS styling for our terminal UI
    CSS = """
    Screen { padding: 1; }
    #search-container { height: 3; margin-bottom: 1; }
    #search-input { width: 1fr; }
    #toggle-view { width: 30; margin-left: 1; }
    #json-view { background: $boost; padding: 1; }
    """

    # Hotkey for the toggle
    BINDINGS = [Binding("ctrl+t", "toggle_view", "Toggle View")]

    def __init__(self):
        super().__init__()
        self.es = Elasticsearch("http://localhost:9200")
        self.current_view = "table"
        self.master_template = set()

        # Load the Universal NA Template dynamically
        if os.path.exists("master_template.json"):
            with open("master_template.json", "r", encoding="utf-8") as f:
                self.master_template = set(json.load(f))

    def compose(self) -> ComposeResult:
        """Draws the UI elements on the screen"""
        yield Header(show_clock=True)

        with Horizontal(id="search-container"):
            yield Input(
                placeholder="Search CVE ID (e.g., CVE-2024-0005)...", id="search-input"
            )
            yield Button(
                "Toggle JSON/Table (Ctrl+T)", id="toggle-view", variant="primary"
            )

        with VerticalScroll(id="content-area"):
            yield DataTable(id="table-view")
            yield Static(id="json-view")

        yield Footer()

    def on_mount(self) -> ComposeResult:
        """Initializes the table structure when the app starts"""
        self.table = self.query_one("#table-view", DataTable)
        self.json_display = self.query_one("#json-view", Static)

        # Hide the JSON view initially
        self.json_display.display = False

        # Setup Table Columns
        self.table.add_columns("JSON Path (Flattened)", "Data Status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Listens for the toggle button click"""
        if event.button.id == "toggle-view":
            self.action_toggle_view()

    def action_toggle_view(self) -> None:
        """Flips between the Table and JSON interface"""
        if self.current_view == "table":
            self.current_view = "json"
            self.table.display = False
            self.json_display.display = True
        else:
            self.current_view = "table"
            self.table.display = True
            self.json_display.display = False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Triggers when the user hits Enter in the search bar"""
        cve_id = event.value.strip().upper()
        if not cve_id:
            return

        try:
            # Query our local data lake
            res = self.es.get(index="cves", id=cve_id)
            data = res["_source"]
            self.render_data(data)
        except Exception as e:
            self.table.clear()
            self.json_display.update(
                f"[!] {cve_id} not found in local database.\nError: {e}"
            )

    def render_data(self, data: dict) -> None:
        """Handles the Senior Dev's specific NA logic"""
        self.table.clear()

        # Get the keys currently present in THIS specific document
        populated_keys = extract_all_keys(data)

        # Calculate exactly what is missing based on 25 years of history
        missing_keys = self.master_template - populated_keys

        # --- 1. Populate Table View (Clean, No NAs) ---
        for k in sorted(populated_keys):
            self.table.add_row(k, "✅ Present")

        # --- 2. Populate JSON View (With NAs stacked at the bottom) ---
        json_output = json.dumps(data, indent=2)

        json_output += "\n\n" + "=" * 60 + "\n"
        json_output += "                 MISSING DATA (NA FIELDS)\n"
        json_output += "=" * 60 + "\n\n"

        for mk in sorted(missing_keys):
            json_output += f'"{mk}": "NA"\n'

        self.json_display.update(json_output)


if __name__ == "__main__":
    app = CVEDashboard()
    app.run()
