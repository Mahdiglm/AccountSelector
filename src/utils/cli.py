from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.padding import Padding
from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.columns import Columns
from rich.style import Style
from rich.console import Group
import questionary
from typing import List, Dict, Any, Optional, Tuple, Callable
import os
import time
import random
import re

# Initialize console
console = Console()

# ASCII Art Logo
APP_LOGO = """
 █████╗  ██████╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝
███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║   ██║   
██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║   ██║   
██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
███████╗███████╗██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
██╔════╝██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████╗█████╗  ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
╚════██║██╔══╝  ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
███████║███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

# Menu animations
LOADING_CHARS = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]

# Enhanced menu icons without Rich formatting tags (questionary doesn't support them)
MENU_ICONS = {
    "Login": "🔑 ",
    "Sign Up": "✨ ",
    "Exit": "🚪 ",
    "Browse": "🔍 ",
    "Add": "➕ ",
    "Manage": "⚙️ ",
    "Change": "🔄 ",
    "Import": "📥 ",
    "Export": "📤 ",
    "View": "👁️ ",
    "Logout": "🔒 ",
    "Users": "👥 ",
    "Password": "🔐 ",
    "Theme": "🎨 ",
    "Account": "📝 ",
    "Stats": "📊 ",
    "Selected": "✓ ",
    "Available": "🔎 ",
}

# Decorative elements
DECORATIONS = {
    "divider": "╠" + "═" * 30 + "╣",
    "top_border": "╔" + "═" * 30 + "╗",
    "bottom_border": "╚" + "═" * 30 + "╝",
    "star_divider": "★═════════════════════════════════════════════════════════════════════════════════════★",
    "dots": "•••••••••••••••••••••••••••••",
    "arrow": "———————————▶",
    "sparkles": "✧ ✧ ✧ ✧ ✧"
}

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_app_logo():
    """Display the application logo with a monochrome effect."""
    lines = APP_LOGO.strip().split('\n')
    
    for line in lines:
        centered_line = Align.center(line)
        console.print(centered_line, style="bold white")
        time.sleep(0.05)  # Small delay for animation effect
    
    console.print()
    console.print(Align.center(DECORATIONS["star_divider"]), style="bold white")
    console.print()

def animate_text(text, style="bold white", delay=0.03):
    """Display text with a typing animation effect."""
    for char in text:
        console.print(char, style=style, end="")
        time.sleep(delay)
    console.print()

def loading_animation(message, duration=1.0):
    """Display a loading animation."""
    end_time = time.time() + duration
    i = 0
    
    # Center the message
    message_with_padding = message.center(50)
    
    while time.time() < end_time:
        char = LOADING_CHARS[i % len(LOADING_CHARS)]
        centered_text = f"{char} {message_with_padding}..."
        console.print(f"\r{centered_text.center(console.width)}", end="", style="bold white")
        time.sleep(0.1)
        i += 1
    
    console.print()

def print_header(title: str, show_logo=False):
    """Print a stylized header."""
    clear_screen()
    
    if show_logo:
        display_app_logo()
    
    # Create a monochrome header
    header_text = Text(title, style="bold white")
    
    # Center the header and add padding
    centered_header = Align.center(header_text)
    padded_header = Padding(centered_header, (2, 4))
    
    # Create a panel with simple box
    panel = Panel(
        padded_header,
        box=box.DOUBLE,
        border_style="white",
        title="★ ★ ★",
        title_align="center",
        subtitle="★ ★ ★",
        subtitle_align="center"
    )
    
    # Center the panel
    console.print(Align.center(panel))
    console.print(Align.center(DECORATIONS["dots"]), style="white")
    console.print()  # Add some space after the header

def print_success(message: str):
    """Print a success message."""
    console.print(Align.center(f"[bold white]✓ {message}[/]"))
    
def print_error(message: str):
    """Print an error message."""
    console.print(Align.center(f"[bold white]✗ {message}[/]"))

def print_info(message: str):
    """Print an informational message."""
    console.print(Align.center(f"[bold white]ℹ {message}[/]"))

def print_warning(message: str):
    """Print a warning message."""
    console.print(Align.center(f"[bold white]⚠ {message}[/]"))

def display_accounts_table(accounts: List[Dict[str, Any]], show_credentials: bool = False):
    """Display accounts in a rich table."""
    if not accounts:
        print_info("No accounts found.")
        return
    
    # Create an attractive title for the table
    console.print(Align.center("[bold white]♦ Account List ♦[/]"))
    console.print()
    
    table = Table(
        box=box.HEAVY_EDGE,
        show_header=True,
        header_style="bold white",
        border_style="white",
        title="Secured Accounts",
        title_style="bold white",
        caption="* Sensitive information",
        caption_style="italic white"
    )
    
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Name", style="white bold")
    table.add_column("Username", style="white")
    
    if show_credentials:
        table.add_column("Password", style="white")
    
    table.add_column("Website", style="white")
    table.add_column("Notes", style="white")
    
    # Add a subtle pulsing animation
    with Live(Align.center(table), refresh_per_second=4, transient=True):
        for account in accounts:
            row = [
                account["id"][:8],  # Show first 8 chars of ID
                account["name"],
                account["username"],
            ]
            
            if show_credentials:
                row.append(account["password"])
            
            row.append(account.get("website", ""))
            row.append(account.get("notes", ""))
            
            table.add_row(*row)
            time.sleep(0.1)  # Small delay for animation effect
    
    console.print(Align.center(table))
    console.print()
    console.print(Align.center(DECORATIONS["divider"]), style="white")

def display_users_table(users: List[Dict[str, Any]]):
    """Display users in a rich table."""
    if not users:
        print_info("No users found.")
        return
    
    # Create an attractive title for the table
    console.print(Align.center("[bold white]♦ User Management ♦[/]"))
    console.print()
    
    table = Table(
        box=box.HEAVY_EDGE,
        show_header=True,
        header_style="bold white",
        border_style="white",
        title="System Users",
        title_style="bold white"
    )
    
    table.add_column("Username", style="white bold")
    table.add_column("Role", style="white")
    table.add_column("Created At", style="white")
    table.add_column("Last Login", style="white")
    
    # Add a subtle pulsing animation
    with Live(Align.center(table), refresh_per_second=4, transient=True):
        for user in users:
            table.add_row(
                user["username"],
                user["role"],
                str(user.get("created_at", "")),
                str(user.get("last_login", "Never"))
            )
            time.sleep(0.1)  # Small delay for animation effect
    
    console.print(Align.center(table))
    console.print()
    console.print(Align.center(DECORATIONS["divider"]), style="white")

def ask_to_continue():
    """Ask the user to press a key to continue."""
    console.print()
    
    # Center the prompt and use a neutral color
    prompt = "• Press Enter to continue •"
    centered_prompt = prompt.center(console.width)
    console.print(f"\r{centered_prompt}", style="bold white", end="")
    input()

def render_menu(title: str, options: List[Tuple[str, str, Callable]]) -> Optional[Callable]:
    """
    Render a menu with the given title and options.
    
    Args:
        title: The menu title
        options: List of (key, description, callback) tuples
    
    Returns:
        Selected callback function or None if user wants to exit
    """
    # Determine if this is the main menu
    is_main_menu = "Authentication" in title or "Admin" in title or "User" in title
    
    # Show logo only for main menus
    print_header(title, show_logo=is_main_menu)
    
    # Display an animated greeting for main menus
    if is_main_menu:
        time_of_day = "morning" if 5 <= time.localtime().tm_hour < 12 else \
                     "afternoon" if 12 <= time.localtime().tm_hour < 18 else "evening"
        greeting = f"Good {time_of_day}! Welcome to Account Selector"
        console.print(Align.center(greeting), style="bold white")
        console.print()
    
    choices = {}
    for key, description, callback in options:
        # Add icon to description if available
        icon = ""
        for key_word, menu_icon in MENU_ICONS.items():
            if key_word in description:
                icon = menu_icon
                break
        
        choices[f"{key}. {icon}{description}"] = callback
    
    # Display a decorative element before the menu
    console.print(Align.center(DECORATIONS["sparkles"]), style="white")
    console.print()
    
    # Center the menu options by adjusting the width
    menu_width = max(len(choice) for choice in choices.keys()) + 10
    
    # Create centered option groups
    result = questionary.select(
        "Select an option:".center(menu_width),
        choices=list(choices.keys()),
        use_arrow_keys=True,
        use_indicator=True,
    ).ask()
    
    # Display a decorative element after selection
    console.print()
    
    if result:
        # Show a brief loading animation when an option is selected
        option_text = result.split(".", 1)[1].strip()
        # Clean any remaining Rich formatting tags that might be in option text
        option_text = re.sub(r'\[.*?\]', '', option_text)
        loading_animation(f"Processing {option_text}", 0.8)
    
    console.print(Align.center(DECORATIONS["sparkles"]), style="white")
    
    if result is None:
        return None
    
    return choices[result]

def form_input(fields: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Display a form with specified fields and return the input values.
    
    Args:
        fields: List of field specifications
            Each field should have keys:
            - name: field name
            - message: prompt message
            - type: 'text', 'password', 'confirm' or 'select'
            - choices: (optional) list of choices for select type
            - default: (optional) default value
            - validate: (optional) validation function
    
    Returns:
        Dict with field values
    """
    # Use Rich's console to print formatted text, but pure text for questionary
    console.print(Align.center("♦ Please Enter Information ♦"), style="bold white")
    console.print()
    
    results = {}
    
    for field in fields:
        field_type = field.get("type", "text")
        name = field["name"]
        message = field["message"]
        default = field.get("default", "")
        
        if field_type == "text":
            result = questionary.text(
                message.center(50),
                default=default
            ).ask()
        elif field_type == "password":
            result = questionary.password(
                message.center(50)
            ).ask()
        elif field_type == "confirm":
            result = questionary.confirm(
                message.center(50),
                default=default
            ).ask()
        elif field_type == "select":
            choices = field.get("choices", [])
            result = questionary.select(
                message.center(50),
                choices=choices,
                default=default
            ).ask()
        else:
            result = None
            
        if result is not None:
            results[name] = result
    
    if results:
        loading_animation("Processing information", 0.5)
    
    return results

def confirm_action(message: str, default: bool = False) -> bool:
    """Ask user to confirm an action."""
    console.print()
    console.print(Align.center("⚠ Confirmation Required:"), style="bold white")
    result = questionary.confirm(message.center(50), default=default).ask()
    
    if result:
        loading_animation("Confirming action", 0.5)
    else:
        console.print(Align.center("Action cancelled"), style="bold white")
    
    return result

def display_spinner(message: str, seconds: float = 1.0):
    """Display a spinner for a given time."""
    with console.status(Align.center(f"[bold white]{message}[/]"), spinner="dots"):
        time.sleep(seconds) 