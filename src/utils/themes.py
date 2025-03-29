from typing import Dict, Any
from rich.theme import Theme
from rich.console import Console

# Define themes
THEMES = {
    "default": {
        "info": "bold blue",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "header": "bold cyan",
        "account_id": "dim",
        "account_name": "green",
        "account_username": "blue",
        "account_password": "yellow",
        "account_website": "magenta",
        "account_notes": "cyan",
        "menu_title": "bold cyan",
        "menu_border": "cyan",
        "panel_border": "cyan",
        "strong_password": "bold green",
        "good_password": "bold blue",
        "fair_password": "bold yellow",
        "weak_password": "bold red",
        "favorite": "bold yellow",
        "tag": "bold magenta"
    },
    "dark": {
        "info": "bold blue",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "header": "bold purple",
        "account_id": "dim",
        "account_name": "bold green",
        "account_username": "bold blue",
        "account_password": "bold yellow",
        "account_website": "bold magenta",
        "account_notes": "bold cyan",
        "menu_title": "bold purple",
        "menu_border": "purple",
        "panel_border": "purple",
        "strong_password": "bold green",
        "good_password": "bold blue",
        "fair_password": "bold yellow",
        "weak_password": "bold red",
        "favorite": "bold yellow",
        "tag": "bold magenta"
    },
    "light": {
        "info": "blue",
        "success": "green",
        "error": "red",
        "warning": "yellow",
        "header": "cyan",
        "account_id": "dim",
        "account_name": "green",
        "account_username": "blue",
        "account_password": "yellow",
        "account_website": "magenta",
        "account_notes": "cyan",
        "menu_title": "cyan",
        "menu_border": "cyan",
        "panel_border": "cyan",
        "strong_password": "green",
        "good_password": "blue",
        "fair_password": "yellow",
        "weak_password": "red",
        "favorite": "yellow",
        "tag": "magenta"
    },
    "hacker": {
        "info": "bold green",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "header": "bold green",
        "account_id": "dim",
        "account_name": "bold green",
        "account_username": "green",
        "account_password": "bold green",
        "account_website": "green",
        "account_notes": "green",
        "menu_title": "bold green",
        "menu_border": "green",
        "panel_border": "green",
        "strong_password": "bold green",
        "good_password": "green",
        "fair_password": "yellow",
        "weak_password": "red",
        "favorite": "bold yellow",
        "tag": "bold green"
    },
    "ocean": {
        "info": "bold cyan",
        "success": "bold blue",
        "error": "bold red",
        "warning": "bold yellow",
        "header": "bold cyan",
        "account_id": "dim",
        "account_name": "blue",
        "account_username": "cyan",
        "account_password": "bold blue",
        "account_website": "blue",
        "account_notes": "cyan",
        "menu_title": "bold cyan",
        "menu_border": "cyan",
        "panel_border": "blue",
        "strong_password": "bold blue",
        "good_password": "cyan",
        "fair_password": "bold yellow",
        "weak_password": "bold red",
        "favorite": "bold yellow",
        "tag": "bold magenta"
    }
}


def get_theme(theme_name: str = "default") -> Dict[str, str]:
    """Get a theme by name"""
    if theme_name not in THEMES:
        theme_name = "default"
    return THEMES[theme_name]


def get_rich_theme(theme_name: str = "default") -> Theme:
    """Get a rich.Theme object by name"""
    return Theme(get_theme(theme_name))


def get_console(theme_name: str = "default") -> Console:
    """Get a Console with the specified theme"""
    theme = get_rich_theme(theme_name)
    return Console(theme=theme)


def get_available_themes() -> Dict[str, str]:
    """Get a dictionary of available themes with descriptions"""
    return {
        "default": "The default blue-green theme",
        "dark": "A darker theme with purple accents",
        "light": "A lighter version of the default theme",
        "hacker": "A green hacker-inspired theme",
        "ocean": "A blue and cyan ocean-inspired theme"
    }