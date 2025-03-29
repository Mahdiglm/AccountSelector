from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QStackedWidget, QMessageBox, QDialog, QMenu, QAction
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import Qt, Signal, QTimer

from ..data.storage import Storage
from ..data.models import User, UserRole
from .login import LoginWidget
from .dashboard import DashboardWidget
from .account_manager import AccountManagerWidget
from .settings import SettingsWidget
from .user_manager import UserManagerWidget
from .profile import ProfileWidget
from .backup_manager import BackupManager

class MainWindow(QMainWindow):
    def __init__(self, storage):
        super().__init__()
        self.storage = storage
        self._init_ui()

    def _init_ui(self):
        # Main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        
        # Create login widget
        self.login_widget = LoginWidget(self.storage)
        self.login_widget.login_successful.connect(self.on_login_successful)
        self.stacked_widget.addWidget(self.login_widget)
        
        # Create dashboard widget
        self.dashboard_widget = DashboardWidget(self.storage)
        self.dashboard_widget.account_selected.connect(self.show_account_details)
        self.dashboard_widget.logout_requested.connect(self.logout)
        self.stacked_widget.addWidget(self.dashboard_widget)
        
        # Create account manager widget
        self.account_manager = AccountManagerWidget(self.storage)
        self.account_manager.back_to_dashboard.connect(self.show_dashboard)
        self.stacked_widget.addWidget(self.account_manager)
        
        # Create settings widget
        self.settings_widget = SettingsWidget(self.storage)
        self.settings_widget.back_requested.connect(self.show_dashboard)
        self.settings_widget.theme_changed.connect(self.apply_theme)
        self.stacked_widget.addWidget(self.settings_widget)
        
        # Create user manager widget
        self.user_manager = UserManagerWidget(self.storage)
        self.user_manager.back_requested.connect(self.show_dashboard)
        self.stacked_widget.addWidget(self.user_manager)
        
        # Create profile widget
        self.profile_widget = ProfileWidget(self.storage)
        self.profile_widget.back_requested.connect(self.show_dashboard)
        self.profile_widget.password_changed.connect(self.on_password_changed)
        self.stacked_widget.addWidget(self.profile_widget)
        
        # Create backup manager widget
        self.backup_manager = BackupManager(self.storage)
        self.backup_manager.restore_completed.connect(self.on_backup_restored)
        self.stacked_widget.addWidget(self.backup_manager)
        
        self.main_layout.addWidget(self.stacked_widget)
        
        # Set up status bar
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Initialize session timer
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_session)
        self.session_timer.start(60000)  # Check every minute
        
        # Set initial widget to login
        self.stacked_widget.setCurrentWidget(self.login_widget)

    def show_dashboard(self):
        """Switch to dashboard widget"""
        self.stacked_widget.setCurrentWidget(self.dashboard_widget)
        self.dashboard_widget.refresh_data()
        self.update_window_title()
    
    def show_settings(self):
        """Switch to settings widget"""
        self.settings_widget.load_settings()
        self.stacked_widget.setCurrentWidget(self.settings_widget)
        self.update_window_title("Settings")
    
    def show_user_manager(self):
        """Switch to user manager widget"""
        if self.current_user and self.current_user.role == UserRole.ADMIN:
            self.user_manager.refresh_users()
            self.stacked_widget.setCurrentWidget(self.user_manager)
            self.update_window_title("User Management")
    
    def show_profile(self):
        """Switch to profile widget"""
        self.profile_widget.set_user(self.current_user)
        self.stacked_widget.setCurrentWidget(self.profile_widget)
        self.update_window_title("My Profile")
    
    def show_backup_manager(self):
        """Switch to backup manager widget"""
        if self.current_user and self.current_user.role == UserRole.ADMIN:
            self.stacked_widget.setCurrentWidget(self.backup_manager)
            self.update_window_title("Backup Manager")
    
    def on_backup_restored(self, result):
        """Handle backup restoration completion"""
        # Schedule an application restart
        self.restart_required = True

    def _create_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # User menu
        self.user_menu = menubar.addMenu("&User")
        self.user_menu.setEnabled(False)
        
        profile_action = QAction("My &Profile", self)
        profile_action.triggered.connect(self.show_profile)
        self.user_menu.addAction(profile_action)
        
        logout_action = QAction("&Logout", self)
        logout_action.triggered.connect(self.logout)
        self.user_menu.addAction(logout_action)
        
        # Admin menu
        self.admin_menu = menubar.addMenu("&Admin")
        self.admin_menu.setEnabled(False)
        
        user_mgmt_action = QAction("&User Management", self)
        user_mgmt_action.triggered.connect(self.show_user_manager)
        self.admin_menu.addAction(user_mgmt_action)
        
        backup_action = QAction("&Backup Manager", self)
        backup_action.triggered.connect(self.show_backup_manager)
        self.admin_menu.addAction(backup_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = QAction("&Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action) 