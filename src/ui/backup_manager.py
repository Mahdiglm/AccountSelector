import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

from PySide6.QtCore import Qt, Signal, QObject, Slot, QTimer, QSize, QThread
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QProgressBar, QFileDialog, QMessageBox,
    QDialog, QLineEdit, QFormLayout, QCheckBox, QComboBox, QFrame,
    QScrollArea, QSizePolicy, QSpacerItem, QListWidget, QListWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QSpinBox, QDialogButtonBox
)
from PySide6.QtGui import QIcon, QPixmap, QFont, QColor, QPalette

from ..data.models import Backup
from ..data.storage import Storage

class BackupTableWidget(QTableWidget):
    """Custom table widget for displaying backups"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "Name", "Created Date", "Size", "Users", "Accounts", "Encrypted"
        ])
        
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        # Set column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Name column
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
    def populate(self, backups: List[Backup]):
        """Populate the table with backup data"""
        self.setRowCount(0)  # Clear table
        
        for backup in backups:
            row = self.rowCount()
            self.insertRow(row)
            
            # Name
            self.setItem(row, 0, QTableWidgetItem(backup.name))
            
            # Created date
            date_str = backup.created_at.strftime("%Y-%m-%d %H:%M:%S")
            self.setItem(row, 1, QTableWidgetItem(date_str))
            
            # Size
            size_str = self._format_size(backup.size_bytes)
            self.setItem(row, 2, QTableWidgetItem(size_str))
            
            # Users
            self.setItem(row, 3, QTableWidgetItem(str(backup.user_count)))
            
            # Accounts
            self.setItem(row, 4, QTableWidgetItem(str(backup.account_count)))
            
            # Encrypted
            encrypted_item = QTableWidgetItem("Yes" if backup.is_encrypted else "No")
            encrypted_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 5, encrypted_item)
            
            # Store backup ID in first column's data
            self.item(row, 0).setData(Qt.UserRole, backup.id)
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def get_selected_backup_id(self) -> Optional[str]:
        """Get ID of the currently selected backup"""
        selected_items = self.selectedItems()
        if not selected_items:
            return None
            
        row = selected_items[0].row()
        return self.item(row, 0).data(Qt.UserRole)

class BackupSettingsDialog(QDialog):
    """Dialog for configuring backup settings"""
    
    def __init__(self, config: Dict[str, Any], parent=None):
        super().__init__(parent)
        
        self.config = config
        self.setWindowTitle("Backup Settings")
        self.resize(400, 300)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        form_layout = QFormLayout()
        
        # Auto backup
        self.auto_backup_checkbox = QCheckBox()
        self.auto_backup_checkbox.setChecked(config.get("backup", {}).get("auto_backup", True))
        form_layout.addRow("Enable automatic backups:", self.auto_backup_checkbox)
        
        # Backup interval
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setMinimum(1)
        self.interval_spinbox.setMaximum(90)
        self.interval_spinbox.setValue(config.get("backup", {}).get("backup_interval_days", 7))
        form_layout.addRow("Backup interval (days):", self.interval_spinbox)
        
        # Max backups
        self.max_backups_spinbox = QSpinBox()
        self.max_backups_spinbox.setMinimum(1)
        self.max_backups_spinbox.setMaximum(100)
        self.max_backups_spinbox.setValue(config.get("backup", {}).get("max_backups", 5))
        form_layout.addRow("Maximum backups to keep:", self.max_backups_spinbox)
        
        # Default encryption
        self.encrypt_checkbox = QCheckBox()
        self.encrypt_checkbox.setChecked(config.get("backup", {}).get("encrypt_backups", True))
        form_layout.addRow("Encrypt backups by default:", self.encrypt_checkbox)
        
        layout.addLayout(form_layout)
        
        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_settings(self) -> Dict[str, Any]:
        """Get the settings from the dialog"""
        if "backup" not in self.config:
            self.config["backup"] = {}
            
        self.config["backup"]["auto_backup"] = self.auto_backup_checkbox.isChecked()
        self.config["backup"]["backup_interval_days"] = self.interval_spinbox.value()
        self.config["backup"]["max_backups"] = self.max_backups_spinbox.value()
        self.config["backup"]["encrypt_backups"] = self.encrypt_checkbox.isChecked()
        
        return self.config

class PasswordDialog(QDialog):
    """Dialog for entering master password for backup restoration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle("Master Password")
        self.resize(350, 100)
        
        layout = QVBoxLayout(self)
        
        form_layout = QFormLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Enter master password:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_password(self) -> str:
        """Get the entered password"""
        return self.password_input.text()

class BackupProgressDialog(QDialog):
    """Dialog for displaying backup or restore progress"""
    
    def __init__(self, operation: str, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle(f"{operation} in Progress")
        self.resize(400, 150)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Status label
        self.status_label = QLabel(f"{operation} in progress...")
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        layout.addWidget(self.progress_bar)
        
        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Buttons (cancel only)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)
    
    def set_status(self, message: str):
        """Update the status message"""
        self.status_label.setText(message)
    
    def set_progress(self, value: int, maximum: int):
        """Set determinate progress"""
        self.progress_bar.setRange(0, maximum)
        self.progress_bar.setValue(value)
    
    def operation_complete(self, success: bool, message: str):
        """Update dialog when operation completes"""
        if success:
            self.status_label.setText(f"✅ {message}")
        else:
            self.status_label.setText(f"❌ {message}")
        
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100 if success else 0)
        
        # Change cancel button to close
        self.button_box.clear()
        self.button_box.addButton(QDialogButtonBox.Close)
        self.button_box.rejected.connect(self.accept)

class BackupThread(QThread):
    """Thread for running backup operations"""
    
    progress_signal = Signal(str)
    finished_signal = Signal(bool, str, object)
    
    def __init__(self, storage: Storage, operation: str, **kwargs):
        super().__init__()
        
        self.storage = storage
        self.operation = operation
        self.kwargs = kwargs
        self.result = None
    
    def run(self):
        try:
            if self.operation == "create":
                self.progress_signal.emit("Creating backup...")
                backup = self.storage.create_backup(
                    name=self.kwargs.get("name"),
                    encrypt=self.kwargs.get("encrypt", True)
                )
                self.result = backup
                self.finished_signal.emit(
                    True, 
                    f"Backup created successfully: {backup.name}", 
                    backup
                )
                
            elif self.operation == "restore":
                self.progress_signal.emit("Preparing to restore from backup...")
                result = self.storage.restore_from_backup(
                    backup_path=self.kwargs.get("backup_path"),
                    master_password=self.kwargs.get("password")
                )
                self.result = result
                self.finished_signal.emit(
                    True, 
                    "Restore completed successfully", 
                    result
                )
                
        except Exception as e:
            self.finished_signal.emit(False, f"Error: {str(e)}", None)

class BackupManager(QWidget):
    """Backup Manager widget for creating and restoring backups"""
    
    backup_created = Signal(Backup)
    restore_completed = Signal(Dict[str, Any])
    
    def __init__(self, storage: Storage, parent=None):
        super().__init__(parent)
        
        self.storage = storage
        self.backups = []
        
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the UI components"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Title and controls
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Backup Manager")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.load_backups)
        header_layout.addWidget(self.refresh_button)
        
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.show_settings)
        header_layout.addWidget(self.settings_button)
        
        main_layout.addLayout(header_layout)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        # Backups table
        self.backups_table = BackupTableWidget()
        self.backups_table.itemSelectionChanged.connect(self.update_button_states)
        main_layout.addWidget(self.backups_table)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.create_button = QPushButton("Create Backup")
        self.create_button.clicked.connect(self.create_backup)
        button_layout.addWidget(self.create_button)
        
        self.restore_button = QPushButton("Restore")
        self.restore_button.clicked.connect(self.restore_backup)
        self.restore_button.setEnabled(False)
        button_layout.addWidget(self.restore_button)
        
        self.import_button = QPushButton("Import")
        self.import_button.clicked.connect(self.import_backup)
        button_layout.addWidget(self.import_button)
        
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_backup)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_backup)
        self.delete_button.setEnabled(False)
        button_layout.addWidget(self.delete_button)
        
        main_layout.addLayout(button_layout)
        
        # Status bar
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Load backups
        QTimer.singleShot(0, self.load_backups)
    
    def load_backups(self):
        """Load and display all backups"""
        try:
            self.status_label.setText("Loading backups...")
            QApplication.processEvents()
            
            self.backups = self.storage.list_backups()
            self.backups_table.populate(self.backups)
            
            self.status_label.setText(f"Found {len(self.backups)} backups")
            self.update_button_states()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load backups: {str(e)}")
            self.status_label.setText("Error loading backups")
    
    def update_button_states(self):
        """Update button enabled states based on selection"""
        has_selection = self.backups_table.get_selected_backup_id() is not None
        
        self.restore_button.setEnabled(has_selection)
        self.export_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)
    
    def show_settings(self):
        """Show backup settings dialog"""
        dialog = BackupSettingsDialog(self.storage.config, self)
        if dialog.exec():
            updated_config = dialog.get_settings()
            
            # Save the updated config
            try:
                self.storage.update_config(updated_config)
                self.status_label.setText("Backup settings updated")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
    
    def create_backup(self):
        """Create a new backup"""
        # Ask for backup name
        name, ok = QLineEdit.getText(
            self, "Create Backup", "Enter a name for this backup:", 
            text=f"Backup {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        
        if not ok or not name:
            return
            
        # Ask for encryption preference
        default_encrypt = self.storage.config.get("backup", {}).get("encrypt_backups", True)
        encrypt = QMessageBox.question(
            self, "Encryption", 
            "Do you want to encrypt this backup?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes if default_encrypt else QMessageBox.No
        ) == QMessageBox.Yes
        
        # Show progress dialog
        progress_dialog = BackupProgressDialog("Backup", self)
        
        # Create and run backup thread
        self.backup_thread = BackupThread(
            self.storage, 
            "create", 
            name=name, 
            encrypt=encrypt
        )
        
        self.backup_thread.progress_signal.connect(progress_dialog.set_status)
        self.backup_thread.finished_signal.connect(
            lambda success, msg, result: self._on_backup_complete(success, msg, result, progress_dialog)
        )
        
        self.backup_thread.start()
        progress_dialog.exec()
    
    def _on_backup_complete(self, success: bool, message: str, result: object, dialog: BackupProgressDialog):
        """Handle backup completion"""
        dialog.operation_complete(success, message)
        
        if success and result:
            # Refresh backups list
            self.load_backups()
            
            # Emit signal
            if isinstance(result, Backup):
                self.backup_created.emit(result)
    
    def restore_backup(self):
        """Restore from selected backup"""
        backup_id = self.backups_table.get_selected_backup_id()
        if not backup_id:
            return
            
        # Find backup by ID
        backup = next((b for b in self.backups if b.id == backup_id), None)
        if not backup:
            QMessageBox.warning(self, "Error", "Selected backup not found")
            return
        
        # Confirm restore
        confirm = QMessageBox.warning(
            self, "Confirm Restore", 
            f"Are you sure you want to restore from '{backup.name}'?\n\n"
            "This will replace all current data with the backup data.\n"
            "A backup of your current data will be created automatically.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
        
        # If encrypted, ask for password
        password = None
        if backup.is_encrypted:
            password_dialog = PasswordDialog(self)
            if password_dialog.exec():
                password = password_dialog.get_password()
            else:
                return
        
        # Show progress dialog
        progress_dialog = BackupProgressDialog("Restore", self)
        
        # Create and run restore thread
        self.restore_thread = BackupThread(
            self.storage, 
            "restore", 
            backup_path=backup.file_path,
            password=password
        )
        
        self.restore_thread.progress_signal.connect(progress_dialog.set_status)
        self.restore_thread.finished_signal.connect(
            lambda success, msg, result: self._on_restore_complete(success, msg, result, progress_dialog)
        )
        
        self.restore_thread.start()
        progress_dialog.exec()
    
    def _on_restore_complete(self, success: bool, message: str, result: object, dialog: BackupProgressDialog):
        """Handle restore completion"""
        dialog.operation_complete(success, message)
        
        if success and result:
            # Emit signal for app to reload data
            self.restore_completed.emit(result)
            
            # Ask to restart app
            QMessageBox.information(
                self, "Restart Required", 
                "Restore completed successfully. You need to restart the application for changes to take effect."
            )
    
    def import_backup(self):
        """Import a backup file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Backup", "", "Backup Files (*.zip)"
        )
        
        if not file_path or not os.path.exists(file_path):
            return
        
        try:
            # Copy the file to backups directory
            backup_dir = os.path.join(self.storage.data_folder, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            dest_path = os.path.join(backup_dir, filename)
            
            # Check if file already exists
            if os.path.exists(dest_path):
                new_filename = f"{os.path.splitext(filename)[0]}_imported_{int(time.time())}.zip"
                dest_path = os.path.join(backup_dir, new_filename)
            
            # Copy the file
            import shutil
            shutil.copy2(file_path, dest_path)
            
            QMessageBox.information(
                self, "Import Successful", 
                f"Backup imported successfully."
            )
            
            # Refresh list
            self.load_backups()
            
        except Exception as e:
            QMessageBox.critical(self, "Import Failed", f"Failed to import backup: {str(e)}")
    
    def export_backup(self):
        """Export selected backup to a file"""
        backup_id = self.backups_table.get_selected_backup_id()
        if not backup_id:
            return
            
        # Find backup by ID
        backup = next((b for b in self.backups if b.id == backup_id), None)
        if not backup:
            QMessageBox.warning(self, "Error", "Selected backup not found")
            return
        
        # Ask for destination
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Backup", 
            f"{backup.name.replace(' ', '_')}.zip", 
            "Backup Files (*.zip)"
        )
        
        if not file_path:
            return
        
        try:
            # Copy the file
            import shutil
            shutil.copy2(backup.file_path, file_path)
            
            QMessageBox.information(
                self, "Export Successful", 
                f"Backup exported successfully to '{file_path}'."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export backup: {str(e)}")
    
    def delete_backup(self):
        """Delete selected backup"""
        backup_id = self.backups_table.get_selected_backup_id()
        if not backup_id:
            return
            
        # Find backup by ID
        backup = next((b for b in self.backups if b.id == backup_id), None)
        if not backup:
            QMessageBox.warning(self, "Error", "Selected backup not found")
            return
        
        # Confirm delete
        confirm = QMessageBox.warning(
            self, "Confirm Delete", 
            f"Are you sure you want to delete the backup '{backup.name}'?\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
        
        try:
            # Delete the file
            if os.path.exists(backup.file_path):
                os.remove(backup.file_path)
            
            QMessageBox.information(
                self, "Delete Successful", 
                f"Backup '{backup.name}' deleted successfully."
            )
            
            # Refresh list
            self.load_backups()
            
        except Exception as e:
            QMessageBox.critical(self, "Delete Failed", f"Failed to delete backup: {str(e)}") 