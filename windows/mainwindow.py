from PyQt5.QtWidgets import (
    QWidget, QPushButton, QFileDialog, QApplication, QProgressBar, QTextEdit, QHBoxLayout, QVBoxLayout, QTableWidget, QTableWidgetItem, QMessageBox
)
from PyQt5.QtCore import Qt
import os
import json
import shutil
from datetime import datetime
from helpers import virustotal


class MainWindow(QWidget):
    QUARANTINE_FOLDER = "quarantine"
    QUARANTINE_LOG = "quarantine_log.json"  # Quarantine log

    def __init__(self):
        super().__init__()
        self.set_window_properties()
        self.initUI()
        self.connect_signals()
        self.show()

    def set_window_properties(self):
        self.setWindowTitle('Antivirus')
        self.resize(800, 600)
        self.setStyleSheet('background: rgba(207, 207, 207, 1);')

    def initUI(self):
        button_style = '''
            background: #7079f0;
            color: white;
            min-width: 150px;
            font-size: 16px;
            font-weight: 500;
            border-radius: 0.5em;
            border: none;
            height: 2.5em;
        '''

        # Create buttons
        self.b_scan_file = QPushButton('Scan File')
        self.b_scan_folder = QPushButton('Scan Folder')
        self.b_quarantine = QPushButton('Quarantine')
        self.b_exit = QPushButton('Exit')

        # Apply style to buttons
        self.b_scan_file.setStyleSheet(button_style)
        self.b_scan_folder.setStyleSheet(button_style)
        self.b_quarantine.setStyleSheet(button_style)
        self.b_exit.setStyleSheet(button_style)

        # Create vertical layout for buttons
        buttons_layout = QVBoxLayout()
        buttons_layout.addWidget(self.b_scan_file)
        buttons_layout.addWidget(self.b_scan_folder)
        buttons_layout.addWidget(self.b_quarantine)
        buttons_layout.addWidget(self.b_exit)

        # Main layout
        self.main_layout = QHBoxLayout()
        self.main_layout.addLayout(buttons_layout, stretch=1)
        self.right_layout = self.create_right_layout()
        self.main_layout.addLayout(self.right_layout, stretch=2)
        self.setLayout(self.main_layout)

    def create_right_layout(self):
        layout = QVBoxLayout()
        self.progress_bar = self.create_progress_bar()
        self.result_box = self.create_result_box()
        self.quarantine_table = self.create_quarantine_table()

        layout.addWidget(self.progress_bar)
        layout.addWidget(self.result_box)
        layout.addWidget(self.quarantine_table)

        self.b_delete = QPushButton("Delete File")
        self.b_restore = QPushButton("Restore File")
        self.b_delete.setStyleSheet(self.b_restore.styleSheet())
        self.b_restore.setStyleSheet(self.b_delete.styleSheet())
        self.b_delete.setVisible(False)
        self.b_restore.setVisible(False)

        layout.addWidget(self.b_delete)
        layout.addWidget(self.b_restore)
        return layout

    def create_progress_bar(self):
        bar = QProgressBar()
        bar.setValue(0)
        bar.setStyleSheet('''
            QProgressBar { border: 1px solid #7079f0; text-align: center; color: black; background: #fff; }
            QProgressBar::chunk { background: #7079f0; }
        ''')
        return bar

    def create_result_box(self):
        box = QTextEdit()
        box.setReadOnly(True)
        box.setStyleSheet('background: white; border: 1px solid #ccc; font-size: 14px;')
        return box

    def create_quarantine_table(self):
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["File Name", "Path", "Date"])
        table.hide()
        return table

    def connect_signals(self):
        self.b_scan_file.clicked.connect(self.scan_file)
        self.b_scan_folder.clicked.connect(self.scan_folder)
        self.b_quarantine.clicked.connect(self.show_quarantine)
        self.b_exit.clicked.connect(QApplication.quit)
        self.b_delete.clicked.connect(self.delete_selected_file)
        self.b_restore.clicked.connect(self.restore_selected_file)

    def scan_file(self):
        self.show_scan_view()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.scan_files([file_path])

    def scan_folder(self):
        self.show_scan_view()
        directory = QFileDialog.getExistingDirectory(self, "Select Folder")
        if directory:
            files = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]
            self.scan_files(files)

    def show_scan_view(self):
        self.result_box.show()
        self.quarantine_table.hide()
        self.b_delete.setVisible(False)
        self.b_restore.setVisible(False)

    def show_quarantine(self):
        self.result_box.hide()
        self.quarantine_table.show()
        self.load_quarantine()

    def load_quarantine(self):
        if not os.path.exists(self.QUARANTINE_LOG):
            self.display_empty_quarantine()
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        quarantined_files = [entry for entry in log_data if entry["status"] == "quarantined" and os.path.exists(entry["quarantine_path"])]
        for entry in log_data:
            if entry["status"] == "quarantined" and not os.path.exists(entry["quarantine_path"]):
                self.remove_file_from_log(entry)

        if not quarantined_files:
            self.display_empty_quarantine()
        else:
            self.populate_quarantine_table(quarantined_files)

    def display_empty_quarantine(self):
        self.quarantine_table.setRowCount(1)
        self.quarantine_table.setItem(0, 0, QTableWidgetItem("Quarantine Empty"))
        self.quarantine_table.setSpan(0, 0, 1, 3)

    def populate_quarantine_table(self, quarantined_files):
        self.quarantine_table.setRowCount(len(quarantined_files))
        for row, file in enumerate(quarantined_files):
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(file["file_name"]))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(file["quarantine_path"]))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(file["date"]))

    def remove_file_from_log(self, file_entry):
        if not os.path.exists(self.QUARANTINE_LOG):
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        log_data = [entry for entry in log_data if entry != file_entry]
        with open(self.QUARANTINE_LOG, "w") as f:
            json.dump(log_data, f, indent=4)

    def scan_files(self, files):
        self.result_box.clear()
        self.progress_bar.setValue(0)
        total_files = len(files)
        infected_files = []

        for i, file_path in enumerate(files, start=1):
            self.progress_bar.setValue(int((i / total_files) * 100))
            vt_result = virustotal.upload_file(file_path)
            self.display_scan_result(vt_result, file_path)
            if vt_result.get('malicious_count', 0) > 0:
                infected_files.append(file_path)
                action = self.show_infected_file_dialog(file_path)
                self.handle_infected_file_action(action, file_path)
            else:
                self.result_box.append("✅ File is safe.")

        if infected_files:
            self.result_box.append(f"\nResults: Found {len(infected_files)} infected file(s).")
        else:
            self.result_box.append("Results: All files are safe.")
        self.result_box.append("\nScanning complete.")

    def display_scan_result(self, vt_result, file_path):
        self.result_box.append(f"Scan Results for file: {file_path}")
        self.result_box.append("=" * 50)
        if "error" in vt_result:
            self.result_box.append(f"Scan Error: {vt_result['error']}")
            return

        self.result_box.append(f"Total checks: {sum(vt_result.get(f'{category}_count', 0) for category in ['malicious', 'harmless', 'suspicious', 'undetected'])}")
        for category in ['malicious', 'harmless', 'suspicious', 'undetected']:
            self.result_box.append(f"{category.capitalize()}: {vt_result.get(f'{category}_count', 0)}")

        self.result_box.append("\n" + "=" * 50 + "\n")

    def show_infected_file_dialog(self, file_path):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Threat Detected")
        msg_box.setText(f"The file {file_path} is infected.")
        msg_box.setInformativeText("Select an action:")
        msg_box.addButton("Delete", QMessageBox.AcceptRole)
        msg_box.addButton("Move to Quarantine", QMessageBox.ActionRole)
        msg_box.addButton("Skip", QMessageBox.RejectRole)
        msg_box.exec_()
        return {"Delete": "delete", "Move to Quarantine": "quarantine"}.get(msg_box.clickedButton().text(), "skip")

    def handle_infected_file_action(self, action, file_path):
        if action == "delete":
            os.remove(file_path)
            self.result_box.append(f"🗑 File deleted: {file_path}")
        elif action == "quarantine":
            self.move_to_quarantine(file_path)
            self.result_box.append(f"🛑 File moved to quarantine: {file_path}")
        else:
            self.result_box.append(f"File skipped: {file_path}")

    def move_to_quarantine(self, file_path):
        quarantine_path = os.path.join(self.QUARANTINE_FOLDER, os.path.basename(file_path))
        os.makedirs(self.QUARANTINE_FOLDER, exist_ok=True)
        shutil.move(file_path, quarantine_path)

        file_info = {
            "file_name": os.path.basename(file_path),
            "quarantine_path": quarantine_path,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "quarantined"
        }

        if os.path.exists(self.QUARANTINE_LOG):
            with open(self.QUARANTINE_LOG, "r") as f:
                log_data = json.load(f)
        else:
            log_data = []

        log_data.append(file_info)
        with open(self.QUARANTINE_LOG, "w") as f:
            json.dump(log_data, f, indent=4)

    def delete_selected_file(self):
        selected_row = self.quarantine_table.currentRow()
        if selected_row >= 0:
            file_path = self.quarantine_table.item(selected_row, 1).text()
            if os.path.exists(file_path):
                os.remove(file_path)
                self.result_box.append(f"🗑 File deleted: {file_path}")
                self.load_quarantine()

    def restore_selected_file(self):
        selected_row = self.quarantine_table.currentRow()
        if selected_row >= 0:
            file_path = self.quarantine_table.item(selected_row, 1).text()
            quarantine_path = self.quarantine_table.item(selected_row, 0).text()
            shutil.move(file_path, quarantine_path)
            self.result_box.append(f"File restored from quarantine: {file_path}")
            self.load_quarantine()

