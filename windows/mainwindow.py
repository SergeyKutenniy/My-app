from PyQt5.QtWidgets import (
    QWidget, QPushButton, QFileDialog, QApplication, QProgressBar, QTextEdit, QHBoxLayout, QVBoxLayout, QListWidgetItem, QTableWidgetItem, QMessageBox, QListWidget, QInputDialog
)
from PyQt5.QtCore import Qt
import os
import json
import shutil
from datetime import datetime
from helpers import virustotal
from PyQt5.QtCore import QThread, pyqtSignal
import time

class FileScanThread(QThread):
    progress = pyqtSignal(str, dict)  # Сигнал: путь файла и результат
    finished = pyqtSignal()

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        # Выполняем сканирование
        result = virustotal.upload_file(self.file_path)
        self.progress.emit(self.file_path, result)  # Передаем результат проверки
        self.finished.emit()


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
        button_style = """
    QPushButton {
            background: #7079f0;
            color: white;
            min-width: 150px;
            font-size: 16px;
            font-weight: 500;
            border-radius: 0.5em;
            border: none;
            height: 2.5em;
    }

    QPushButton:hover {
            background: #5b65f5;
    }

    QPushButton:pressed {
        background: #404df7;  
    }
    """

        # Create buttons
        self.b_scan_file = QPushButton('Scan File')
        self.b_scan_folder = QPushButton('Scan Folder')
        self.b_quarantine = QPushButton('Quarantine')
        self.b_exit = QPushButton('Exit')
        self.b_delete = QPushButton("Delete File")
        self.b_restore = QPushButton("Restore File")
        self.b_scan_url = QPushButton('Scan URL')
        
        # Apply style to buttons
        self.b_scan_file.setStyleSheet(button_style)
        self.b_scan_folder.setStyleSheet(button_style)
        self.b_quarantine.setStyleSheet(button_style)
        self.b_exit.setStyleSheet(button_style)
        self.b_delete.setStyleSheet(button_style)  # Assuming you have a delete button
        self.b_restore.setStyleSheet(button_style)
        self.b_scan_url.setStyleSheet(button_style)

        # Create vertical layout for buttons
        buttons_layout = QVBoxLayout()
        buttons_layout.addWidget(self.b_scan_file)
        buttons_layout.addWidget(self.b_scan_folder)
        buttons_layout.addWidget(self.b_quarantine)
        buttons_layout.addWidget(self.b_scan_url)
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

        # Create quarantine buttons
        
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


    def create_quarantine_table(self):  # Updated to use QListWidget
        list_widget = QListWidget()
        list_widget.setStyleSheet('''
            QListWidget { background: white; border: 1px solid #ccc; font-size: 14px; }
            QListWidget::item { padding: 5px; }
            QListWidget::item:selected { background: #7079f0; color: white; }
        ''')
        list_widget.hide()
        return list_widget
    

    def connect_signals(self):
        self.b_scan_file.clicked.connect(self.scan_file)
        self.b_scan_folder.clicked.connect(self.scan_folder)
        self.b_quarantine.clicked.connect(self.show_quarantine)
        self.b_exit.clicked.connect(QApplication.quit)
        self.b_delete.clicked.connect(self.delete_selected_file)
        self.b_restore.clicked.connect(self.restore_selected_file)
        self.b_scan_url.clicked.connect(self.scan_url)

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

    def scan_url(self):
        # Показываем диалоговое окно для ввода URL
        url, ok = QInputDialog.getText(self, "Scan URL", "Enter URL for scanning:")
        if ok and url:
            self.result_box.append(f"Scanning URL: {url}\nPlease wait...")
            QApplication.processEvents()  # Обновляем интерфейс
            result = virustotal.scan_url(url)
            self.display_url_scan_result(url, result)
            self.progress_bar.setValue(100)

    def display_url_scan_result(self, url, result):
        # Очищаем поле результатов
        self.result_box.clear()
        self.result_box.append(f"Scan Results for URL: {url}")
        self.result_box.append("=" * 50)

        if "error" in result:
            self.result_box.append(f"Scan Error: {result['error']}")
            return

        # Разбираем результаты анализа
        analysis_data = result.get("data", {}).get("attributes", {})
        malicious_count = analysis_data.get("stats", {}).get("malicious", 0)
        total_votes = analysis_data.get("stats", {}).get("total", 0)
        reputation = analysis_data.get("reputation", "Unknown")
        last_analysis_results = analysis_data.get("last_analysis_results", {})

        # Отображаем основные данные
        self.result_box.append(f"Total Votes: {total_votes}")
        self.result_box.append(f"Malicious Reports: {malicious_count}")
        self.result_box.append(f"Reputation: {reputation}")
        self.result_box.append("\nDetailed Results:")

        # Подробный анализ от поставщиков
        for engine, details in last_analysis_results.items():
            category = details.get("category", "unknown")
            result = details.get("result", "clean")
            self.result_box.append(f"{engine}: {category} ({result})")

        if malicious_count > 0:
            self.result_box.append("❌ URL is flagged as malicious!")
        else:
            self.result_box.append("✅ URL appears safe.")

        self.result_box.append("=" * 50)
        self.result_box.ensureCursorVisible()

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
        self.quarantine_table.clear()
        if not os.path.exists(self.QUARANTINE_LOG):
            self.quarantine_table.addItem("Quarantine is empty")
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        quarantined_files = [entry for entry in log_data if entry["status"] == "quarantined" and os.path.exists(entry["quarantine_path"])]
        for entry in log_data:
            if entry["status"] == "quarantined" and not os.path.exists(entry["quarantine_path"]):
                self.remove_file_from_log(entry)

        if not quarantined_files:
            self.quarantine_table.addItem("Quarantine is empty")
        else:
            for file in quarantined_files:
                item = QListWidgetItem(f"{file['file_name']} - {file['quarantine_path']} ({file['date']})")
                item.setData(Qt.UserRole, file)  # Store the file entry as data
                self.quarantine_table.addItem(item)

        self.b_delete.setVisible(True)
        self.b_restore.setVisible(True)

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
        self.threads = []
        total_files = len(files)
        self.processed_files = 0
        self.infected_files = []

        for file_path in files:
            thread = FileScanThread(file_path)
            thread.progress.connect(self.handle_scan_result)  # Обрабатываем результаты
            thread.finished.connect(self.update_progress_bar)
            self.threads.append(thread)
            thread.start()

    def handle_scan_result(self, file_path, result):
        self.result_box.append(f"Scan Results for file: {file_path}")
        self.result_box.append("=" * 50)

        if "error" in result:
            error_message = result["error"]
            self.result_box.append(f"Scan Error: {error_message}")

            # Проверяем на ошибку 429
            if "429" in error_message or "Too Many Requests" in error_message:
                self.result_box.append("⚠️ Error 429: Too many requests.")
                retry = self.show_retry_dialog(file_path)
                if retry:
                    self.retry_scan(file_path)
                else:
                    self.result_box.append(f"❌ Skipping file: {file_path}")
            else:
                self.result_box.append("⚠️ An error occurred. Skipping file.")
        else:
            malicious_count = result.get('malicious_count', 0)
            if malicious_count > 0:
                self.result_box.append(f"⚠️ Malicious file detected: {file_path} (Malicious count: {malicious_count})")
                self.infected_files.append(file_path)

                # Показываем диалог и обрабатываем выбор
                action = self.show_infected_file_dialog(file_path)
                self.handle_infected_file_action(action, file_path)
            else:
                self.result_box.append("✅ File is safe.")

        self.result_box.append("=" * 50 + "\n")


    def show_retry_dialog(self, file_path):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Too Many Requests")
        msg_box.setText(f"The file {file_path} could not be scanned due to too many requests.")
        msg_box.setInformativeText("Would you like to try scanning it again?")
    
        # Добавляем кнопки
        retry_button = msg_box.addButton("Retry", QMessageBox.AcceptRole)
        skip_button = msg_box.addButton("Skip", QMessageBox.RejectRole)

        # Запускаем диалог
        msg_box.exec_()

        # Пытаемся вернуть, какая кнопка была нажата
        if msg_box.clickedButton() == retry_button:
            return True  # Retry
        elif msg_box.clickedButton() == skip_button:
            return False  # Skip
        return False  # По умолчанию, если ошибка


    def retry_scan(self, file_path, retries=3):
        """Повторяет сканирование файла до заданного количества попыток."""
        for attempt in range(retries):
            self.result_box.append(f"Retrying scan for {file_path}... (Attempt {attempt + 1}/{retries})")
            result = virustotal.upload_file(file_path)
            if "error" in result and "429" in result["error"]:
                time.sleep(5)  # Ждём перед повторной попыткой
            else:
                self.handle_scan_result(file_path, result)
                return

        # Если после всех попыток ошибка сохраняется
        self.result_box.append(f"❌ Failed to scan {file_path} after {retries} attempts. Skipping file.")


    def update_scan_result(self, file_path, scan_result):
            # Выводим результат в текстовое поле
            self.result_box.append(f"Scan Results for file: {file_path}")
            self.result_box.append("=" * 50)
            if "error" in scan_result:
                self.result_box.append(f"Scan Error: {scan_result['error']}")
            else:
                self.result_box.append(f"Total checks: {sum(scan_result.get(f'{category}_count', 0) for category in ['malicious', 'harmless', 'suspicious', 'undetected'])}")
                for category in ['malicious', 'harmless', 'suspicious', 'undetected']:
                    self.result_box.append(f"{category.capitalize()}: {scan_result.get(f'{category}_count', 0)}")
        
            self.result_box.append("\n" + "=" * 50 + "\n")
            self.result_box.ensureCursorVisible()

    def scan_single_file(self, file_path):
        retry_count = 3  # Максимальное количество повторных попыток
        for attempt in range(retry_count):
            scan_result = virustotal.upload_file(file_path)
            if "error" in scan_result and "429" in scan_result["error"]:
                time.sleep(5)  # Ждём 5 секунд перед повторной попыткой
            else:
                break  # Успешно, выходим из цикла
        self.update_scan_result(file_path, scan_result)
        self.update_progress_bar()


    def update_progress_bar(self):
        self.processed_files += 1
        total_files = len(self.threads)
        self.progress_bar.setValue(int((self.processed_files / total_files) * 100))

        if self.processed_files == total_files:  # Все файлы обработаны
            if self.infected_files:
                self.result_box.append(f"\nResults: Found {len(self.infected_files)} infected file(s).")
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
    
        # Создаем кнопки
        quarantine_button = msg_box.addButton("Quarantine", QMessageBox.AcceptRole)
        delete_button = msg_box.addButton("Delete", QMessageBox.DestructiveRole)
        skip_button = msg_box.addButton("Skip", QMessageBox.RejectRole)

        msg_box.exec_()  # Показываем диалог

        # Проверяем, какая кнопка была нажата
        if msg_box.clickedButton() == quarantine_button:
            return "quarantine"
        elif msg_box.clickedButton() == delete_button:
            return "delete"
        elif msg_box.clickedButton() == skip_button:
            return "skip"
        else:
            return None  # Если что-то пошло не так

    def handle_infected_file_action(self, action, file_path):
        if action == "quarantine":
            self.quarantine_file(file_path)
        elif action == "delete":
            self.delete_file(file_path)
        elif action == "skip":
            self.skip_file(file_path)
        else:
            self.result_box.append(f"Unknown action for {file_path}")

    # Методы для обработки действий
    def quarantine_file(self, file_path):
        self.result_box.append(f"🛡 File moved to quarantine: {file_path}")
        self.move_to_quarantine(file_path)

    def delete_file(self, file_path):
         os.remove(file_path)
         self.result_box.append(f"🗑 File deleted: {file_path}")

    def skip_file(self, file_path):
        self.result_box.append(f"⏩ File skipped: {file_path}")
        # Ничего не делаем


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
        selected_item = self.quarantine_table.currentItem()
        if selected_item:  # Check if an item is selected
            file_entry = selected_item.data(Qt.UserRole)
            file_path = file_entry["quarantine_path"]
            if os.path.exists(file_path):
                os.remove(file_path)
                self.result_box.append(f"File deleted: {file_path}")
                self.remove_file_from_log(file_entry)
                self.load_quarantine()
            else:
                self.show_file_not_found_message(file_path)
        else:
            self.show_no_file_selected_message()

    def restore_selected_file(self):
        selected_item = self.quarantine_table.currentItem()
        if selected_item:  # Check if an item is selected
            file_entry = selected_item.data(Qt.UserRole)
            file_path = file_entry["quarantine_path"]
            original_path = os.path.join(os.getcwd(), file_entry["file_name"])
            if os.path.exists(file_path):
                shutil.move(file_path, original_path)
                self.result_box.append(f"File restored from quarantine: {file_path}")
                self.remove_file_from_log(file_entry)
                self.load_quarantine()
            else:
                self.show_file_not_found_message(file_path)
        else:
            self.show_no_file_selected_message()

    # Add helper method to show the "No file selected" message
    def show_no_file_selected_message(self):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("No File Selected")
        msg.setText("Please select a file to delete or restore.")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    # Add helper method to show "File not found" message
    def show_file_not_found_message(self, file_path):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("File Not Found")
        msg.setText(f"The file '{file_path}' was not found.")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

