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
    QUARANTINE_LOG = "quarantine_log.json"  # Лог для карантина

    def __init__(self):
        super().__init__()
        self.set_win()
        self.initUI()
        self.connects()
        self.show()

    def set_win(self):
        self.setWindowTitle('Антивирус')
        self.resize(800, 600)
        self.setStyleSheet('background: rgba(207, 207, 207, 1);')

    def initUI(self):
        self.main_layout = QHBoxLayout()

        # --- Основной стиль кнопок ---
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

        # --- Основные кнопки ---
        buttons_layout = QVBoxLayout()
        self.b_scan_file = QPushButton('Сканировать файл')
        self.b_scan_folder = QPushButton('Сканировать папку')
        self.b_quarantine = QPushButton('Карантин')
        self.b_exit = QPushButton('Выход')

        for button in [self.b_scan_file, self.b_scan_folder, self.b_quarantine, self.b_exit]:
            button.setStyleSheet(button_style)
            buttons_layout.addWidget(button, alignment=Qt.AlignTop)

        buttons_layout.addStretch()

        # --- Правая часть (прогрессбар, результат, таблица) ---
        self.right_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet('''
            QProgressBar {
                border: 1px solid #7079f0;
                text-align: center;
                color: black;
                background: #fff;
            }
            QProgressBar::chunk {
                background: #7079f0;
            }
        ''')

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setStyleSheet('''
            background: white;
            border: 1px solid #ccc;
            font-size: 14px;
        ''')

        self.right_layout.addWidget(self.progress_bar)
        self.right_layout.addWidget(self.result_box)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(3)
        self.quarantine_table.setHorizontalHeaderLabels(["Имя файла", "Путь", "Дата"])
        self.quarantine_table.hide()
        self.right_layout.addWidget(self.quarantine_table)

        # --- Кнопки управления карантином ---
        self.b_delete = QPushButton("Удалить файл")
        self.b_restore = QPushButton("Восстановить файл")
        self.b_delete.setStyleSheet(button_style)
        self.b_restore.setStyleSheet(button_style)

        # Скрываем кнопки по умолчанию
        self.b_delete.setVisible(False)
        self.b_restore.setVisible(False)

        self.right_layout.addWidget(self.b_delete)
        self.right_layout.addWidget(self.b_restore)

        # --- Расположение основной компоновки ---
        self.main_layout.addLayout(buttons_layout, stretch=1)
        self.main_layout.addLayout(self.right_layout, stretch=2)
        self.setLayout(self.main_layout)


    def connects(self):
        self.b_scan_file.clicked.connect(self.click_scan_file)
        self.b_scan_folder.clicked.connect(self.click_scan_folder)
        self.b_quarantine.clicked.connect(self.click_quarantine)
        self.b_exit.clicked.connect(QApplication.quit)
        self.b_delete.clicked.connect(self.delete_selected_file)
        self.b_restore.clicked.connect(self.restore_selected_file)

    def click_scan_file(self):
        self.result_box.show()
        self.quarantine_table.hide()

         # Скрываем кнопки
        self.b_delete.setVisible(False)
        self.b_restore.setVisible(False)

        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.scan_files([file_path])

    def click_scan_folder(self):
        self.result_box.show()
        self.quarantine_table.hide()

         # Скрываем кнопки
        self.b_delete.setVisible(False)
        self.b_restore.setVisible(False)

        directory = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if directory:
            files = [
                os.path.join(root, file)
                for root, _, files in os.walk(directory) for file in files
            ]
            self.scan_files(files)

    def click_quarantine(self):
        self.result_box.hide()
        self.quarantine_table.show()

        # Делаем кнопки видимыми
        self.b_delete.setVisible(True)
        self.b_restore.setVisible(True)

        if not os.path.exists(self.QUARANTINE_LOG):
            self.quarantine_table.setRowCount(1)
            self.quarantine_table.setItem(0, 0, QTableWidgetItem("Карантин пуст"))
            self.quarantine_table.setSpan(0, 0, 1, 3)
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        quarantined_files = []
        for entry in log_data:
            if entry["status"] == "quarantined":
                file_path = entry["quarantine_path"]
                if os.path.exists(file_path):
                    quarantined_files.append(entry)
                else:
                    self.remove_file_from_log(entry)

        if not quarantined_files:
            self.quarantine_table.setRowCount(1)
            self.quarantine_table.setItem(0, 0, QTableWidgetItem("Карантин пуст"))
            self.quarantine_table.setSpan(0, 0, 1, 3)
        else:
            self.quarantine_table.setRowCount(len(quarantined_files))
            for row, file in enumerate(quarantined_files):
                self.quarantine_table.setItem(row, 0, QTableWidgetItem(file["file_name"]))
                self.quarantine_table.setItem(row, 1, QTableWidgetItem(file["quarantine_path"]))
                self.quarantine_table.setItem(row, 2, QTableWidgetItem(file["date"]))


    def remove_file_from_log(self, file_entry):
        """Удаляет запись о файле из лога карантина, если файл не существует"""
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

            self.result_box.append(f"Scan results for file: {file_path}")
            self.result_box.append("=" * 50)

            if "error" in vt_result:
                self.result_box.append(f"Error during scan: {vt_result['error']}")
                continue

            total_engines = sum(vt_result[f"{category}_count"] for category in ["malicious", "harmless", "suspicious", "undetected"])
    
            self.result_box.append(f"Total number of scans: {total_engines}")
            self.result_box.append(f"Threats detected: {vt_result['malicious_count']}")
            self.result_box.append(f"Harmless: {vt_result['harmless_count']}")
            self.result_box.append(f"Suspicious: {vt_result['suspicious_count']}")
            self.result_box.append(f"Undetected: {vt_result['undetected_count']}")
            self.result_box.append("")

            for category, engines in vt_result["engine_results"].items():
                if engines:
                    self.result_box.append(f"{category.capitalize()} engines:")
                    for engine in engines:
                        self.result_box.append(f"  - {engine['engine']}: {engine['result']} (Version: {engine['engine_version']}, Updated: {engine['update']})")
                    self.result_box.append("")

            if vt_result['malicious_count'] > 0:
                infected_files.append(file_path)
                self.result_box.append("❌ File may contain threats!")
            else:
                self.result_box.append("✅ File is considered safe.")

            self.result_box.append("\n" + "=" * 50 + "\n")

        if not infected_files:
            self.result_box.append("Summary: All files are safe!")
        else:
            self.result_box.append(f"Summary: Potentially dangerous files detected: {len(infected_files)}")
            for file in infected_files:
                self.result_box.append(f" - {file}")

        self.result_box.append("\nScan completed.")


    def show_virus_warning(self, file_path):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Обнаружен вирус")
        msg.setText(f"Файл {file_path} был обнаружен как вирус.")
        msg.setInformativeText("Что вы хотите сделать с этим файлом?")
        
        # Добавляем кастомные кнопки с логичными надписями
        move_button = msg.addButton("Переместить в карантин", QMessageBox.AcceptRole)
        delete_button = msg.addButton("Удалить файл", QMessageBox.RejectRole)
        cancel_button = msg.addButton("Отменить", QMessageBox.DestructiveRole)

        msg.setDefaultButton(cancel_button)

        response = msg.exec_()

        if msg.clickedButton() == move_button:
            # Переместить в карантин
            if self.move_to_quarantine(file_path):
                self.result_box.append(f"Файл {file_path} перемещен в карантин.")
        elif msg.clickedButton() == delete_button:
            # Удалить файл
            if self.delete_file(file_path):
                self.result_box.append(f"Файл {file_path} был удалён.")
    
    def move_to_quarantine(self, file_path):
        """Перемещает файл в карантин и обновляет лог"""
        try:
            if not os.path.exists(self.QUARANTINE_FOLDER):
                os.makedirs(self.QUARANTINE_FOLDER)

            file_name = os.path.basename(file_path)
            quarantine_path = self.get_unique_quarantine_path(file_name)

            # Перемещаем файл
            shutil.move(file_path, quarantine_path)

            # Логирование
            self.log_quarantine_file(file_name, file_path, quarantine_path)
            return True
        except Exception as e:
            return False
        

    def load_quarantine(self):
    # """Обновляет содержимое таблицы карантина."""
        self.quarantine_table.clearContents()

        if not os.path.exists(self.QUARANTINE_LOG):
            self.quarantine_table.setRowCount(1)
            self.quarantine_table.setItem(0, 0, QTableWidgetItem("Карантин пуст"))
            self.quarantine_table.setSpan(0, 0, 1, 3)
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        quarantined_files = []
        for entry in log_data:
            if entry["status"] == "quarantined":
                file_path = entry["quarantine_path"]
                # Проверяем, существует ли файл в карантине
                if os.path.exists(file_path):
                    quarantined_files.append(entry)
                else:
                    # Если файл не найден, удаляем запись из логов
                    self.remove_file_from_log(entry)

        if not quarantined_files:
            self.quarantine_table.setRowCount(1)
            self.quarantine_table.setItem(0, 0, QTableWidgetItem("Карантин пуст"))
            self.quarantine_table.setSpan(0, 0, 1, 3)
        else:
            self.quarantine_table.setRowCount(len(quarantined_files))
            for row, file in enumerate(quarantined_files):
                self.quarantine_table.setItem(row, 0, QTableWidgetItem(file["file_name"]))
                self.quarantine_table.setItem(row, 1, QTableWidgetItem(file["quarantine_path"]))
                self.quarantine_table.setItem(row, 2, QTableWidgetItem(file["date"]))

        
    def get_unique_quarantine_path(self, file_name):
        """
        Возвращает уникальный путь для файла в карантине, если файл с таким именем уже существует.
        """
        quarantine_path = os.path.join(self.QUARANTINE_FOLDER, file_name)
        
        # Если файл с таким именем уже существует, добавляем метку времени
        if os.path.exists(quarantine_path):
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            name, ext = os.path.splitext(file_name)
            quarantine_path = os.path.join(self.QUARANTINE_FOLDER, f"{name}_{timestamp}{ext}")
        
        return quarantine_path

    def delete_file(self, file_path):
        try:
            os.remove(file_path)
            return True
        except Exception as e:
            return False

    def log_quarantine_file(self, file_name, original_path, quarantine_path):
        """Добавляет запись о файле в лог карантина"""
        log_data = []
        if os.path.exists(self.QUARANTINE_LOG):
            with open(self.QUARANTINE_LOG, "r") as f:
                log_data = json.load(f)

        log_data.append({
            "file_name": file_name,
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "quarantined"
        })

        with open(self.QUARANTINE_LOG, "w") as f:
            json.dump(log_data, f, indent=4)


    def remove_file_from_log(self, file_entry):
        """Удаляет запись из лог-файла."""
        if not os.path.exists(self.QUARANTINE_LOG):
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        log_data = [entry for entry in log_data if entry != file_entry]

        with open(self.QUARANTINE_LOG, "w") as f:
            json.dump(log_data, f, indent=4)

    def delete_selected_file(self):
        """Удаляет выбранный файл из карантина и из лог-файла."""
        selected_row = self.quarantine_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для удаления.")
            return

        file_path = self.quarantine_table.item(selected_row, 1).text()

        if os.path.exists(file_path):
            os.remove(file_path)

        # Удаляем запись из лог-файла
        file_name = self.quarantine_table.item(selected_row, 0).text()
        self.remove_file_from_log({"file_name": file_name, "quarantine_path": file_path})
        self.load_quarantine()

    def restore_selected_file(self):
        """Восстанавливает выбранный файл из карантина в исходное место."""
        selected_row = self.quarantine_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для восстановления.")
            return

        file_name = self.quarantine_table.item(selected_row, 0).text()
        quarantine_path = self.quarantine_table.item(selected_row, 1).text()

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        for entry in log_data:
            if entry["file_name"] == file_name and entry["quarantine_path"] == quarantine_path:
                original_path = entry["original_path"]
                break
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось найти исходный путь файла.")
            return

        if not os.path.exists(quarantine_path):
            QMessageBox.warning(self, "Ошибка", "Файл отсутствует в карантине.")
            return

        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantine_path, original_path)

        # Удаляем запись из лог-файла
        self.remove_file_from_log({"file_name": file_name, "quarantine_path": quarantine_path})
        self.load_quarantine()

