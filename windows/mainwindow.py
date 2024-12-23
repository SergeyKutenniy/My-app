from PyQt5.QtWidgets import (
    QWidget, QPushButton, QFileDialog, QApplication, QProgressBar, QTextEdit, QHBoxLayout, QVBoxLayout, QListWidgetItem, QMessageBox, QListWidget, QInputDialog, QDialog, QComboBox, QLabel, QDialogButtonBox, QLineEdit
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

class SettingsDialog(QDialog):
    def __init__(self, current_language, current_theme, parent=None):
        super().__init__(parent)
        self.language = current_language  # Получаем текущий язык
        self.theme = current_theme  # Получаем текущую тему
        self.setWindowTitle(self.translate("Settings"))  # Переводим заголовок
        self.resize(400, 200)

        # Установка стилей в зависимости от темы
        self.apply_theme_styles()

        # Элементы интерфейса
        self.language_label = QLabel(self.translate("Language:"))
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Українська"])
        self.language_combo.setCurrentText(self.language)  # Устанавливаем текущий язык

        self.theme_label = QLabel(self.translate("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([self.translate("Light"), self.translate("Dark")])

        self.theme_combo.setCurrentText(self.theme)

        # Компоновка
        layout = QVBoxLayout()
        layout.addWidget(self.language_label)
        layout.addWidget(self.language_combo)
        layout.addWidget(self.theme_label)
        layout.addWidget(self.theme_combo)

        # Кнопки
        self.ok_button = QPushButton(self.translate("Ok"))
        self.cancel_button = QPushButton(self.translate("Cancel"))
        self.ok_button.clicked.connect(self.apply_settings)
        self.cancel_button.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def apply_theme_styles(self):
        # Устанавливает стили для диалогового окна в зависимости от выбранной темы.
        if self.theme in ["Dark", "Темна"]:
            self.setStyleSheet("""
                QDialog {
                    background-color: #333333; /* Цвет фона диалогового окна */
                    border: 1px solid #333333; /* Граница окна */
                    border-radius: 8px; /* Закругленные углы */
                }
                QLabel {
                    color: white; /* Цвет текста */
                    font-size: 14px; /* Размер шрифта */
                }
                QComboBox {
                    background-color: #1E1E1E; /* Цвет фона выпадающего списка */
                    color: white; /* Цвет текста */
                    border: 1px solid #d3d3d3; /* Граница */
                    border-radius: 4px; /* Закругленные углы */
                    padding: 5px; /* Внутренний отступ */
                }
                QComboBox QAbstractItemView {
                    background-color: #444444; /* Фон выпадающего списка */
                    color: white; /* Цвет текста */
                    selection-background-color: #5b65f5; /* Цвет выделения */
                }
                QPushButton {
                    background: #7079f0;
                    color: white;
                    min-width: 100px;
                    font-size: 14px;
                    font-weight: 500;
                    border-radius: 0.5em;
                    border: none;
                    height: 1.5em;
                }

                QPushButton:hover {
                    background: #5b65f5;
                }

                QPushButton:pressed {
                    background: #404df7;  
                }
            """)
        else:  # Light theme
            self.setStyleSheet("""
                QDialog {
                    background-color: #EEEFF0; /* Цвет фона диалогового окна */
                    border: 1px solid #d3d3d3; /* Граница окна */
                    border-radius: 8px; /* Закругленные углы */
                }
                QLabel {
                    color: #333; /* Цвет текста */
                    font-size: 14px; /* Размер шрифта */
                }
                QComboBox {
                    background-color: #ffffff; /* Цвет фона выпадающего списка */
                    color: #000; /* Цвет текста */
                    border: 1px solid #d3d3d3; /* Граница */
                    border-radius: 4px; /* Закругленные углы */
                    padding: 5px; /* Внутренний отступ */
                }
                QComboBox QAbstractItemView {
                    background-color: #ffffff; /* Фон выпадающего списка */
                    color: black; /* Цвет текста */
                    selection-background-color: #7079f0; /* Цвет выделения */
                }
                QPushButton {
                    background: #7079f0;
                    color: white;
                    min-width: 100px;
                    font-size: 14px;
                    font-weight: 500;
                    border-radius: 0.5em;
                    border: none;
                    height: 1.5em;
                }

                QPushButton:hover {
                    background: #5b65f5;
                }

                QPushButton:pressed {
                    background: #404df7;  
                }
            """)

    def apply_settings(self):
        # Применяем настройки и закрываем окно.
        self.language = self.language_combo.currentText()
        self.theme = self.theme_combo.currentText()
        self.accept()

    def get_settings(self):
        # Возвращает выбранные настройки.
        return {
            "language": self.language_combo.currentText(),
            "theme": self.theme_combo.currentText()
        }

    def translate(self, text):
        # Функция перевода текста.
        translations = {
            "Settings": "Налаштування",
            "Language:": "Мова:",
            "Theme:": "Тема:",
            "Ok": "Оk",
            "Cancel": "Відміна",
            "Light": "Світла",
            "Dark": "Темна",
        }
        if self.language == "Українська":
            return translations.get(text, text)
        return text

class QuarantineWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.theme = "Light"  # Текущая тема
        self.list_widget = self.create_quarantine_table(self.theme)  # Создаем таблицу с текущей темой
        layout = QVBoxLayout()
        layout.addWidget(self.list_widget)
        self.setLayout(layout)

    def update_theme(self, theme):
        # Обновление темы таблицы
        self.theme = theme
        self.list_widget.setParent(None)  # Удаляем текущий виджет
        self.list_widget = self.create_quarantine_table(self.theme)  # Пересоздаем таблицу
        self.layout().addWidget(self.list_widget)  # Добавляем новую таблицу



class MainWindow(QWidget):
    QUARANTINE_FOLDER = "quarantine"
    QUARANTINE_LOG = "quarantine_log.json"  # Quarantine log

    def __init__(self):
        super().__init__()
        self.language = "English"
        self.theme = "Light"
        self.list_widget = QListWidget()
        self.result_box = QTextEdit()  # Инициализация result_box
        self.result_box.setReadOnly(True)
        self.set_window_properties()
        self.initUI()
        self.connect_signals()
        self.show()
        

    def set_window_properties(self):
        self.setWindowTitle('My_Antivirus')
        self.resize(800, 600)
        self.setStyleSheet(self.get_theme_stylesheet())

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
        self.b_scan_file = QPushButton(self.translate("Scan File"))
        self.b_scan_folder = QPushButton(self.translate("Scan Folder"))
        self.b_quarantine = QPushButton(self.translate("Quarantine"))
        self.b_exit = QPushButton(self.translate("Exit"))
        self.b_settings = QPushButton(self.translate("Settings"), self)
        self.b_delete = QPushButton(self.translate("Delete File"))
        self.b_restore = QPushButton(self.translate("Restore File"))
        self.b_scan_url = QPushButton(self.translate('Scan URL'))
        
         # Apply style to buttons
        for button in [
            self.b_scan_file, self.b_scan_folder, self.b_quarantine,
            self.b_exit, self.b_settings, self.b_delete, self.b_restore, self.b_scan_url
        ]:
            button.setStyleSheet(button_style)

        # Create vertical layout for buttons
        buttons_layout = QVBoxLayout()
        buttons_layout.addWidget(self.b_scan_file)
        buttons_layout.addWidget(self.b_scan_folder)
        buttons_layout.addWidget(self.b_quarantine)
        buttons_layout.addWidget(self.b_scan_url)
        buttons_layout.addWidget(self.b_settings)
        buttons_layout.addWidget(self.b_exit)
        
        # Main layout
        self.main_layout = QHBoxLayout()
        self.main_layout.addLayout(buttons_layout, stretch=1)
        self.right_layout = self.create_right_layout()
        self.main_layout.addLayout(self.right_layout, stretch=2)
        self.setLayout(self.main_layout)

    def translate(self, text):
        translations = {
            "Scan File": "Сканувати файл",
            "Scan Folder": "Сканувати папку",
            "Quarantine": "Карантин",
            "Exit": "Вихід",
            "Settings": "Налаштування",
            "Delete File": "Видалити файл",
            "Restore File": "Відновити файл",
            "Scan URL": "Сканувати URL",
            "Enter URL for scanning:": "Введіть URL для сканування:",
            "Scan Results for file": "Результат сканування файлу:",
            "Scan Results for URL:": "Результати сканування URL-адреси:",
            "Scan Error": "Помилка сканування",
            "⛔️ Error 429: Too many requests.": "⛔️ Помилка 429: Забагато запитів.",
            "Skipped": "⏩️ Файл пропущено",
            "🗑 File deleted": "🗑 Файл видалено",
            "⭕️ File moved to quarantine": "⭕️ Файл переміщено до карантину",
            "An error occurred. Skipping file.": "Сталася помилка. Пропускаємо файл.",
            "❌ Malicious file detected": "❌ Виявлено шкідливий файл",
            "❗️ Number of security providers": "❗️ Кількість антивірусів, які виявили шкідливий файл:",
            "✅ File is safe.": "✅ Файл безпечний.",
            "General result: All files are safe.": "Загальний результат: Всі файли безпечні",
            "General result: Found": "Загальний результат: Знайдено",
            " infected file(s).": " заражений(их) файл(ів).",
            "Scanning complete": "Сканування завершено",
            "Quarantine is empty": "Карантин пустий",
            "Cancel": "Відміна",
            "Malicious Reports": "Зловмисні звіти",
            "Reputation": "Репутація",
            "reputation": "Репутація",
            "Unknown": "Невідома",
            "Detailed Results:": "Результат сканування:",
            "❌ URL is flagged as malicious!": "❌ URL позначений як зловмисний",
            "✅ URL appears safe.": "✅ URL виглядає безпечним",
            "Quarantine": "В карантин",
            "Delete": "Видалити",
            "Skip": "Пропустити",
            "Retry": "Повторити",
            "Select an action:": "Оберіть дію:",
            "Threat Detected": "Виявлено загрозу",
            "The file": "Файл",
            "is infected.": "є зловмисним",
            "Too Many Requests": "Забагато запитів", 
            "Would you like to try scanning it again?": "Бажаєте спробувати відсканувати його ще раз?",
            "could not be scanned due to too many requests.": "не вдалося відсканувати через збільшену кількість запитів.",
            "Failed to scan": "Не вдалося просканувати",
            "after": "після",
            "attempts. Skipping file.": "спроб. Пропускаємо файл.",
            "Scan Error:": "Помилка сканування:",
            "error": "помилка",
            "Total checks:": "Усього перевірок:",
            "Unknown action for": "Невідома дія для",
            "File deleted": "Файл видалено", 
            "File restored to": "Файл відновлено до", 
            "No File Selected": "Файл не вибрано",
            "Please select a file to delete or restore.": "Будь ласка, виберіть файл для видалення або відновлення.",
            "File Not Found": "Файл не знайдено",
            "was not found.": "не було знайдено.",
        }
        if self.language == "Українська":
            return translations.get(text, text)
        return text
    
    
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
            QProgressBar { border: 2px solid #7079f0; border-radius: 0.5em; text-align: center; color: black; background: #fff; }
            QProgressBar::chunk { background: #7079f0; border-radius: 0.2em;}
        ''')
        return bar

    def create_result_box(self):
        box = QTextEdit()
        box.setReadOnly(True)
        box.setStyleSheet('background: white; border-radius: 0.5em; border: 1px solid #ccc; font-size: 14px;')
        return box


    def create_quarantine_table(self):  # Добавлен параметр theme
    
        # Установка стилей в зависимости от темы
        if self.theme in ["Dark", "Темна"]:
            self.list_widget.setStyleSheet('''
                QListWidget { background: #222; border: 1px solid #555; font-size: 14px; color: white; }
                QListWidget::item { padding: 5px; }
                QListWidget::item:selected { background: #5055f0; color: white; }
            ''')
        else:
            self.list_widget.setStyleSheet('''
                QListWidget { background: white; border: 1px solid #ccc; font-size: 14px; color: black; }
                QListWidget::item { padding: 5px; }
                QListWidget::item:selected { background: #7079f0; color: white; }
            ''')
    
        self.list_widget.hide()
        return self.list_widget

    def connect_signals(self):
        self.b_scan_file.clicked.connect(self.scan_file)
        self.b_scan_folder.clicked.connect(self.scan_folder)
        self.b_quarantine.clicked.connect(self.show_quarantine)
        self.b_exit.clicked.connect(QApplication.quit)
        self.b_settings.clicked.connect(self.open_settings)
        self.b_delete.clicked.connect(self.delete_selected_file)
        self.b_restore.clicked.connect(self.restore_selected_file)
        self.b_scan_url.clicked.connect(self.scan_url)

    def open_settings(self):
        settings_dialog = SettingsDialog(self.language, self.theme, self)
        if settings_dialog.exec_() == QDialog.Accepted:
            settings = settings_dialog.get_settings()
            self.language = settings["language"]
            self.theme = settings["theme"]
            self.update_ui()

    def update_ui(self):
        self.setStyleSheet(self.get_theme_stylesheet())
        self.b_scan_file.setText(self.translate("Scan File"))
        self.b_scan_folder.setText(self.translate("Scan Folder"))
        self.b_quarantine.setText(self.translate("Quarantine"))
        self.b_exit.setText(self.translate("Exit"))
        self.b_settings.setText(self.translate("Settings"))
        self.b_delete.setText(self.translate("Delete File"))
        self.b_restore.setText(self.translate("Restore File"))
        self.b_scan_url.setText(self.translate("Scan URL"))


    def get_theme_stylesheet(self):
        if self.theme in ["Dark", "Темна"]:
            # Устанавливаем темный стиль для result_box
            self.list_widget.setStyleSheet('''
                QListWidget { background: #222; border: 1px solid #555; font-size: 14px; color: white; }
                QListWidget::item { padding: 5px; }
                QListWidget::item:selected { background: #5055f0; color: white; }
            ''')
            self.result_box.setStyleSheet(
                'background: rgba(30, 30, 30, 1); border: 1px solid #666; border-radius: 0.5em; font-size: 14px; color: white;'
            )
            # Возвращаем темный стиль для всей программы
            return """
            QWidget { background: #333; color: white; }
            QPushButton { background: #555; color: white; border: 1px solid #777; }
            QPushButton:hover { background: #666; }
            QPushButton:pressed { background: #444; }
            """
        else:
            # Устанавливаем светлый стиль для result_box
            self.result_box.setStyleSheet(
                'background: white; border: 1px solid #ccc; border-radius: 0.5em; font-size: 14px; color: black;'
            )
            self.list_widget.setStyleSheet('''
                QListWidget { background: white; border: 1px solid #ccc; font-size: 14px; color: black; }
                QListWidget::item { padding: 5px; }
                QListWidget::item:selected { background: #7079f0; color: white; }
            ''')
            # Возвращаем светлый стиль для всей программы
            return """
            QWidget { background: #EEEFF0; color: black; }
            QPushButton { background: #ccc; color: black; border: 1px solid #aaa; }
            QPushButton:hover { background: #ddd; }
            QPushButton:pressed { background: #bbb; }
            """

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
        dialog = QInputDialog(self)
        dialog.setWindowTitle(f"{self.translate('Scan URL')}")
        dialog.setLabelText(f"{self.translate('Enter URL for scanning:')}")
        dialog.setCancelButtonText(self.translate("Cancel"))  # Перевод кнопки Cancel
        dialog.resize(400, 200)  # Устанавливаем размер окна (ширина, высота)
        self.result_box.show()
        self.quarantine_table.hide()

    # Применение стилей
        if self.theme in ["Dark", "Темна"]:
            dialog.setStyleSheet("""
            QInputDialog {
                background-color: #333333; /* Цвет фона диалогового окна */
                border: 1px solid #333333; /* Граница окна */
                border-radius: 8px; /* Закругленные углы */
            }
            QLabel {
                color: white; /* Цвет текста заголовка */
                font-size: 14px; /* Размер шрифта текста */
            }
            QPushButton {
                background: #7079f0;
                color: white;
                min-width: 100px;
                font-size: 14px;
                font-weight: 500;
                border-radius: 0.5em;
                border: none;
                height: 1.5em;
            }
            QPushButton:hover {
                background: #5b65f5;
            }
            QPushButton:pressed {
                background: #404df7;  
            }
        """)
        else:
            dialog.setStyleSheet("""
            QInputDialog {
                background-color: #EEEFF0; /* Цвет фона диалогового окна */
                border: 1px solid #d3d3d3; /* Граница окна */
                border-radius: 8px; /* Закругленные углы */
            }
            QLabel {
                color: #333; /* Цвет текста заголовка */
                font-size: 14px; /* Размер шрифта текста */
            }
            QPushButton {
                background: #7079f0;
                color: white;
                min-width: 100px;
                font-size: 14px;
                font-weight: 500;
                border-radius: 0.5em;
                border: none;
                height: 1.5em;
            }
            QPushButton:hover {
                background: #5b65f5;
            }
            QPushButton:pressed {
                background: #404df7;  
            }
        """)
        line_edit = dialog.findChild(QLineEdit)
        if line_edit:
            if self.theme in ["Dark", "Темна"]:
                line_edit.setStyleSheet("""
                QLineEdit {
                    background-color: #1E1E1E; /* Цвет фона текстового поля */
                    color: white; /* Цвет текста */
                    border: 1px solid #d3d3d3; /* Граница текстового поля */
                    border-radius: 4px; /* Закругленные углы */
                    padding: 5px; /* Внутренний отступ */
                }
            """)
            else:
                line_edit.setStyleSheet("""
                QLineEdit {
                    background-color: white; /* Цвет фона текстового поля */
                    color: #000; /* Цвет текста */
                    border: 1px solid #d3d3d3; /* Граница текстового поля */
                    border-radius: 4px; /* Закругленные углы */
                    padding: 5px; /* Внутренний отступ */
                }
            """)
    # Повторное применение стилей к кнопкам
        button_box = dialog.findChild(QDialogButtonBox)
        if button_box:
            cancel_button = button_box.button(QDialogButtonBox.Cancel)
            ok_button = button_box.button(QDialogButtonBox.Ok)
            if cancel_button:
                cancel_button.setStyleSheet("""
                QPushButton {
                    background: #7079f0;
                    color: white;
                    min-width: 100px;
                    font-size: 14px;
                    font-weight: 500;
                    border-radius: 0.5em;
                    border: none;
                    height: 1.5em;
                }
                QPushButton:hover {
                    background: #5b65f5;
                }
                QPushButton:pressed {
                    background: #404df7;  
                }
            """)
            if ok_button:
                ok_button.setStyleSheet("""
                QPushButton {
                    background: #7079f0;
                    color: white;
                    min-width: 100px;
                    font-size: 14px;
                    font-weight: 500;
                    border-radius: 0.5em;
                    border: none;
                    height: 1.5em;
                }
                QPushButton:hover {
                    background: #5b65f5;
                }
                QPushButton:pressed {
                    background: #404df7;  
                }
            """)

    # Отображение диалогового окна
        if dialog.exec_() == QInputDialog.Accepted:
            url = dialog.textValue()
            if url:
                self.result_box.append(f"Scanning URL: {url}\nPlease wait...")
                QApplication.processEvents()  # Обновляем интерфейс
                result = virustotal.scan_url(url)
                self.display_url_scan_result(url, result)
                self.progress_bar.setValue(100)


    def display_url_scan_result(self, url, result):
        # Очищаем поле результатов
        self.result_box.clear()
        self.result_box.append(self.translate("Scan Results for URL:") + f" {url}")
        self.result_box.append("=" * 50)

        if "error" in result:
            self.result_box.append(f"Scan Error: {result['error']}")
            return

        # Разбираем результаты анализа
        analysis_data = result.get("data", {}).get("attributes", {})
        malicious_count = analysis_data.get("stats", {}).get("malicious", 0)
        reputation = self.translate(analysis_data.get("reputation", "Unknown"))
        last_analysis_results = analysis_data.get("last_analysis_results", {})

        # Отображаем основные данные
        self.result_box.append(f"{self.translate('Malicious Reports')}: {malicious_count}")
        self.result_box.append(f"{self.translate('Reputation')}: {reputation}")
        self.result_box.append(self.translate("Detailed Results:"))

        # Подробный анализ от поставщиков
        for engine, details in last_analysis_results.items():
            category = details.get("category", "unknown")
            result = details.get("result", "clean")
            self.result_box.append(f"{engine}: {category} ({result})")

        if malicious_count > 0:
            self.result_box.append(self.translate("❌ URL is flagged as malicious!"))
        else:
            self.result_box.append(self.translate("✅ URL appears safe."))

        self.result_box.append("=" * 50)
        self.result_box.append(f"{self.translate('Scanning complete')}")
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
            self.quarantine_table.addItem(f"{self.translate('Quarantine is empty')}")
            return

        with open(self.QUARANTINE_LOG, "r") as f:
            log_data = json.load(f)

        quarantined_files = [entry for entry in log_data if entry["status"] == "quarantined" and os.path.exists(entry["quarantine_path"])]
        for entry in log_data:
            if entry["status"] == "quarantined" and not os.path.exists(entry["quarantine_path"]):
                self.remove_file_from_log(entry)

        if not quarantined_files:
            self.quarantine_table.addItem(f"{self.translate('Quarantine is empty')}")
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
        self.processed_files = 0
        self.infected_files = []

        for file_path in files:
            thread = FileScanThread(file_path)
            thread.progress.connect(self.handle_scan_result)  # Обрабатываем результаты
            thread.finished.connect(self.update_progress_bar)
            self.threads.append(thread)
            thread.start()

    def handle_scan_result(self, file_path, result):
        # Переводим сообщения перед отображением
        self.result_box.append(f"{self.translate('Scan Results for file')}: {file_path}")
        self.result_box.append("=" * 50)

        if "error" in result:
            error_message = result["error"]
            self.result_box.append(f"{self.translate('Scan Error')}: {error_message}")

            # Проверяем на ошибку 429
            if "429" in error_message or "Too Many Requests" in error_message:
                self.result_box.append(f"{self.translate('⛔️ Error 429: Too many requests.')}")
                retry = self.show_retry_dialog(file_path)
                if retry:
                    self.retry_scan(file_path)
                else:
                    self.result_box.append(f"{self.translate('Skipped')}: {file_path}")
            else:
                self.result_box.append(f"{self.translate('An error occurred. Skipping file.')}")
        else:
            malicious_count = result.get('malicious_count', 0)
            if malicious_count > 0:
                self.result_box.append(f"{self.translate('❌ Malicious file detected')}: {file_path}")
                self.result_box.append(f"{self.translate('❗️ Number of security providers')}: {malicious_count}")
                self.infected_files.append(file_path)

                # Показываем диалог и обрабатываем выбор
                action = self.show_infected_file_dialog(file_path)
                self.handle_infected_file_action(action, file_path)
            else:
                self.result_box.append(f"{self.translate('✅ File is safe.')}")

        self.result_box.append("=" * 50 + "\n")



    def show_retry_dialog(self, file_path):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle(self.translate("Too Many Requests"))
        msg_box.setText(f"{self.translate('The file')} {file_path} {self.translate('could not be scanned due to too many requests.')}")
        msg_box.setInformativeText(self.translate("Would you like to try scanning it again?"))
    
        # Добавляем кнопки
        retry_button = msg_box.addButton(self.translate("Retry"), QMessageBox.AcceptRole)
        skip_button = msg_box.addButton(self.translate("Skip"), QMessageBox.RejectRole)

        # Запускаем диалог
        msg_box.exec_()

        # Пытаемся вернуть, какая кнопка была нажата
        if msg_box.clickedButton() == retry_button:
            return True  # Retry
        elif msg_box.clickedButton() == skip_button:
            return False  # Skip
        return False  # По умолчанию, если ошибка


    def retry_scan(self, file_path, retries=3):
        # """Повторяет сканирование файла до заданного количества попыток."""
        for attempt in range(retries):
            self.result_box.append(f"Retrying scan for {file_path}... (Attempt {attempt + 1}/{retries})")
            result = virustotal.upload_file(file_path)
            if "error" in result and "429" in result["error"]:
                time.sleep(1)  # Ждём перед повторной попыткой
            else:
                self.handle_scan_result(file_path, result)
                return

        # Если после всех попыток ошибка сохраняется
        self.result_box.append(f"❌ {self.translate('Failed to scan')} {file_path} {self.translate('after')} {retries} {self.translate('attempts. Skipping file.')}")

    def update_scan_result(self, file_path, scan_result):
            # Выводим результат в текстовое поле
            self.result_box.append(f"{self.translate('Scan Results for file')}: {file_path}")
            self.result_box.append("=" * 50)
            if "error" in scan_result:
                self.result_box.append(f"{self.translate('Scan Error:')} {scan_result['error']}")
            else:
                self.result_box.append(f"{self.translate('Total checks:')} {sum(scan_result.get(f'{category}_count', 0) for category in ['malicious', 'harmless', 'suspicious', 'undetected'])}")
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
                self.result_box.append(self.translate("General result: Found") + f" {len(self.infected_files)}" + self.translate(" infected file(s)."))

            else:
                self.result_box.append(f"{self.translate('General result: All files are safe.')}")
            self.result_box.append("=" * 50)
            self.result_box.append(f"{self.translate('Scanning complete')}")


    def display_scan_result(self, vt_result, file_path):
        self.result_box.append(f"{self.translate('Scan Results for file')}: {file_path}")
        self.result_box.append("=" * 50)
        if "error" in vt_result:
            self.result_box.append(f"{self.translate('Scan Error:')} {vt_result['error']}")

            return

        self.result_box.append(f"{self.translate('Total checks:')} {sum(vt_result.get(f'{category}_count', 0) for category in ['malicious', 'harmless', 'suspicious', 'undetected'])}")
        for category in ['malicious', 'harmless', 'suspicious', 'undetected']:
            self.result_box.append(f"{category.capitalize()}: {vt_result.get(f'{category}_count', 0)}")

        self.result_box.append("\n" + "=" * 50 + "\n")

    def show_infected_file_dialog(self, file_path):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle(self.translate("Threat Detected"))
        msg_box.setText(f"{self.translate('The file')} {file_path} {self.translate('is infected.')}")
        msg_box.setInformativeText(self.translate("Select an action:"))
    
        # Создаем кнопки
        quarantine_button = msg_box.addButton(self.translate("Quarantine"), QMessageBox.AcceptRole)
        delete_button = msg_box.addButton(self.translate("Delete"), QMessageBox.DestructiveRole)
        skip_button = msg_box.addButton(self.translate("Skip"), QMessageBox.RejectRole)

        delete_button.setStyleSheet("""
        QPushButton {
            background-color: #d9534f; /* Красный цвет для Delete */
            color: white;
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background-color: #c9302c;
        }
        QPushButton:pressed {
            background-color: #ac2925;
        }
    """)
        skip_button.setStyleSheet("""
        QPushButton {
            background-color: #7079f0; /* Красный цвет для Delete */
            color: white;
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background: #5b65f5;
        }
       QPushButton:pressed {
            background: #404df7;  
                }
    """)
        quarantine_button.setStyleSheet("""
        QPushButton {
            background-color: #f0ad4e; /* Желтый цвет для Quarantine */
            color: white;
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background-color: #ec971f;
        }
        QPushButton:pressed {
            background-color: #d58512;
        }
    """)
        msg_box.setStyleSheet("""
        QMessageBox {
            background-color: #EEEFF0; /* Фон окна */
            border-radius: 8px; /* Закругленные углы */
            font-size: 14px; /* Размер шрифта */
        }
        QLabel {
            color: #333; /* Цвет текста */
            font-size: 14px; /* Размер шрифта текста */
        }
        QPushButton {
            background-color: #7079f0; /* Фон кнопок */
            color: white; /* Цвет текста кнопок */
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background-color: #5b65f5;
        }
        QPushButton:pressed {
            background-color: #404df7;
        }
    """)

        if self.theme in ["Dark", "Темна"]:
            msg_box.setStyleSheet("""
        QMessageBox {
            background-color: #333333; /* Фон окна */
        }
        QLabel {
            color: white; /* Цвет текста */
        }
        """)
    
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
            self.result_box.append(f"{self.translate('Unknown action for')} {file_path}")

    # Методы для обработки действий
    def quarantine_file(self, file_path):
        self.result_box.append(f"{self.translate('⭕️ File moved to quarantine')}: {file_path}")
        self.move_to_quarantine(file_path)

    def delete_file(self, file_path):
         os.remove(file_path)
         self.result_box.append(f"{self.translate('🗑 File deleted')}: {file_path}")

    def skip_file(self, file_path):
        self.result_box.append(f"{self.translate('Skipped')}: {file_path}")
        # Ничего не делаем


    def move_to_quarantine(self, file_path):
        quarantine_path = os.path.join(self.QUARANTINE_FOLDER, os.path.basename(file_path))
        os.makedirs(self.QUARANTINE_FOLDER, exist_ok=True)
        shutil.move(file_path, quarantine_path)

        file_info = {
            "file_name": os.path.basename(file_path),
            "quarantine_path": quarantine_path,
            "original_path": file_path,  # Сохраняем оригинальный путь
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
                self.result_box.append(f"{self.translate('File deleted')}: {file_path}")
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
            original_path = file_entry.get("original_path")  # Берём оригинальный путь из логов
            if os.path.exists(file_path):
                os.makedirs(os.path.dirname(original_path), exist_ok=True)  # Создаём папку, если её нет
                shutil.move(file_path, original_path)
                self.result_box.append(f"{self.translate('File restored to')}: {original_path}")
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
        msg.setWindowTitle(self.translate("No File Selected"))
        msg.setText(self.translate("Please select a file to delete or restore."))  
        msg.setStandardButtons(QMessageBox.Ok)

        ok_button = msg.button(QMessageBox.Ok)
        if ok_button:
            ok_button.setStyleSheet("""
            QPushButton {
                background-color: #7079f0;
                width: 100px;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
                padding: 6px 12px;
                border: none;
            }
            QPushButton:hover {
                background-color: #5b65f5;
            }
            QPushButton:pressed {
                background-color: #404df7;
            }
        """)


        msg.exec_()

    # Add helper method to show "File not found" message
    def show_file_not_found_message(self, file_path):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle(self.translate("File Not Found"))
        msg.setText(f"{self.translate('The file')} '{file_path}' {self.translate('was not found.')}")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

