from PyQt5.QtWidgets import QApplication
from windows import mainwindow

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    mw = mainwindow.MainWindow()
    sys.exit(app.exec_())


