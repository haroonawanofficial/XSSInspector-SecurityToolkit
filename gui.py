import sys
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QLineEdit,
    QCheckBox,
    QFileDialog,
    QProgressBar,
)
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor
from PyQt5.QtCore import QTimer, QThread, Qt, pyqtSignal

class AnimatedProgressBar(QProgressBar):
    def __init__(self, duration=1000, steps=100):
        super().__init__()
        self.duration = duration
        self.steps = steps
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_animation)
        self.animation_value = 0
        self.animation_direction = 1
        self.is_running = False

        self.setFixedWidth(100)
        self.setTextVisible(False)
        self.setMinimum(0)
        self.setMaximum(100)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(
            "QProgressBar { border: 2px solid grey; border-radius: 10px; background-color: #f0f0f0; } "
            "QProgressBar::chunk { background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #49a2db, stop: 1 #105384); }"
        )

    def set_bar_width(self, bar_width):
        self.setFixedWidth(bar_width)

    def start_animation(self):
        if not self.is_running:
            self.is_running = True
            self.timer.start(self.duration // self.steps)

    def stop_animation(self):
        self.is_running = False
        self.timer.stop()
        self.setValue(0)

    def update_animation(self):
        if not self.is_running:
            return

        if self.animation_value == 0:
            self.animation_direction = 1
        elif self.animation_value == self.steps:
            self.animation_direction = -1

        self.animation_value += self.animation_direction
        self.setValue(int((self.animation_value / self.steps) * 100))

class ScanThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    scan_stopped_signal = pyqtSignal()

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.stopped = False

    def run(self):
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in iter(self.process.stdout.readline, ''):
                if self.isInterruptionRequested():
                    break
                self.update_signal.emit(line)

            self.process.wait()
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}")

    def stop_scan(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.kill()

class XSSInspectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.scanning_thread = ScanThread([])
        self.executor = ThreadPoolExecutor(max_workers=50)
        os.environ['PYTHONUNBUFFERED'] = '1'
        self.unique_results = set()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('XSS Inspector')
        self.setGeometry(100, 100, 600, 400)
        self.create_input_elements()
        self.create_results_text_areas()
        self.create_progress_bar()

        self.layout = QVBoxLayout()

        self.layout.addWidget(self.domain_label)
        self.layout.addWidget(self.domain_input)
        self.layout.addWidget(self.url_list_label)
        self.layout.addWidget(self.url_list_input)
        self.layout.addWidget(self.browse_button)
        self.layout.addWidget(self.reports_checkbox)
        self.layout.addWidget(self.threads_checkbox)
        self.layout.addWidget(self.include_subdomain_checkbox)
        self.layout.addWidget(self.deep_crawl_checkbox)
        self.layout.addWidget(self.results_text)
        self.layout.addWidget(self.testing_results_text)
        self.layout.addWidget(self.potential_results_text)

        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        self.layout.addLayout(progress_layout)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.scan_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addWidget(self.close_button)
        self.layout.addLayout(buttons_layout)

        self.layout.addWidget(self.link_label)

        self.setLayout(self.layout)

        self.connect_signals()

        self.domain_input.setPlaceholderText('Enter domain that you want to scan')
        self.url_list_input.setPlaceholderText('Select URL list file which has hosts on each new line')

        self.results_text.setText('No information yet, waiting for code to run')
        self.testing_results_text.setText('No testing results yet, waiting for code to run')
        self.potential_results_text.setText('No potential XSS results yet, waiting for code to run')

    def connect_signals(self):
        self.scanning_thread.update_signal.connect(self.append_results_text)
        self.scanning_thread.progress_signal.connect(self.update_progress_bar)
        self.scanning_thread.scan_stopped_signal.connect(self.scan_stopped)
        self.scan_button.clicked.connect(self.start_scan)

    def scan_stopped(self):
        self.scan_finished()
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.stop_animation()  # Stop the animation when the scan is finished

    def append_results_text(self, text):
        self.results_text.append(text)

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

    def create_input_elements(self):
        self.domain_label = QLabel('Domain:', self)
        self.domain_input = QLineEdit(self)

        self.url_list_label = QLabel('URL List File:', self)
        self.url_list_input = QLineEdit(self)
        self.browse_button = QPushButton('Browse', self)
        self.browse_button.clicked.connect(self.browse_for_file)

        self.reports_checkbox = QCheckBox('Generate Reports', self)
        self.threads_checkbox = QCheckBox('Use 50 Threads', self)
        self.include_subdomain_checkbox = QCheckBox('Include Subdomains', self)
        self.deep_crawl_checkbox = QCheckBox('Deep Crawl', self)

        self.scan_button = QPushButton('Start Scan', self)
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton('Stop Scan', self)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.close_button = QPushButton('Close App', self)
        self.close_button.clicked.connect(self.close_app)

        self.link_label = QLabel(
            '<div style="display: flex; justify-content: space-between;">'
            '<span style="text-align: left;">'
            'Hyperthreading, concurrency and 96 obfuscation functions loaded successfully'
            '</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            '<span style="margin-right:100px!important;">'
            '<b>XSS Inspector</b> by Haroon Ahmad Awan | <a href="http://www.cyberzeus.pk">Cyberzeus.pk</a>'
            '</span>'
            '</div>',
            self
        )
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_link)

    def create_results_text_areas(self):
        self.results_text = QTextEdit('No information yet, waiting for code to run', self)
        self.results_text.setReadOnly(True)

        self.testing_results_text = QTextEdit('No testing results yet, waiting for code to run', self)
        self.testing_results_text.setReadOnly(True)

        self.potential_results_text = QTextEdit('No potential XSS results yet, waiting for code to run', self)
        self.potential_results_text.setReadOnly(True)

    # Modify the update_results_text method
    def update_results_text(self, output):
        print(f"Received output: {output}")
        
        if "testing" in output.lower():
            self.append_to_text_edit(output, self.testing_results_text)
        elif "potential" in output.lower():
            self.append_to_text_edit(output, self.potential_results_text)
        else:
            self.append_to_text_edit(output, self.results_text)

    # Modify the append_to_text_edit method to handle initial text setting
    def append_to_text_edit(self, text, text_edit):
        if text_edit.toPlainText() == text_edit.placeholderText():
            text_edit.clear()
        cursor = text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        text_edit.setTextCursor(cursor)
        text_edit.ensureCursorVisible()

    def create_progress_bar(self):
        self.progress_label = QLabel('Status of Payload Analysis:', self)
        self.progress_bar = AnimatedProgressBar()
        self.stop_button.setEnabled(False)

    def start_scan(self):
        if not self.scanning_thread or not self.scanning_thread.isRunning():
            self.results_text.clear()
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.progress_bar.start_animation()  # Start the animation when the scan starts
            self.set_text_color("Initializing...\n", QColor("darkGreen"))
            domain = self.domain_input.text()
            url_list = self.url_list_input.text()

            if not domain and not url_list:
                self.set_text_color("Please enter a domain or select a URL list file.", QColor("red"))
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return

            command = ["python3", "xssinspector.py", "--domain", domain, "--list", url_list]

            if not self.scanning_thread or not self.scanning_thread.isRunning():
                self.scanning_thread = ScanThread(command)
                self.scanning_thread.update_signal.connect(self.update_results_text)
                self.scanning_thread.progress_signal.connect(self.update_progress_bar)
                self.scanning_thread.scan_stopped_signal.connect(self.scan_stopped)
                self.scanning_thread.start()

    def stop_scan(self):
        if self.scanning_thread and self.scanning_thread.isRunning():
            self.scanning_thread.stop_scan()
            self.stop_button.setEnabled(False)
            self.scan_button.setEnabled(True)  # Enable Start Scan button after stopping
            self.progress_bar.stop_animation()  # Stop the animation when the scan is stopped

    def close_app(self):
        self.close()

    def open_link(self, link):
        QDesktopServices.openUrl(QUrl(link))

    def browse_for_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Select URL List File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            self.url_list_input.setText(file_name)

    def set_text_color(self, text, color):
        cursor = self.results_text.textCursor()
        format = QTextCharFormat()
        format.setForeground(color)
        cursor.insertText(text, format)

    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.stop_animation()  # Stop the animation when the scan is finished

if __name__ == "__main__":
    app = QApplication(sys.argv)
    xss_app = XSSInspectorApp()
    xss_app.show()
    sys.exit(app.exec_())
