import sys
import os
import subprocess
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
from PyQt5.QtCore import QTimer, pyqtSlot, QUrl, QThread, Qt
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QTextCursor
from datetime import datetime
from PyQt5.QtGui import QDesktopServices

class AnimatedProgressBar(QProgressBar):
    def __init__(self, duration=1000, steps=1000):
        super().__init__()
        self.duration = duration
        self.steps = steps
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_animation)
        self.animation_value = 0
        self.animation_direction = 1
        self.is_running = False

        # Customize the appearance of the progress bar
        self.setFixedWidth(100)  # Set the default width of the progress bar
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

    def update_animation(self):
        if not self.is_running:
            return

        if self.animation_value == 0:
            self.animation_direction = 1
        elif self.animation_value == self.steps:
            self.animation_direction = -1

        self.animation_value += self.animation_direction
        self.setValue(int((self.animation_value / self.steps) * 100))

# Define the ScanThread class
class ScanThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.stopped = False

    def run(self):
        try:
            process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in process.stdout:
                if self.stopped:
                    break
                self.update_signal.emit(line)

                # Simulate progress (you should update this logic)
                for i in range(101):
                    if self.stopped:
                        break
                    self.progress_signal.emit(i)
                    self.msleep(100)  # Sleep to simulate work

            process.wait()
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}")

    def stop_scan(self):
        self.stopped = True

class XSSInspectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.scanning_thread = None
        os.environ['PYTHONUNBUFFERED'] = '1'

    def initUI(self):
        # Set up the main window
        self.setWindowTitle('XSS Inspector')
        self.setGeometry(100, 100, 600, 400)

        # Create UI elements
        self.create_input_elements()  # Make sure this method creates self.domain_input, self.url_list_input, etc.
        self.create_results_text_areas()
        self.create_progress_bar()

        # Set up layout
        self.create_layout()

        # Connect signals to slots
        self.connect_signals()

        # Add the following lines after creating the QLineEdit widgets
        self.domain_input.setPlaceholderText('Enter domain that you want to scan')
        self.url_list_input.setPlaceholderText('Select URL list file which have hosts on each new line')

        # Add the following lines after creating the QTextEdit widgets
        self.results_text.setPlaceholderText('No information yet, waiting for code to run')
        self.testing_results_text.setPlaceholderText('No testing results yet, waiting for code to run')
        self.potential_results_text.setPlaceholderText('No potential xss results yet, waiting for code to run')

    def create_input_elements(self):
        # Domain input
        self.domain_label = QLabel('Domain:', self)
        self.domain_input = QLineEdit(self)

        # URL List input
        self.url_list_label = QLabel('URL List File:', self)
        self.url_list_input = QLineEdit(self)
        self.browse_button = QPushButton('Browse', self)
        self.browse_button.clicked.connect(self.browse_for_file)

        # Options checkboxes
        self.reports_checkbox = QCheckBox('Generate Reports', self)
        self.threads_checkbox = QCheckBox('Use 50 Threads', self)
        self.include_subdomain_checkbox = QCheckBox('Include Subdomains', self)
        self.deep_crawl_checkbox = QCheckBox('Deep Crawl', self)

        # Buttons
        self.scan_button = QPushButton('Start Scan', self)
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton('Stop Scan', self)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.close_button = QPushButton('Close App', self)
        self.close_button.clicked.connect(self.close_app)

        # Link label
        self.link_label = QLabel(
            '(<b>XSS Inspector</b> by Haroon Ahmad Awan | <a href="http://www.cyberzeus.pk">Cyberzeus.pk</a> | Hyperthreading and concurrency enabled',
            self)
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_link)

    def create_results_text_areas(self):
        # Results text area
        self.results_text = QTextEdit(self)
        self.results_text.setReadOnly(True)

        # Additional result text areas
        self.testing_results_text = QTextEdit(self)
        self.testing_results_text.setReadOnly(True)
        self.potential_results_text = QTextEdit(self)
        self.potential_results_text.setReadOnly(True)

    def create_progress_bar(self):
        # Progress bar and label
        self.progress_label = QLabel('Status of Payload Analysis:', self)
        self.progress_bar = AnimatedProgressBar()

    def create_layout(self):
        # Layout for domain input
        layout_domain = QHBoxLayout()
        layout_domain.addWidget(self.domain_label)
        layout_domain.addWidget(self.domain_input)

        # Layout for URL list input
        layout_url_list = QHBoxLayout()
        layout_url_list.addWidget(self.url_list_label)
        layout_url_list.addWidget(self.url_list_input)

        # Main layout
        layout = QVBoxLayout()
        layout.addLayout(layout_domain)
        layout.addLayout(layout_url_list)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.reports_checkbox)
        layout.addWidget(self.threads_checkbox)
        layout.addWidget(self.include_subdomain_checkbox)
        layout.addWidget(self.deep_crawl_checkbox)
        layout.addWidget(self.results_text)
        layout.addWidget(self.testing_results_text)
        layout.addWidget(self.potential_results_text)

        # Layout for progress bar and label
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addLayout(progress_layout)

        # Layout for buttons
        layout_buttons = QHBoxLayout()
        layout_buttons.addWidget(self.scan_button)
        layout_buttons.addWidget(self.stop_button)
        layout_buttons.addWidget(self.close_button)
        layout.addLayout(layout_buttons)

        # Link label
        layout.addWidget(self.link_label)

        # Set the main layout
        self.setLayout(layout)

    def connect_signals(self):
        # Connect the browse button to the browse_for_file method
        self.browse_button.clicked.connect(self.browse_for_file)

        # Connect the scan and stop buttons to their respective methods
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)

        # Set up the link label to open the specified URL when clicked
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_link)

    @pyqtSlot()
    def stop_scan(self):
        if self.scanning_thread and self.scanning_thread.isRunning():
            self.scanning_thread.stop_scan()
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_bar.stop_animation()

    @pyqtSlot()
    def scan_finished(self):
        self.results_text.append("Scan finished.")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.stop_animation()

    def start_scan(self):
        if not self.scanning_thread or not self.scanning_thread.isRunning():
            self.results_text.clear()
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.set_text_color("Initializing...", QColor("darkGreen"))
            domain = self.domain_input.text()
            url_list = self.url_list_input.text()
            if not domain and not url_list:
                self.set_text_color("Please enter a domain or select a URL list file.", QColor("red"))
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return
            command = ["python3", "xssinspector.py", "--domain", domain, "--list", url_list]

            # Create a thread to run xssinspector.py and capture output
            self.scanning_thread = ScanThread(command)
            self.scanning_thread.update_signal.connect(self.update_results_text)
            self.scanning_thread.progress_signal.connect(self.update_progress)
            self.scanning_thread.start()
            self.progress_bar.set_bar_width(200)  # Set the width of the progress bar
            self.progress_bar.start_animation()

    @pyqtSlot(int)
    def update_progress(self, progress_value):
        self.progress_bar.setValue(progress_value)

    @pyqtSlot(str)
    def update_results_text(self, output):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        cursor = QTextCursor(self.results_text.document())
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(timestamp, QTextCharFormat())
        cursor.insertText(output)
        self.results_text.setTextCursor(cursor)
        self.results_text.verticalScrollBar().setValue(self.results_text.verticalScrollBar().maximum())

        # Determine the type of result and append to the appropriate QTextEdit
        if "Testing" in output:
            self.append_to_text_edit(output, self.testing_results_text)
        elif "Potential" in output:
            self.append_to_text_edit(output, self.potential_results_text)

    def append_to_text_edit(self, text, text_edit):
        cursor = QTextCursor(text_edit.document())
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        text_edit.setTextCursor(cursor)
        text_edit.verticalScrollBar().setValue(text_edit.verticalScrollBar().maximum())

    def close_app(self):
        if self.scanning_thread and self.scanning_thread.isRunning():
            self.scanning_thread.stop_scan()
        self.close()

    def open_link(self, url):
        QDesktopServices.openUrl(QUrl(url))

    def browse_for_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Select URL List File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            self.url_list_input.setText(file_name)

    def set_text_color(self, text, color):
        document = self.results_text.document()
        cursor = QTextCursor(document)
        format = QTextCharFormat()
        format.setForeground(color)
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text, format)
        self.results_text.setTextCursor(cursor)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = XSSInspectorApp()
    window.show()
    sys.exit(app.exec_())
