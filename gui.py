import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit, QCheckBox, QFileDialog
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtCore import Qt, QUrl, QTimer, QThread, pyqtSignal
import subprocess

class ScanningThread(QThread):
    outputReady = pyqtSignal(str)
    errorReady = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        try:
            process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = "", ""
            while True:
                out_line = process.stdout.readline()
                err_line = process.stderr.readline()
                if not out_line and not err_line:
                    break
                if out_line:
                    output += out_line
                    self.outputReady.emit(out_line)
                if err_line:
                    error += err_line
                    self.errorReady.emit(err_line)
        except subprocess.CalledProcessError as e:
            self.errorReady.emit(f"Error: {e}")

class XSSInspectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('XSS Inspector')
        self.setGeometry(100, 100, 600, 400)

        # Input field for the domain
        self.domain_label = QLabel('Domain:', self)
        self.domain_input = QLineEdit(self)

        # Input field for the URL list file
        self.url_list_label = QLabel('URL List File:', self)
        self.url_list_input = QLineEdit(self)
        self.browse_button = QPushButton('Browse', self)
        self.browse_button.clicked.connect(self.browse_for_file)

        # Checkboxes for scanning options
        self.reports_checkbox = QCheckBox('Generate Reports', self)
        self.threads_checkbox = QCheckBox('Use 50 Threads', self)
        self.include_subdomain_checkbox = QCheckBox('Include Subdomains', self)
        self.deep_crawl_checkbox = QCheckBox('Deep Crawl', self)

        self.results_text = QTextEdit(self)
        self.results_text.setReadOnly(True)

        self.scan_button = QPushButton('Start Scan', self)
        self.scan_button.clicked.connect(self.start_scan)

        self.close_button = QPushButton('Close App', self)
        self.close_button.clicked.connect(self.close_app)

        # Create a QLabel for the link
        self.link_label = QLabel('<b>XSS Inspector</b> by Haroon Awan | <a href="http://www.cyberzeus.pk">Cyberzeus.pk</a>', self)
        self.link_label.setTextFormat(Qt.RichText)
        self.link_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_link)

        layout = QVBoxLayout()
        layout.addWidget(self.domain_label)
        layout.addWidget(self.domain_input)
        layout.addWidget(self.url_list_label)
        layout.addWidget(self.url_list_input)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.reports_checkbox)
        layout.addWidget(self.threads_checkbox)
        layout.addWidget(self.include_subdomain_checkbox)
        layout.addWidget(self.deep_crawl_checkbox)
        layout.addWidget(self.results_text)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.close_button)
        layout.addWidget(self.link_label)

        self.setLayout(layout)

        # Create a QTimer for blinking message
        self.blink_timer = QTimer(self)
        self.blink_timer.timeout.connect(self.toggle_blink_message)
        self.blink_state = True

    def toggle_blink_message(self):
        # Toggle the visibility of the blinking message
        self.blink_state = not self.blink_state
        message = 'Initializing...' if self.blink_state else ''
        self.results_text.setPlainText(message)

    def start_scan(self):
        # Get the domain and URL list file from the input fields
        domain = self.domain_input.text()
        url_list = self.url_list_input.text()

        if not domain and not url_list:
            self.results_text.setPlainText("Please enter a domain or select a URL list file.")
            return

        command = ["python3", "xssinspector.py", "--domain", domain, "--list", url_list]

        # Create a scanning thread and start it
        self.scanning_thread = ScanningThread(command)
        self.scanning_thread.outputReady.connect(self.update_results_text)
        self.scanning_thread.start()

        # Start the blink timer
        self.blink_timer.start(1000)

    def update_results_text(self, output):
        # Stop the blink timer when output is received
        self.blink_timer.stop()
        # Update the results_text field with the scanning output
        self.results_text.setPlainText(output)

    def close_app(self):
        self.close()

    def open_link(self, url):
        QDesktopServices.openUrl(QUrl(url))

    def browse_for_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Select URL List File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            self.url_list_input.setText(file_name)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = XSSInspectorApp()
    window.show()
    sys.exit(app.exec_())
