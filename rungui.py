import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit, QCheckBox
from PyQt5.QtGui import QDesktopServices, QCursor
from PyQt5.QtCore import Qt, QUrl

class XSSInspectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('XSSInspector')
        self.setGeometry(100, 100, 600, 400)

        # Input field for the domain
        self.domain_label = QLabel('Domain:', self)
        self.domain_input = QLineEdit(self)

        # Checkboxes for custom arguments
        self.reports_checkbox = QCheckBox('Reports', self)
        self.threads_checkbox = QCheckBox('Threads', self)
        self.include_subdomain_checkbox = QCheckBox('Include Subdomain', self)
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
        layout.addWidget(self.reports_checkbox)
        layout.addWidget(self.threads_checkbox)
        layout.addWidget(self.include_subdomain_checkbox)
        layout.addWidget(self.deep_crawl_checkbox)
        layout.addWidget(self.results_text)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.close_button)
        layout.addWidget(self.link_label)  # Add the link to the layout

        self.setLayout(layout)

    def start_scan(self):
        # Get the domain from the input field
        domain = self.domain_input.text()

        # Check the state of each checkbox and add corresponding arguments
        custom_args = []
        if self.reports_checkbox.isChecked():
            custom_args.append("--report report_template.html")
        if self.threads_checkbox.isChecked():
            custom_args.append("--thread 50")
        if self.include_subdomain_checkbox.isChecked():
            custom_args.append("--subs")
        if self.deep_crawl_checkbox.isChecked():
            custom_args.append("--deepcrawl")

        # Construct the command with custom arguments
        command = ["python3", "xssinspector.py", "--domain", domain] + custom_args

        # Simulate the scanning process
        # Replace this with your actual scanning code
        result = "Scanning in progress..."

        self.results_text.setPlainText(result)

    def close_app(self):
        self.close()

    def open_link(self, url):
        QDesktopServices.openUrl(QUrl(url))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = XSSInspectorApp()
    window.show()
    sys.exit(app.exec_())
