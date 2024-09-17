import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit, QMessageBox, QStackedWidget, QInputDialog
import functions_pyq
"DONT FOLD UNDERNEATH!"
"""🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑
💀💀💀💀💀💀💀💀💀💀💀💀
DO NOT RUN THIS!
THIS WILL CRASH THE ENTIRE LAPTOP!
IF YOU RUN THIS THE ENTIRE SYSTEM WILL BREAK
ONLY RUN THIS IF YOU HAVE A FULL PC CONNECTED OR ELSE 
THE LAPTOP WILL OVERHEAT AND THE ENTIRE PYTHON SYSTEM WILL STOP!
SO DONT RUN THIS IF YOU HAVE A LAPTOP!
IT FREEZES THE WHOLE ENTIRE THING!
💀💀💀💀💀💀💀💀💀💀💀💀
🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑"""

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("My Passive Safe Ultra Max Pro Security Double Glazed Account")
        self.setGeometry(100, 100, 800, 600)
        
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.stacked_widget.addWidget(self.create_login_page())
        self.stacked_widget.addWidget(self.create_signup_page())
        self.stacked_widget.addWidget(self.create_send_message_page())
        self.stacked_widget.addWidget(self.create_view_messages_page())
        self.stacked_widget.addWidget(self.create_quick_chat_page())
        self.stacked_widget.addWidget(self.create_friends_page())

        self.logged_in_user_id = None

    def create_login_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.handle_login)
        layout.addWidget(login_button)

        page.setLayout(layout)
        return page

    def create_signup_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.signup_username_input = QLineEdit()
        self.signup_username_input.setPlaceholderText("Username")
        layout.addWidget(self.signup_username_input)

        self.signup_password_input = QLineEdit()
        self.signup_password_input.setPlaceholderText("Password")
        self.signup_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.signup_password_input)

        self.signup_user_id_input = QLineEdit()
        self.signup_user_id_input.setPlaceholderText("Unique ID")
        layout.addWidget(self)
        signup_button = QPushButton("Sign Up")
        signup_button.clicked.connect(self.handle_signup)
        layout.addWidget(signup_button)

        page.setLayout(layout)
        return page

    def create_send_message_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.recipient_id_input = QLineEdit()
        self.recipient_id_input.setPlaceholderText("Recipient ID")
        layout.addWidget(self.recipient_id_input)

        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Subject")
        layout.addWidget(self.subject_input)

        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Message")
        layout.addWidget(self.message_input)

        send_button = QPushButton("Send")
        send_button.clicked.connect(self.handle_send_message)
        layout.addWidget(send_button)

        page.setLayout(layout)
        return page

    def create_view_messages_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.messages_label = QLabel("Messages will be displayed here.")
        layout.addWidget(self.messages_label)

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.handle_view_messages)
        layout.addWidget(refresh_button)

        page.setLayout(layout)
        return page

    def create_quick_chat_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.chat_recipient_id_input = QLineEdit()
        self.chat_recipient_id_input.setPlaceholderText("Recipient ID")
        layout.addWidget(self.chat_recipient_id_input)

        self.chat_message_input = QTextEdit()
        self.chat_message_input.setPlaceholderText("Type your message here...")
        layout.addWidget(self.chat_message_input)

        send_chat_button = QPushButton("Send Chat")
        send_chat_button.clicked.connect(self.handle_send_quick_chat)
        layout.addWidget(send_chat_button)

        clear_cache_button = QPushButton("Clear Cache")
        clear_cache_button.clicked.connect(self.handle_clear_cache)
        layout.addWidget(clear_cache_button)

        page.setLayout(layout)
        return page

    def create_friends_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.friend_id_input = QLineEdit()
        self.friend_id_input.setPlaceholderText("Friend ID")
        layout.addWidget(self.friend_id_input)

        send_friend_request_button = QPushButton("Send Friend Request")
        send_friend_request_button.clicked.connect(self.handle_send_friend_request)
        layout.addWidget(send_friend_request_button)

        self.friends_label = QLabel("Friends and requests will be displayed here.")
        layout.addWidget(self.friends_label)

        page.setLayout(layout)
        return page

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        user_id = functions_pyq.login(username, password)
        if user_id:
            self.logged_in_user_id = user_id
            self.stacked_widget.setCurrentIndex(2)  # Switch to Send Message page
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password")

    def handle_signup(self):
        username = self.signup_username_input.text()
        password = self.signup_password_input.text()
        user_id = self.signup_user_id_input.text()
        if functions_pyq.verify_signup(username, password, user_id):
            functions_pyq.sign_up(username, password, user_id)
            QMessageBox.information(self, "Sign Up Successful", "You have successfully signed up!")
            self.stacked_widget.setCurrentIndex(0)  # Switch to Login page
        else:
            QMessageBox.warning(self, "Sign Up Failed", "Sign Up failed. Please check your details.")

    def handle_send_message(self):
        recipient_id = self.recipient_id_input.text()
        subject = self.subject_input.text()
        message = self.message_input.toPlainText()
        if self.logged_in_user_id:
            functions_pyq.send_message(self.logged_in_user_id, recipient_id, subject, message)
            QMessageBox.information(self, "Message Sent", "Your message has been sent successfully!")
        else:
            QMessageBox.warning(self, "Send Message Failed", "You need to be logged in to send a message.")

    def handle_view_messages(self):
        if self.logged_in_user_id:
            messages = functions_pyq.view_messages(self.logged_in_user_id)
            self.messages_label.setText(messages)
        else:
            QMessageBox.warning(self, "View Messages Failed", "You need to be logged in to view messages.")

    def handle_send_quick_chat(self):
        recipient_id = self.chat_recipient_id_input.text()
        message = self.chat_message_input.toPlainText()
        if self.logged_in_user_id:
            functions_pyq.send_quick_chat(self.logged_in_user_id, recipient_id, message)
            QMessageBox.information(self, "Quick Chat Sent", "Your quick chat message has been sent!")
        else:
            QMessageBox.warning(self, "Send Quick Chat Failed", "You need to be logged in to send a quick chat.")

    def handle_clear_cache(self):
        # Implement the clear cache functionality
        system_password, _ = QInputDialog.getText(self, "System Password", "Enter System Password:", QLineEdit.EchoMode.Password)
        if system_password == "Muiz2013":
            functions_pyq.clear_quick_chat_cache()
            QMessageBox.information(self, "Cache Cleared", "Quick chat cache has been cleared.")
        else:
            QMessageBox.warning(self, "Invalid Password", "The system password you entered is incorrect.")

    def handle_send_friend_request(self):
        friend_id = self.friend_id_input.text()
        if self.logged_in_user_id:
            functions_pyq.send_friend_request(friend_id, self.logged_in_user_id)
            QMessageBox.information(self, "Friend Request Sent", "Your friend request has been sent!")
        else:
            QMessageBox.warning(self, "Send Friend Request Failed", "You need to be logged in to send a friend request.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
