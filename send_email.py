import smtplib, ssl
def send_email(message, reciever, sender):
    host = "smtp.gmail.com"
    port = 465
    username = "littlecoders10@gmail.com"
    password = "ahkb dlqz uubs dxav"

    my_context = ssl.create_default_context()

    with smtplib.SMTP_SSL(host, port, context = my_context) as server:
        server.login(username, password)
        message = f"Subject: New Message From {sender} \n From: {sender} VIA ultramax.streamlit.app \n" + message

        server.sendmail(username, reciever,message)