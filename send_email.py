import smtplib, ssl
def send_email(message, reciever, sender):
    host = "smtp.gmail.com"
    port = 465
    username = "littlecoders10@gmail.com"
    password = "ahkb dlqz uubs dxav"

    my_context = ssl.create_default_context()

    with smtplib.SMTP_SSL(host, port, context = my_context) as server:
        server.login(username, password)
        server.sendmail(username, reciever,f"""\
                        Subject: Email From {sender}
                        
                        You Got An Email From {sender} VIA Passive Safe Ultra Max Pro Secruity Double Glazed Account: Your Message:\n{message}""")