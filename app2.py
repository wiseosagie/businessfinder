import smtplib

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('wizzy.systems@gmail.com', 'vslt mysa knoo jine')
server.sendmail('wizzy.systems@gmail.com', 'wiseosagie@yahoo.com', 'Test Email')
server.quit()
