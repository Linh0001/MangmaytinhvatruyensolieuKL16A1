import socket

client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#Kết nối tới Server tại IP và cổng
client_socket.connect(("127.0.0.1",5000))

client_socket.send("Hello server!".encode())

#Nhận phản hồi từ server
message=client_socket.recv(5000).decode()
print('Tin nhắn từ server:',message)

#Gửi lệnh thoát để đóng server nếu muốn
client_socket.send('exit'.encode())
client_socket.close()