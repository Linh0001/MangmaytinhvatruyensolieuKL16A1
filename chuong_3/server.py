import socket
# my_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print('Socket đã được tạo thành công!')

#Thiết lập server
server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1",5000))
server_socket.listen(5)

print('Server đang lắng nghe kết nối trên cổng 5000...')
while True:
    client_socket,client_address = server_socket.accept()
    print(f'Kết nối từ {client_address}')
    #Nhận dữ liệu từ client
    data= client_socket.recv(1024).decode()
    print(f'Dữ liệu nhận được: {data}')

    # Điều kiện dừng server khi nhận từ exit từ client
    if data.lower() =="exits":
        print('Server đang tắt ...')
        client_socket.send('Server đang tắt...\n'.encode())
        client_socket.close()
        break
        #Phản hồi từ client
    response="Server đã nhận dữ liệu!"
    client_socket.send(response.encode())
    #Đóng kết nối
    client_socket.close()
#Đóng server
server_socket.close()