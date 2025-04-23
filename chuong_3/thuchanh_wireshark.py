import pyshark

# đương dẫn
path= r'D:\MMTVTTDL\chuong_3\datalinhthanh.pcapng'

# tạo đối tượng đọc file gói tin 
cap=pyshark.FileCapture(path,display_filter='http.request')

print("Phân tích gói http request chứa từ khóa 'login' hoặc 'test'\n")

# duyệt qua từng gói tin trong file
for i, pkt in enumerate(cap):
    try:
        # chuyển toàn bộ nội dung http sang dạng chữ thường để tìm kiếm dễ hơn
        http_info=str(pkt.http).lower()

        # nếu trong nội dung chứa "login" hoặc"test"
        if "login" in http_info or "test" in http_info:
            print('='*50)
            print(f"Gói # {i+1} có chưa từ khóa")

            # hiển thị thời gian bắt đc gói tin
            print("Thời gian:",pkt.sniff_time)

            # hiển thị Ip nguồn và IP đích (máy chủ)
            print("IP nguồn: ",pkt.ip.src if hasattr(pkt,'ip')else "N/A")
            print("IP đích: ",pkt.ip.dst if hasattr(pkt,'ip')else "N/A")

            # hiển thị phương thức http :get hoặc post
            if hasattr (pkt.http,'request_method'):
                print("Phương thức :",pkt.http.request_method)

            # hiển thị url đầy đủ nếu có
            if hasattr(pkt.http,"host")and hasattr(pkt.http,"request_uri"):
                print("URL:",f"http://{pkt.http.host}{pkt.http.request_uri}")

            # hiển thị cookie nếu gói có gửi cookie
            if hasattr(pkt.http,"cookie"):
                print("Cookie:",pkt.http.cookie)

            # hiển thị dữ liệu gửi đi trong phần thân(post form data)
            if hasattr(pkt.http,"file_data"):
                print("Payload:",pkt.http.file_data)

    # nếu có lỗi 
    except Exception as e:
        print(f"[Lỗi tại gói# {i+1}]:{e}")