import pyshark

# Đường dẫn đến file .pcapng
file_path = "datalinhthanh.pcapng"

# Đọc file .pcapng
capture = pyshark.FileCapture(file_path)

# Biến đếm để giới hạn 10 gói tin đầu tiên
count = 0
max_packets = 10

# Duyệt qua từng gói tin
for packet in capture:
    if count >= max_packets:
        break  # Thoát sau khi xử lý 10 gói tin

    try:
        # Tầng 2: Ethernet (Data Link)
        if "eth" in packet:
            eth_src = packet.eth.src  # Địa chỉ MAC nguồn
            eth_dst = packet.eth.dst  # Địa chỉ MAC đích
            print(f"Packet {packet.number}:")
            print(f"  Tầng 2 - Ethernet:")
            print(f"    MAC Nguồn: {eth_src}")
            print(f"    MAC Đích: {eth_dst}")

        # Tầng 3: IP (Network)
        if "ip" in packet:
            ip_src = packet.ip.src  # Địa chỉ IP nguồn
            ip_dst = packet.ip.dst  # Địa chỉ IP đích
            print(f"  Tầng 3 - IP:")
            print(f"    IP Nguồn: {ip_src}")
            print(f"    IP Đích: {ip_dst}")
            print("-" * 50)

        count += 1  # Tăng biến đếm

    except AttributeError:
        # Bỏ qua nếu gói tin không có thông tin tầng 2 hoặc 3
        continue

# Đóng file capture
capture.close()