import socket
import time


vehicle_identification_response = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 04 00 00 00 21 31 32 33 34 35 36 37 38 39 61 62 63 41 42 43 40 23 07 12 12 34 56 78 9a bc 00 00 00 00 00 00 00 00".split(
            " "
        )
    ])
vehicle_identification_request = bytearray(
    [int(x, 16) for x in "02 fd 00 01 00 00 00 00".split(" ")])

def recvfrom_test():

    ip = "192.168.197.129"  # 对方ip和端口
    port = 13400
    other_addr = (ip, port)
    byte = 1024
    NETWORK_MAX_SIZE =1024
    send_Count = 0
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建socket
    udp_socket.bind(('192.168.197.1', 65534))
    send_data = vehicle_identification_request
    udp_socket.sendto(send_data, other_addr)  # 发送报文

    while send_Count <2 :
        packet = udp_socket.recvfrom(NETWORK_MAX_SIZE)
        print(packet[0])
        send_Count=send_Count+1


if __name__ =="__main__":
    recvfrom_test()


