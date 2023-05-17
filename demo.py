import asyncio
import os
import threading
import time
import socket
from asyncore import loop
import pyshark
import pytest
import gettime
from multiprocessing import Process
test_logical_address = 0x0710
test_ip = "192.168.197.129"


activation_request = bytearray(
    [int(x, 16) for x in "02 fd 00 05 00 00 00 07 07 10 00 00 00 00 00".split(" ")]
)
vehicle_identification_request_with_ein = bytearray(
    [int(x, 16) for x in "02 fd 00 02 00 00 00 06 31 31 31 31 31 31".split(" ")])

vehicle_identification_request = bytearray(
    [int(x, 16) for x in "02 fd 00 01 00 00 00 00".split(" ")])



vehicle_identification_response = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 04 00 00 00 21 31 32 33 34 35 36 37 38 39 61 62 63 41 42 43 40 23 07 12 12 34 56 78 9a bc 00 00 00 00 00 00 00 00".split(
            " "
        )
    ])
diagnostic_positive_response = bytearray(
    [int(x, 16) for x in "02 fd 00 04 00 00 00 21 31 32 33 34 35 36 37 38 39 61 62 63 41 42 43 40 23 07 12 12 34 56 78 9a bc 00 00 00 00 00 00 00 00".split(" ")])

diagnostic_request = bytearray(
    [int(x, 16) for x in "02 fd 80 01 00 00 00 06 07 10 07 12 10 01".split(" ")]
)

route_activation_response = bytearray(
    [int(x,16) for x in "02 fd 00 06 00 00 00 09 07 10 07 12 10 00 00 00 00".split(" ")]
)
header_version = b'\x02'

# class test_demo:
def send_rev_msg():
    ip = "192.168.197.129" # 对方ip和端口
    port = 13400
    other_addr = (ip, port)
    byte = 1024
    send_Count=0
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# 创建socket
    udp_socket.bind(('192.168.197.1', 65534))
    send_data= vehicle_identification_request
           # send_data = input("输入要发送的信息:").encode("utf-8")
           # send_data_hex= int(send_data,16)12345678

    udp_socket.sendto(send_data, other_addr)
    get_header_version2()#检测接收报文

    # date, nowtime = gettime.nowtime()
    # print('发送报文的时间为'+nowtime)
    # recv_data, other_addr = udp_socket.recvfrom(byte)
    # date1, nowtime1 = gettime.nowtime()
    # print('接收报文的时间为' + nowtime1)
    #         # print("收到来自%s的消息: %s" % (other_addr, recv_data.decode("utf-8")))
    # print(f"收到来自{other_addr}的消息: {recv_data}")
    # if recv_data == vehicle_identification_response :
    #             print("相等")
    # else:
    #     print("不相等")
    # udp_socket.close()
    # print('当前活跃线程数量:', threading.active_count())  # 当前活跃线程数量
    # print('当前所有线程信息:', threading.enumerate())  # 当前所有线程信息
    # print('当前线程信息:', threading.current_thread())  # 当前线程信息

def get_header_version():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    time.sleep(2)
    start_time = time.time()
    print("开始获取版本")
    version = ''
    capture = pyshark.LiveCapture(interface='VMware Network Adapter VMnet8')
    count = 0
    print('当前活跃线程数量:', threading.active_count())  # 当前活跃线程数量
    print('当前所有线程信息:', threading.enumerate())  # 当前所有线程信息
    print('当前线程信息:', threading.current_thread())  # 当前线程信息
    for packet in capture.sniff_continuously():
        if packet.layers[1].layer_name == 'ip':
            if packet.ip.src == '192.168.197.1':
                    # print(packet.doip)
                if packet.highest_layer == 'DOIP':
                    t = packet.doip.get_field('version')
                    count = count + 1
                        # print(t)
                    if count == 1:
                            #return t
                        break
        if time.time() - start_time > 10:
            return None

def gettrace(pathname,name):

    path = os.path.join(".","trace",pathname)
    filepath = os.path.join(path,f"{name}.cap")
    print(path)
    print(filepath)
    os.makedirs(path,exist_ok=True)
    time.sleep(0.1)
    capture = pyshark.LiveCapture(interface='VMware Network Adapter VMnet8', output_file=filepath)
    capture.sniff(packet_count=20)
    capture.close()
    print("捕获数据包完成...")
    return True

def get_header_version2():
    print("开始获取版本")
    version = ''
    capture = pyshark.LiveCapture(interface='VMware Network Adapter VMnet8')
    capture.sniff(packet_count=15)
    for packet in capture.sniff_continuously():
        # if packet.layers[1].layer_name == 'ip':
        #     if packet.ip.src == '192.168.197.1':
        #         # print(packet.doip)
        #         if packet.highest_layer == 'DOIP':
        #             t = packet.doip.get_field('version')
        #             count = count + 1
                    print(packet)

def check_header_version2():
    print("开始获取版本")
    version = ''
    capture = pyshark.LiveCapture(interface='VMware Network Adapter VMnet8')
    count = 0
    for packet in capture.sniff_continuously():
        if packet.layers[1].layer_name == 'ip':
            if packet.ip.src == '192.168.197.1':
                # print(packet.doip)
                if packet.highest_layer == 'DOIP':
                    t = packet.doip.get_field('version')
                    count = count + 1
                    print(t)



if __name__ == '__main__':
    # P0 = Process(group=None, target=gettrace, args=("1111", "233444222"))
    # P1 =Process( group= None,target=send_rev_msg )
    # # P2=Process( group= None,target=get_header_version2 )
    #
    # P0.start()
    # time.sleep(3)
    # P1.start()
    # # P2.start()
    send_rev_msg()
    gettrace("1111","222")