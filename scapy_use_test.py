
from scapy.all import *

package = sniff(iface='VMware Network Adapter VMnet8', timeout=10)
print(package)
wrpcap("test.pcap", package)  # 将抓取的包保存为test.pcap文件
