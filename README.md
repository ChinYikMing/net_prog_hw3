# 封包檢視工具

請寫出一個封包檢視工具，具有底下功能：
可以讀入既有的pcap檔案，並對於檔案中的每個封包顯示(每個封包一行)：
1. 那個封包擷取的時間戳記
2. 來源MAC位址、目的MAC位址、Ethernet type欄位
3. 如果那個封包是IP封包，則再多顯示來源IP位址與目的地IP位址
4. 如果那個封包是TCP或UDP封包，則再多顯示來源port號碼與目的port號碼

Features:
1. supported protocols:
   - Application Layer: rfc1035 DNS query, RR format(except experimental, obsolete specifications, and WKS RDATA format)
   - Transport   Layer：TCP and UDP
   - Internet    Layer: IPv4
   - Link        Layer: Ethernet and Loopback
2. multiple options, please refer to the program usage
