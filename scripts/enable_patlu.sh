sudo vppctl -s /run/vpp/cli-vpp1.sock clear error
sudo vppctl -s /run/vpp/cli-vpp1.sock clear runtime
sudo vppctl -s /run/vpp/cli-vpp1.sock patlu enable-disable host-vpp1out
#sudo vppctl -s /run/vpp/cli-vpp1.sock patlu enable-disable loop0
sudo vppctl -s /run/vpp/cli-vpp1.sock patlu enable-disable memif0/0
#sudo vppctl -s /run/vpp/cli-vpp1.sock trace add af-packet-input 50
sudo vppctl -s /run/vpp/cli-vpp1.sock trace add memif-input 20
sudo ip netns exec bear nslookup bing.com

sudo vppctl -s /run/vpp/cli-vpp1.sock show error
sudo vppctl -s /run/vpp/cli-vpp1.sock show runtime
sudo vppctl -s /run/vpp/cli-vpp1.sock show trace

