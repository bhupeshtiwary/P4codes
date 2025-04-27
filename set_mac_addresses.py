
def fix_mac_addresses(net):
    switches=['s1','s2','s3','s4']
    mac_map={
        's1':['aa:bb:cc:00:01:01','aa:bb:cc:00:01:02','aa:bb:cc:00:01:03'],
        's2':['aa:bb:cc:00:02:01','aa:bb:cc:00:02:02'],
        's3':['aa:bb:cc:00:03:01','aa:bb:cc:00:03:02'],
        's4':['aa:bb:cc:00:04:01','aa:bb:cc:00:04:02','aa:bb:cc:00:04:03']
        }
    for sw in switches:
        switch=net.get(sw)
        eth_idx=1
        for mac in mac_map[sw]:
            iface=f"{sw}-eth{eth_idx}"
            print(f"Setting{iface}->{mac}")
            switch.cmd(f"ifconfig {iface} hw ether {mac}")
            eth_idx+=1
