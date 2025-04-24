# Steps

Symptom:
```
❯ k8s::logs kube-system coredns
.:53
[INFO] plugin/reload: Running configuration SHA512 = 591cf328cccc12bc490481273e738df59329c62c0b729d94e8b61db9961c2fa5f046dd37f1cf888b953814040d180f52594972691cd6ff41be96639138a43908
CoreDNS-1.11.1
linux/amd64, go1.20.7, ae2bbc2
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp 10.88.0.2:53974->208.67.222.222:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:34639->[2003:e6:6701:ce00:b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:33975->[2003:e6:6701:ce00:b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:50664->[2003:e6:6701:ce00:b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:44633->[fd00::b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:35232->[2003:e6:6701:ce00:b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp 10.88.0.2:44297->208.67.222.222:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp [2001:db8:4860::2]:34381->[fd00::b2f2:8ff:fef1:9d19]:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp 10.88.0.2:33154->208.67.222.222:53: i/o timeout
[ERROR] plugin/errors: 2 8163874400136247191.5223924823700009031. HINFO: read udp 10.88.0.2:34835->208.67.222.222:53: i/o timeout
```

Check cni config:

```
❯ cat /etc/cni/net.d/10-containerd-net.conflist
{
 "cniVersion": "1.0.0",
 "name": "containerd-net",
 "plugins": [
   {
     "type": "bridge",
     "bridge": "cni0",
     "isGateway": true,
     "ipMasq": true,
     "promiscMode": true,
     "ipam": {
       "type": "host-local",
       "ranges": [
         [{
           "subnet": "10.88.0.0/16"
         }],
         [{
           "subnet": "2001:db8:4860::/64"
         }]
       ],
       "routes": [
         { "dst": "0.0.0.0/0" },
         { "dst": "::/0" }
       ]
     }
   },
   {
     "type": "portmap",
     "capabilities": {"portMappings": true},
     "externalSetMarkChain": "KUBE-MARK-MASQ"
   }
 ]
}

```

 - Clone kubernetes/kubernetes
 - Script k8s::up
 - modify sudoers to pass env & custom PATH
 - check interfaces are up and configured correctly
 - check `traceroute`
 - enable or disable HOSTPATH CSI
- debug networking
  - firewalld rules and active zones
  - disable for testing
  - check iptables rules (conntrack)
```
Chain KUBE-FORWARD (1 references)
pkts bytes target     prot opt in     out     source               destination         
61  5364 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate INVALID
0     0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes forwarding rules */ mark match 0x4000/0x4000
0     0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes forwarding conntrack rule */ ctstate RELATED,ESTABLISHED

```
   - install conntrack ()
   - check kubeproxy log

```
❯ tail -f /tmp/kube-proxy.log
I0815 10:01:52.241750   13281 endpointslicecache.go:348] "Setting endpoints for service port name" portName="kube-system/kube-dns:dns-tcp" endpoints=["10.88.0.2:53"]
I0815 10:01:52.241768   13281 endpointslicecache.go:348] "Setting endpoints for service port name" portName="kube-system/kube-dns:metrics" endpoints=["10.88.0.2:9153"]
I0815 10:01:52.241808   13281 endpointslicecache.go:348] "Setting endpoints for service port name" portName="kube-system/kube-dns:dns-tcp" endpoints=["10.88.0.2:53"]
I0815 10:01:52.241825   13281 endpointslicecache.go:348] "Setting endpoints for service port name" portName="kube-system/kube-dns:metrics" endpoints=["10.88.0.2:9153"]
I0815 10:01:52.241841   13281 endpointslicecache.go:348] "Setting endpoints for service port name" portName="kube-system/kube-dns:dns" endpoints=["10.88.0.2:53"]
I0815 10:01:52.241876   13281 proxier.go:805] "Syncing iptables rules"
I0815 10:01:52.249466   13281 proxier.go:1494] "Reloading service iptables data" numServices=4 numEndpoints=4 numFilterChains=6 numFilterRules=4 numNATChains=10 numNATRules=18
E0815 10:01:52.281163   13281 cleanup.go:70] "Failed to delete stale service connections" err="error deleting connection tracking state for UDP service IP: 10.0.0.10, error: error looking for path of conntrack: executable file not found in $PATH" IP="10.0.0.10"
I0815 10:01:52.281205   13281 proxier.go:799] "SyncProxyRules complete" elapsed="39.54232ms"
I0815 10:01:52.281225   13281 bounded_frequency_runner.go:296] sync-runner: ran, next possible in 1s, periodic in 1h0m0s

```

**Compare tcpdump from local system with Pod:**

```
❯ sudo tcpdump -i cni0 src 10.88.0.5
dropped privs to tcpdump
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on cni0, link-type EN10MB (Ethernet), snapshot length 262144 bytes

10:46:38.475721 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149363564 ecr 0,nop,wscale 7], length 0
10:46:38.854152 IP 10.88.0.5.llmnr > sbaumer-thinkpadp1gen4i.remote.csb.37492: Flags [R.], seq 0, ack 1703251671, win 0, length 0
10:46:39.518177 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149364607 ecr 0,nop,wscale 7], length 0
10:46:40.542193 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149365631 ecr 0,nop,wscale 7], length 0
10:46:41.566219 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149366655 ecr 0,nop,wscale 7], length 0
10:46:42.590257 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149367679 ecr 0,nop,wscale 7], length 0
10:46:43.614260 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149368703 ecr 0,nop,wscale 7], length 0
10:46:43.870187 ARP, Reply 10.88.0.5 is-at 1e:33:59:1c:da:0b (oui Unknown), length 28
10:46:45.663174 IP 10.88.0.5.45388 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 1930408727, win 64240, options [mss 1460,sackOK,TS val 1149370752 ecr 0,nop,wscale 7], length 0
```

Local:

```
❯ sudo tcpdump dst 142.250.186.174
dropped privs to tcpdump
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on wlp9s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:47:35.858143 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [S], seq 4122152502, win 64240, options [mss 1460,sackOK,TS val 342813999 ecr 0,nop,wscale 7], length 0
10:47:35.869373 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [.], ack 3342487195, win 502, options [nop,nop,TS val 342814011 ecr 3545817314], length 0
10:47:35.869449 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [P.], seq 0:78, ack 1, win 502, options [nop,nop,TS val 342814011 ecr 3545817314], length 78: HTTP: GET / HTTP/1.1
10:47:35.895047 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [.], ack 774, win 496, options [nop,nop,TS val 342814036 ecr 3545817341], length 0
10:47:35.895403 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [F.], seq 78, ack 774, win 496, options [nop,nop,TS val 342814037 ecr 3545817341], length 0
10:47:35.906429 IP sbaumer-thinkpadp1gen4i.remote.csb.41910 > fra24s08-in-f14.1e100.net.http: Flags [.], ack 775, win 496, options [nop,nop,TS val 342814048 ecr 3545817351], length 0
```

Enable port-forwarding:
```
# enable necessary sysctls
sudo sysctl -w net.ipv4.conf.all.route_localnet=1
sudo sysctl -w net.ipv4.ip_forward=1
# needed for crictl test
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo iptables -t nat -I POSTROUTING -s 127.0.0.0/8 ! -d 127.0.0.0/8 -j MASQUERADE
```