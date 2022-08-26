# my_ping

> a host alive test tools

## Reference

* [cli_ping](https://github.com/KevinJi22/cli_ping)
* [iputils-source](http://www.skbuff.net/iputils/)
* [iputils-github](https://github.com/dgibson/iputils)
* [netkit-base](https://github.com/NovantaPhotonics/netkit-base-0.17)

## Usage

```
$ ./my_ping
(main:452) Usage: sudo ./my_ping [-4 (IPv4) or -6 (IPv6)] hostname/IP address

$ sudo ./my_ping 127.0.0.1
(ping_sock_init:335) target host[127.0.0.1], addrs[127.0.0.1]
(ping_icmp_send:202) recv from loopback true
(ping_icmp_send:191) request retry 1!
(ping_icmp_send:202) recv from loopback true
127.0.0.1 is alive!

$ sudo ./my_ping -6 ::1
(ping_sock_init:335) target host[::1], addrs[::1]
(ping_icmp_send:202) recv from loopback true
(ping_icmp_send:191) request retry 1!
(ping_icmp_send:202) recv from loopback true
::1 is alive!

$ sudo ./my_ping www.baidu.com
(ping_sock_init:335) target host[www.baidu.com], addrs[14.215.177.39]
(ping_icmp_send:202) recv from loopback false
www.baidu.com is alive!
```

