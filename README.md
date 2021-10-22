# mptcpscanner

This project is a fork of [latency](https://github.com/grahamking/) that refers to it on how to craft TCP packets on golang.

The mptcpscanner tool is implemented for checking the MPTCP availalbe sites on the Internet. It needs a Golang compiler to build it, and Linux and root permission to run. Using the following commands can build and run it:

```shell
go build mptcpscanner.go tcp.go 
sudo ./mptcpscanner -a -c 10000 -i eth0 -f 1000000.csv -o results.json
```

And this the usage informant.
```shell
Usage of ./mptcpscanner:
  -c int
        The count of sites need to scan (default 100)
  -f string
        The file path of the site list
  -h    Print help
  -i string
        Interface (e.g. eth0, wlan1, etc)
  -o string
        The flie path of output result
```

The following command can be used to count the results of a scan that is implemented in NodeJs.
```shell
node stats.js
```

License: GPL.
