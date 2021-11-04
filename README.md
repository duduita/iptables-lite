# iptables-lite
A lightweight firewall for nuttx

## Prerequisites
The first step to get started with NuttX is to install a series of required tools. They can be found <a href="http://nuttx.incubator.apache.org/docs/latest/quickstart/install.html">here</a>.

## Initialize Configuration
The first step is to initialize NuttX configuration for a given board, based from a pre-existing configuration.
```
$ cd nuttx
$ ./tools/configure.sh -l sim:nsh
```
The `-l` tells use that we’re on Linux (macOS and Windows builds are possible). Use the `-h` argument to see all available options.

## Build NuttX
We can now build NuttX. To do so, you can simply run:
```
$ cd nuttx
$ make
```

## Run the Simulator
```
$ ./nuttx
login: admin
password: Administrator
```
Got any trouble? Check the official NuttX quickstart guide:
http://nuttx.incubator.apache.org/docs/latest/quickstart/index.html
