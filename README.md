# vNFChain - a yet another NFV style -

---
## Overviews

The *vNFChain* is a local serivice function chaining framework for μVNFs.
Micro-VNFs are lightweight user VM-dedicated Virtual
Network Functions (VNFs) unlike existing VNFs.
Micro-VNFs are realized as normal user-space processes
on Linux platform, and they can support stateful L7
protocol services. The vNFChain framework enables
not only service function chaining of μVNFs but also
transparently attaching the chain to the "target VM".
This framework has been designed to engage with
de-facto standard open source technologies, such as
DPDK and vhost-user. Main characteristics of vNFChain
are listed as follows:
- User VM dedicated μVNFs
- Flexible and efficient chaining of μVNFs
- Zero touch configuration of user VMs
- No modification of system environment
- Broad-ranging user VMs including Linux and Windows

### Architecture
The vNFChain mainly consists of two components,
*vNFCLib* and *vNFCModule*. The former is a user-space
C library for μVNFs developers. The later is a Linux
kernel module extended from the TAP device, and it
manages the service function chain of μVNF processes.
More details of vNFChain are explained in the papers
listed below.

### Supported
- RHEL 7
- Fedora 24

---
## Contents

##### include/vnfchain/*
- Include files

##### lib/*
- .c files for vNFCLib

###### lib/utils/*
- Utility files (socket, poll, object pool, shared memory, print)

###### lib/vhu/*
- vhost-user implementation (server)

###### lib/dpdk/*
- DPDK related implementation (ring client)

###### lib/tests/*
- Test files (object pool, vNFCLib)

###### lib/examples/*
- Sample μVNFs (C++)

##### module/*
- .c/.h files for vNFCModule

---
## Build

##### [vNFCLib]
`$ make`  -- normal build

`$ make VNFC_DEBUG=1` -- debug build

`$ make USE_DPDK=1` -- For using DPDK ring

##### [vNFCModule]
`$ make` -- normal build

`$ make VNFC_DEBUG=1` --debug build

`$ make FAKE_TUN=1` -- Fake tun mode (/dev/net/tun)

###### [vNFCModule test controller] (module/test.c)
```
$ make test
$ sudo setcap cap_net_admin+ep test
```

---
## Usage

##### [vNFCModule]
`$ sudo insmod vnfchain.ko`

```
$ sudo ./test
> create vnfc <device name>
```

##### [μVNFs process]

`$ sudo ./simple_service -n <service name> -d <device name> [--use-dpdk-ring <ring num>]`

- "--use-dpdk-ring" option should be specified to
only the last μVNF process in the chain that directly
communicates with the virtual switch (DPDK ring server).

`$ sudo chmod a+w /tmp/vhu_<device name>.sock`

---
## Papers

* R. Kawashima and H. Matsuo, "A Generic and Efficient Local Service Function Chaining Framework for User VM-dedicated Micro-VNFs",
  IEICE Transactions on Communications, vol. E100-B, no. 11, 2017. 
  http://search.ieice.org/bin/summary_advpub.php?id=2016NNP0009
  
* R. Kawashima and H. Matsuo, "vNFChain: A VM-dedicated Fast Service Chaining Framework for Micro-VNFs", Proc. The Fifth European Workshop on Software Defined Networks (EWSDN 2016), The Hague, The Netherlands, Oct. 2016. (to be published).
