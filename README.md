# vcenter-exporter
Prometheus vcenter exporter


This is a Prometheus exporter, which collects virtual machines, performance metrics from vsphere api. 
The metric names, which can be defined in the config file are a construct of different fields in counterids.
The name is a construction of: counterid.groupInfo.key + "." + counterid.nameInfo.key + "." + counterid.rollupType:
an example:

```
  - 'cpu.latency.average'
  - 'disk.usage.average'
  - 'mem.usage.average'
  - 'net.usage.average'
  - 'virtualDisk.read.average'
  - 'virtualDisk.totalReadLatency.average'
  - 'virtualDisk.totalWriteLatency.average'
...
```

### Openstack specific notes:
The metrics are only collected for vms, which are in state "poweredOn" and have an annotation field (child.summary.config.annotation), which starts with "name:" otherwise
we cannot attach the openstack specific metadata to the collected metrics, which are definied in the annotation field of each vm like Openstack vm name and Openstack project id.

Labels available:

```
  - vmware_name
  - project_id
  - vcenter_name
  - vcenter_node
  - instance_uuid
  - datastore
```

## Installation


To build the Docker container:

```bash
docker build .
```

## Usage

Command-line option:

```
NAME:
  vcenter-exporter.py - Prometheus vcenter exporter for vm metrics

USAGE:
  python vcenter-export.py
  --config, -c config.yaml
```


## Changelog

2017/09/20 we now use the property collector to get the vm properties instead of a view, which speeds up things quite a bit (thanks to http://www.errr-online.com/index.php/2014/10/06/using-pyvmomi-to-get-a-list-of-all-virtual-machines-fast/ and https://github.com/vmware/pyvmomi-community-samples/blob/master/samples/vminfo_quick.py for inspiration). besides that we introduced the possibility to select the vms we get metrics for via a regex over the host-system to have an easy way to split the work over multiple exporters and we introduced another regex to exclude certain vms by name (for instance test instances etc.). we did experiment a bit with multithreading as well, but the prometheus python client is not really multiprocess aware in a nice way (there is a way, but its quite complexi and ugly).
