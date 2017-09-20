#!/usr/bin/env python

# python interface to vmware performance metrics
from pyVmomi import vim, vmodl
# prometheus export functionality
from prometheus_client import start_http_server, Gauge
from pyVim.connect import SmartConnect, Disconnect
import atexit
import ssl
import sys
from yamlconfig import YamlConfig
import argparse
import re
import logging
import time

from datetime import timedelta, datetime

# vcenter connection defaults
defaults = {
    'vcenter_ip': 'localhost',
    'vcenter_user': 'administrator@vsphere.local',
    'vcenter_password': 'password',
    'ignore_ssl': True
}

# list of vm properties we are using and which we get via property collector later
# see: http://goo.gl/fjTEpW for all properties.
vm_properties = [
    "runtime.powerState", "runtime.host", "config.annotation", "config.name",
    "config.instanceUuid"
]

logger = logging.getLogger()


# Shamelessly borrowed from:
# https://github.com/dnaeon/py-vconnector/blob/master/src/vconnector/core.py
def collect_properties(service_instance, view_ref, obj_type, path_set=None,
                       include_mors=False):
    """
    Collect properties for managed objects from a view ref

    Check the vSphere API documentation for example on retrieving
    object properties:

        - http://goo.gl/erbFDz

    Args:
        si          (ServiceInstance): ServiceInstance connection
        view_ref (vim.view.*): Starting point of inventory navigation
        obj_type      (vim.*): Type of managed object
        path_set               (list): List of properties to retrieve
        include_mors           (bool): If True include the managed objects
                                       refs in the result

    Returns:
        A list of properties for the managed objects

    """
    collector = service_instance.content.propertyCollector

    # Create object specification to define the starting point of
    # inventory navigation
    obj_spec = vmodl.query.PropertyCollector.ObjectSpec()
    obj_spec.obj = view_ref
    obj_spec.skip = True

    # Create a traversal specification to identify the path for collection
    traversal_spec = vmodl.query.PropertyCollector.TraversalSpec()
    traversal_spec.name = 'traverseEntities'
    traversal_spec.path = 'view'
    traversal_spec.skip = False
    traversal_spec.type = view_ref.__class__
    obj_spec.selectSet = [traversal_spec]

    # Identify the properties to the retrieved
    property_spec = vmodl.query.PropertyCollector.PropertySpec()
    property_spec.type = obj_type

    if not path_set:
        property_spec.all = True

    property_spec.pathSet = path_set

    # Add the object and property specification to the
    # property filter specification
    filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = [obj_spec]
    filter_spec.propSet = [property_spec]

    # Retrieve properties
    props = collector.RetrieveContents([filter_spec])

    data = []
    for obj in props:
        properties = {}
        for prop in obj.propSet:
            properties[prop.name] = prop.val

        if include_mors:
            properties['obj'] = obj.obj

        data.append(properties)
    return data


def get_container_view(service_instance, obj_type, container=None):
    """
    Get a vSphere Container View reference to all objects of type 'obj_type'

    It is up to the caller to take care of destroying the View when no longer
    needed.

    Args:
        obj_type (list): A list of managed object types

    Returns:
        A container view ref to the discovered managed objects

    """
    if not container:
        container = service_instance.content.rootFolder

    view_ref = service_instance.content.viewManager.CreateContainerView(
        container=container,
        type=obj_type,
        recursive=True
    )
    return view_ref


def main():

    # config file parsing
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="Specify config file", metavar="FILE")
    args, remaining_argv = parser.parse_known_args()
    config = YamlConfig(args.config, defaults)

    # set default log level if not defined in config file
    if config.get('main').get('log'):
        logger.setLevel(
            logging.getLevelName(config.get('main').get('log').upper()))
    else:
        logger.setLevel('INFO')
    FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
    logging.basicConfig(stream=sys.stdout, format=FORMAT)

    # check for insecure ssl option
    si = None
    context = None
    if config.get('main').get('ignore_ssl') and \
       hasattr(ssl, "_create_unverified_context"):
        context = ssl._create_unverified_context()

    # connect to vcenter
    try:
        si = SmartConnect(
            host=config.get('main').get('host'),
            user=config.get('main').get('user'),
            pwd=config.get('main').get('password'),
            port=int(config.get('main').get('port')),
            sslContext=context)
        atexit.register(Disconnect, si)

    except IOError as e:
        logging.error("Could not connect to vcenter." + e)

    if not si:
        raise SystemExit("Unable to connect to host with supplied info.")

    content = si.RetrieveContent()
    perfManager = content.perfManager

    # get the datacenter info
    datacenter = si.content.rootFolder.childEntity[0]
    datacentername = datacenter.name
    logging.debug('datacenter name: ' + datacentername)

    # create a list of vim.VirtualMachine objects so that we can query them for statistics
    container = content.rootFolder
    viewType = [vim.VirtualMachine]
    recursive = True

    # initialize some variables
    counterInfo = {}
    gauge = {}

    # time intervall to average vcenter data across in seconds
    interval = int(config.get('main').get('interval'))

    # compile a regex for trying to filter out openstack generated vms - they all have the "name:" field set
    openstack_match_regex = re.compile("^name:")

    # compile a regex for stripping out not required parts of hostnames etc. to have shorter label names (for better grafana display)
    if config.get('main').get('shorter_names_regex'):
        shorter_names_regex = re.compile(
            config.get('main').get('shorter_names_regex'))
    else:
        shorter_names_regex = re.compile('')
    logging.debug("name shortening regex: " +
                  str(config.get('main').get('shorter_names_regex')))

    # compile a regex for matching the vcenter_node name, so that we can deal only with the matching node or bb with this vcenter-exporter
    if config.get('main').get('host_match_regex'):
        host_match_regex = re.compile(
            config.get('main').get('host_match_regex'))
    else:
        host_match_regex = re.compile('')
    logging.debug("vcenter_node name (host) regex: " +
                  str(config.get('main').get('host_match_regex')))

    # compile a regex for matching the vmware_name against machines we do not want to collect metrics for (canary, blackbox vms etc.)
    if config.get('main').get('ignore_match_regex'):
        ignore_match_regex = re.compile(
            config.get('main').get('ignore_match_regex'))
    else:
        ignore_match_regex = re.compile(
            'this_string_will_definitely_not_match_any_vmware_name')
    logging.debug("vmware name ignore regex: " +
                  str(config.get('main').get('ignore_match_regex')))

    # create a mapping from performance stats to their counterIDs
    # counterInfo: [performance stat => counterId]
    # performance stat example: cpu.usagemhz.LATEST
    # counterId example: 6
    # level defines the amouts of metrics available and its default setting in the vcenter here is 4
    counterids = perfManager.QueryPerfCounterByLevel(level=4)

    # start up the http server to expose the prometheus metrics
    start_http_server(int(config.get('main').get('listen_port')))

    logging.debug('list of all available metrics and their counterids')
    # loop over all counterids and build their full name and a dict relating it to the ids
    for c in counterids:
        fullName = c.groupInfo.key + "." + c.nameInfo.key + "." + c.rollupType
        logging.debug(fullName + ': ' + str(c.key))
        counterInfo[fullName] = c.key

        # define a dict of gauges for the counter ids
        gauge['vcenter_' + fullName.replace('.', '_')] = Gauge(
            'vcenter_' + fullName.replace('.', '_'),
            'vcenter_' + fullName.replace('.', '_'), [
                'vmware_name', 'project_id', 'vcenter_name', 'vcenter_node',
                'instance_uuid', 'metric_detail'
            ])

    # in case we have a set of metric to handle, use those - otherwise use all we can get
    selected_metrics = config.get('main').get('vm_metrics')
    if selected_metrics:
        counterIDs = [
            counterInfo[i] for i in selected_metrics if i in counterInfo
        ]
    else:
        counterIDs = [i.key for i in counterids]

    # infinite loop for getting the metrics
    while True:
        logging.debug('====> total loop start: %s' % datetime.now())
        # get the start time of the loop to be able to fill it to intervall exactly at the end
        loop_start_time = int(time.time())

        # get all the data regarding vcenter hosts
        hostView = content.viewManager.CreateContainerView(
            container, [vim.HostSystem], recursive)

        hostssystems = hostView.view

        # build a dict to lookup the hostname by its id later
        hostsystemsdict = {}
        for host in hostssystems:
            hostsystemsdict[host] = host.name
        logging.debug(
            'list of all available vcenter nodes and their internal id')
        logging.debug(hostsystemsdict)

        # collect the properties we are interested in
        view = get_container_view(si, obj_type=[vim.VirtualMachine])
        vm_data = collect_properties(
            si,
            view_ref=view,
            obj_type=vim.VirtualMachine,
            path_set=vm_properties,
            include_mors=True)

        count_vms = 0

        # define the time range in seconds the metric data from the vcenter should be averaged across
        # all based on vcenter time
        vchtime = si.CurrentTime()
        startTime = vchtime - timedelta(seconds=(interval + 60))
        endTime = vchtime - timedelta(seconds=60)

        # loop over all vmware machines
        for vm in vm_data:
            try:
                # only consider machines which have an annotation, are powered on, match our regex for the host system and are not in the ignore list
                if (vm["runtime.powerState"] == "poweredOn" and
                        openstack_match_regex.match(vm["config.annotation"]) and
                        host_match_regex.match(
                            hostsystemsdict[vm["runtime.host"]])
                    ) and not ignore_match_regex.match(vm["config.name"]):
                    logging.debug('current vm processed - ' +
                                  vm["config.name"])

                    logging.debug('==> running on vcenter node: ' +
                                  hostsystemsdict[vm["runtime.host"]])

                    # split the multi-line annotation into a dict per property (name, project-id, ...)
                    annotation_lines = vm["config.annotation"].split('\n')

                    # rename flavor: to flavor_, so that it does not break the split on : below
                    annotation_lines = [
                        w.replace('flavor:', 'flavor_')
                        for w in annotation_lines
                    ]

                    # the filter is for filtering out empty lines
                    annotations = dict(
                        s.split(':', 1)
                        for s in filter(None, annotation_lines))

                    # get a list of metricids for this vm in preparation for the stats query
                    metricIDs = [
                        vim.PerformanceManager.MetricId(
                            counterId=i, instance="*") for i in counterIDs
                    ]

                    # query spec for the metric stats query, the intervallId is the default one
                    logging.debug(
                        '==> vim.PerformanceManager.QuerySpec start: %s' %
                        datetime.now())
                    spec = vim.PerformanceManager.QuerySpec(
                        maxSample=1,
                        entity=vm["obj"],
                        metricId=metricIDs,
                        intervalId=20,
                        startTime=startTime,
                        endTime=endTime)
                    logging.debug(
                        '==> vim.PerformanceManager.QuerySpec end: %s' %
                        datetime.now())

                    # get metric stats from vcenter
                    logging.debug('==> perfManager.QueryStats start: %s' %
                                  datetime.now())
                    result = perfManager.QueryStats(querySpec=[spec])
                    logging.debug(
                        '==> perfManager.QueryStats end: %s' % datetime.now())

                    # loop over the metrics
                    logging.debug('==> gauge loop start: %s' % datetime.now())
                    for val in result[0].value:
                        # send gauges to prometheus exporter: metricname and value with
                        # labels: vm name, project id, vcenter name, vcneter
                        # node, instance uuid and metric detail (for instance a partition
                        # for io or an interface for net metrics) - we update the gauge
                        # only if the value is not -1 which means the vcenter has no value
                        if val.value[0] != -1:
                            if val.id.instance == '':
                                metric_detail = 'total'
                            else:
                                metric_detail = val.id.instance
                            gauge['vcenter_' +
                                  counterInfo.keys()[counterInfo.values()
                                                     .index(val.id.counterId)]
                                  .replace('.', '_')].labels(
                                      annotations['name'],
                                      annotations['projectid'], datacentername,
                                      shorter_names_regex.sub(
                                          '',
                                          hostsystemsdict[vm["runtime.host"]]),
                                      vm["config.instanceUuid"],
                                      metric_detail).set(val.value[0])
                    logging.debug('==> gauge loop end: %s' % datetime.now())
                    count_vms += 1

            except IndexError:
                logging.info('a machine disappeared during processing')

        loop_end_time = int(time.time())

        logging.info('number of vms we got metrics for: ' + str(count_vms) + ' - actual runtime: ' + str(loop_end_time - loop_start_time) + 's')

        # this is the time we sleep to fill the loop runtime until it reaches "interval"
        # the 0.9 makes sure we have some overlap to the last interval to avoid gaps in
        # metrics coverage (i.e. we get the metrics quicker than the averaging time)
        loop_sleep_time = 0.9 * interval - (loop_end_time - loop_start_time)
        if loop_sleep_time < 0:
            logging.warn('getting the metrics takes around ' + str(interval) + ' seconds or longer - please increase the interval setting')
            loop_sleep_time = 0

        logging.debug('====> loop end before sleep: %s' % datetime.now())
        time.sleep(int(loop_sleep_time))
        logging.debug('====> total loop end: %s' % datetime.now())

if __name__ == "__main__":
    main()
