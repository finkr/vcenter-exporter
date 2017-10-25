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
    parser.add_argument(
        "-d", "--datastore", help="Get metrics for datastores instead of vms", action='store_true')
    args, remaining_argv = parser.parse_known_args()
    config = YamlConfig(args.config, defaults)

    # list of vm properties we are using and which we get via property collector later
    # see: http://goo.gl/fjTEpW for all properties.
    # once for vms and once for datastores ... and some other stuff, which differs for the two cases
    if args.datastore == False:
      my_properties = [
          "runtime.powerState", "runtime.host", "config.annotation", "config.name",
           "config.instanceUuid", "config.guestId", "summary.config.vmPathName"
      ]
      my_name = "vm"
      my_obj_type = vim.VirtualMachine
    else:
      my_properties = [
         "summary.accessible", "summary.capacity", "summary.freeSpace", "summary.maintenanceMode", "summary.name", "summary.type", "summary.url", "overallStatus"
      ]
      my_name = "datastore"
      my_obj_type = vim.Datastore

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

    # create a list of vim.VirtualMachine / vim.Datastore objects so that we can query them for statistics
    container = content.rootFolder
    viewType = [my_obj_type]
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
    # level defines the amounts of metrics available and its default setting in the vcenter here is 1
    counterids = perfManager.QueryPerfCounterByLevel(level=1)

    # start up the http server to expose the prometheus metrics
    start_http_server(int(config.get('main').get('listen_port')))

    if args.datastore == False:
      logging.debug('list of all available metrics and their counterids')
      # loop over all counterids and build their full name and a dict relating it to the ids
      for c in counterids:
          fullName = c.groupInfo.key + "." + c.nameInfo.key + "." + c.rollupType
          logging.debug(fullName + ': ' + str(c.key))
          counterInfo[fullName] = c.key

          # define a dict of vm gauges for the counter ids
          gauge['vcenter_' + fullName.replace('.', '_')] = Gauge(
              'vcenter_' + fullName.replace('.', '_'),
              'vcenter_' + fullName.replace('.', '_'), [
                  'vmware_name', 'project_id', 'vcenter_name', 'vcenter_node',
                  'instance_uuid', 'guest_id', 'datastore', 'metric_detail'
              ])

      # in case we have a configured set of metrics to handle, use those - otherwise use all we can get
      selected_metrics = config.get('main').get('vm_metrics')
      if selected_metrics:
          counterIDs = [
              counterInfo[i] for i in selected_metrics if i in counterInfo
          ]
      else:
          counterIDs = [i.key for i in counterids]
    else:
        # define the gauges - they have to be defined by hand for the datastores, as there is no clear pattern behind
        gauge['vcenter_datastore_accessible'] = Gauge('vcenter_datastore_accessible', 'vcenter_datastore_accessible', ['datastore_name', 'datastore_type', 'datastore_url'])
        gauge['vcenter_datastore_capacity'] = Gauge('vcenter_datastore_capacity', 'vcenter_datastore_capacity', ['datastore_name', 'datastore_type', 'datastore_url'])
        gauge['vcenter_datastore_freespace'] = Gauge('vcenter_datastore_freespace', 'vcenter_datastore_freespace', ['datastore_name', 'datastore_type', 'datastore_url'])
        gauge['vcenter_datastore_maintenancemode'] = Gauge('vcenter_datastore_maintenancemode', 'vcenter_datastore_maintenancemode', ['datastore_name', 'datastore_type', 'datastore_url'])
        gauge['vcenter_datastore_overallstatus'] = Gauge('vcenter_datastore_overallstatus', 'vcenter_datastore_overallstatus', ['datastore_name', 'datastore_type', 'datastore_url'])

    # infinite loop for getting the metrics
    while True:
        logging.debug('====> total loop start: %s' % datetime.now())
        # get the start time of the loop to be able to fill it to intervall exactly at the end
        loop_start_time = int(time.time())

        # first the vm metric case
        if args.datastore == False:
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
        view = get_container_view(si, obj_type=[my_obj_type])
        my_data = collect_properties(
            si,
            view_ref=view,
            obj_type=my_obj_type,
            path_set=my_properties,
            include_mors=True)

        my_count = 0

        # define the time range in seconds the metric data from the vcenter should be averaged across
        # all based on vcenter time
        vchtime = si.CurrentTime()
        startTime = vchtime - timedelta(seconds=(interval + 60))
        endTime = vchtime - timedelta(seconds=60)

        # loop over all vmware machines
        for item in my_data:
            try:
                if args.datastore == False:
                  # only consider machines which have an annotation, are powered on, match our regex for the host system and are not in the ignore list
                  if (item["runtime.powerState"] == "poweredOn" and
                          openstack_match_regex.match(item["config.annotation"]) and
                          host_match_regex.match(
                              hostsystemsdict[item["runtime.host"]])
                      ) and not ignore_match_regex.match(item["config.name"]):
                      logging.debug('current vm processed - ' +
                                    item["config.name"])

                      logging.debug('==> running on vcenter node: ' +
                                    hostsystemsdict[item["runtime.host"]])

                      # split the multi-line annotation into a dict per property (name, project-id, ...)
                      annotation_lines = item["config.annotation"].split('\n')

                      # rename flavor: to flavor_, so that it does not break the split on : below
                      annotation_lines = [
                          w.replace('flavor:', 'flavor_')
                          for w in annotation_lines
                      ]

                      # the filter is for filtering out empty lines
                      annotations = dict(
                          s.split(':', 1)
                          for s in filter(None, annotation_lines))

                      # datastore name
                      datastore = item["summary.config.vmPathName"].split('[', 1)[1].split(']')[0]

                      # get a list of metricids for this vm in preparation for the stats query
                      metricIDs = [
                          vim.PerformanceManager.MetricId(
                              counterId=i, instance="*") for i in counterIDs
                      ]

                      # query spec for the metric stats query, the intervalId is the default one
                      logging.debug(
                          '==> vim.PerformanceManager.QuerySpec start: %s' %
                          datetime.now())
                      spec = vim.PerformanceManager.QuerySpec(
                          maxSample=1,
                          entity=item["obj"],
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
                                            hostsystemsdict[item["runtime.host"]]),
                                        item["config.instanceUuid"],
                                        item["config.guestId"],
                                        datastore,
                                        metric_detail).set(val.value[0])
                      logging.debug('==> gauge loop end: %s' % datetime.now())
                # alternatively the datastore metric case
                else:
                    logging.debug('current datastore processed - ' +
                                  item["summary.name"])

                    logging.debug('==> accessible: ' +
                                  str(item["summary.accessible"]))
                    # convert strings to numbers, so that we can generate a prometheus metric from them
                    if item["summary.accessible"] == True:
                      number_accessible = 1
                    else:
                      number_accessible = 0
                    logging.debug('==> capacity: ' +
                                  str(item["summary.capacity"]))
                    logging.debug('==> freeSpace: ' +
                                  str(item["summary.freeSpace"]))
                    logging.debug('==> maintenanceMode: ' +
                                  str(item["summary.maintenanceMode"]))
                    # convert strings to numbers, so that we can generate a prometheus metric from them
                    if item["summary.maintenanceMode"] == "normal":
                      number_maintenanceMode = 0
                    else:
                      # fallback to note if we do not yet catch a value
                      number_maintenanceMode = 99
                      logging.info('unexpected maintenanceMode for datastore ' + item["summary.name"])
                    logging.debug('==> type: ' +
                                  str(item["summary.type"]))
                    logging.debug('==> url: ' +
                                  str(item["summary.url"]))
                    logging.debug('==> overallStatus: ' +
                                  str(item["overallStatus"]))
                    # convert strings to numbers, so that we can generate a prometheus metric from them
                    if item["overallStatus"] == "green":
                      number_overallStatus = 0
                    elif item["overallStatus"] == "yellow":
                      number_overallStatus = 1
                    elif item["overallStatus"] == "red":
                      number_overallStatus = 2
                    else:
                      # fallback to note if we do not yet catch a value
                      number_overallStatus = 99
                      logging.info('unexpected overallStatus for datastore ' + item["summary.name"])

                    # set the gauges for the datastore properties
                    logging.debug('==> gauge start: %s' % datetime.now())
                    gauge['vcenter_datastore_accessible'].labels(item["summary.name"],item["summary.type"],item["summary.url"]).set(number_accessible)
                    gauge['vcenter_datastore_capacity'].labels(item["summary.name"],item["summary.type"],item["summary.url"]).set(item["summary.capacity"])
                    gauge['vcenter_datastore_freespace'].labels(item["summary.name"],item["summary.type"],item["summary.url"]).set(item["summary.freeSpace"])
                    gauge['vcenter_datastore_maintenancemode'].labels(item["summary.name"],item["summary.type"],item["summary.url"]).set(number_maintenanceMode)
                    gauge['vcenter_datastore_overallstatus'].labels(item["summary.name"],item["summary.type"],item["summary.url"]).set(number_overallStatus)
                    logging.debug('==> gauge end: %s' % datetime.now())

                my_count += 1

            except IndexError:
                logging.info('a ' + my_name + ' disappeared during processing')

        loop_end_time = int(time.time())

        logging.info('number of ' + my_name + 's we got metrics for: ' + str(my_count) + ' - actual runtime: ' + str(loop_end_time - loop_start_time) + 's')

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
