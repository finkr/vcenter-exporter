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
from vcenter_util import *
from datetime import timedelta, datetime


class VcenterExporter():

    # Supported exporter types - Checked on CLI
    supported_types = ['CUSTVM', 'CUSTDS', 'VERSIONSANDAPI',
                       'INFRAESX', 'VCHEALTH']

    # vcenter connection defaults
    defaults = {
        'ignore_ssl': True,
        'vcenter_port': 443,
        'vc_polling_interval': 120,
        'vcenter_hostname': 'localhost',
        'vcenter_user': 'administrator@vsphere.local',
        'vcenter_password': 'password',
        'prometheus_port': 9102
    }

    def __init__(self, configs, exporter_type):

        # Set vars to local object vars
        self.exporter_type = exporter_type.upper()
        self.configs = configs

        # Create empty structures for use
        self.gauge = {}
        self.counter_info = {}
        self.counter_ids_to_collect = []
        self.regexs = {}
        self.metric_count = 0
        if self.exporter_type == "VERSIONSANDAPI":
            self.sessions_dict = {}
            self.configs['main']['interval'] = 120

        # List of properties we want for VMs and datastores
        self.vm_properties = [
            "runtime.powerState", "runtime.host", "config.annotation", "config.name",
            "config.instanceUuid", "config.guestId", "summary.config.vmPathName"
        ]
        self.datastore_properties = [
            "summary.accessible", "summary.capacity", "summary.freeSpace",
            "summary.maintenanceMode", "summary.name",
            "summary.type", "summary.url", "overallStatus"
        ]
        self.host_properties =[
            "summary.config.name", "config.product.version",
            "config.product.build"
        ]

        # exporter type to function dictionary:  Call appropriate functions for each exporter type
        self.function_map = {"SETGAUGES": 0, "GETMETRICS": 1}
        self.function_list = {
            "CUSTVM": [self.setup_cust_vm, self.get_cust_vm_metrics],
            "CUSTDS": [self.setup_cust_ds, self.get_cust_ds_metrics],
            "VERSIONSANDAPI": [self.setup_versions_and_api, self.get_versions_and_api_metrics],
            "VCHEALTH": [self.setup_vc_health, self.get_vc_health_metrics],
            "INFRAESX": [self.setup_infra_esx, self.get_infra_esx_metrics]
        }

        # Start logging
        self.logger = logging.getLogger()

        # set default log level if not defined in config file
        if self.configs['main']['exporter_log_level']:
            self.logger.setLevel(
                logging.getLevelName(self.configs['main']['exporter_log_level'].upper()))
        else:
            self.logger.setLevel('INFO')
        format = '[%(asctime)s] [%(levelname)s] %(message)s'
        logging.basicConfig(stream=sys.stdout, format=format)

        # Start http server for exported data
        try:
            start_http_server(int(self.configs['main']['prometheus_port']))
        except Exception as e:
            logging.debug("Couldn't start exporter http:" + str(e))

        # vCenter preparations
        # check for insecure ssl option
        if self.configs['main']['ignore_ssl'] and \
                hasattr(ssl, "_create_unverified_context"):
            self.context = ssl._create_unverified_context()
        else:
            self.context = None

        # Connect to the vCenter
        self.si = connect_to_vcenter(self.configs['main']['vcenter_host'],
                                     self.configs['main']['vcenter_user'],
                                     self.configs['main']['vcenter_password'],
                                     self.configs['main']['vcenter_port'],
                                     self.context)
        atexit.register(Disconnect, self.si)
        # Create attributes for Containerviews
        content = self.si.RetrieveContent()
        self.container = content.rootFolder
        datacenter = content.rootFolder.childEntity[0]
        self.datacentername = datacenter.name

        # compile a regex for trying to filter out openstack generated vms
        # they all have the "name:" field set
        self.regexs['openstack_match_regex'] = re.compile("^name")

        # Compile other regexs
        #for regular_expression in ['shorter_names_regex', 'host_match_regex', 'ignore_match_regex']:
        for regular_expression in ['name_shortening_regex', 'ignore_vm_match_regex', 'ignore_ds_match_regex']:
            if self.configs['main'][regular_expression]:
                self.regexs[regular_expression] = re.compile(
                    self.configs['main'][regular_expression]
                )
            else:
                self.regexs[regular_expression] = re.compile('')

    def setup_cust_vm(self):

        content = self.si.content
        perf_manager = content.perfManager
        vm_counter_ids = perf_manager.QueryPerfCounterByLevel(level=4)

        # Store all counter information in self.counter_info and create gauges
        logging.debug('list of all available metrics and their counterids')
        for vm_counter_id in vm_counter_ids:

            full_name = '.'.join([vm_counter_id.groupInfo.key, vm_counter_id.nameInfo.key,
                                  vm_counter_id.rollupType])
            logging.debug(full_name + ": %s", str(vm_counter_id.key))
            self.counter_info[full_name] = vm_counter_id.key

        selected_metrics = config.get('main').get('vm_metrics')

        # Populate counter_ids_to_collect from config if specified
        if selected_metrics:
            self.counter_ids_to_collect = [self.counter_info[i] for i in selected_metrics
                                           if i in self.counter_info]
        else:
            self.counter_ids_to_collect = [i.key for i in self.counter_info]
        for counter_id in selected_metrics:
            # vc_gauge = 'vcenter_' + full_name.replace('.', '_')
            vc_gauge = 'vcenter_' + counter_id.replace('.', '_')
            self.gauge[vc_gauge] = Gauge(vc_gauge, vc_gauge, [
                'vmware_name', 'project_id', 'vcenter_name', 'vcenter_node',
                'instance_uuid', 'guest_id', 'datastore', 'metric_detail'
            ])

        # get all the data regarding vcenter hosts
        self.host_view = content.viewManager.CreateContainerView(
            self.container, [vim.HostSystem], True)

        # get vm containerview
        self.view_ref = self.si.content.viewManager.CreateContainerView(
            container=self.container,
            type=[vim.VirtualMachine],
            recursive=True
        )

    def setup_cust_ds(self):

        # define the gauges - they have to be defined by hand for the datastores,
        # as there is no clear pattern behind
        self.gauge['vcenter_datastore_accessible'] = Gauge('vcenter_datastore_accessible',
                                                           'vcenter_datastore_accessible',
                                                           ['datastore_name',
                                                            'datastore_type',
                                                            'datastore_url'])
        self.gauge['vcenter_datastore_capacity'] = Gauge('vcenter_datastore_capacity',
                                                         'vcenter_datastore_capacity',
                                                         ['datastore_name',
                                                          'datastore_type',
                                                          'datastore_url'])
        self.gauge['vcenter_datastore_freespace'] = Gauge('vcenter_datastore_freespace',
                                                          'vcenter_datastore_freespace',
                                                          ['datastore_name',
                                                           'datastore_type',
                                                           'datastore_url'])
        self.gauge['vcenter_datastore_maintenancemode'] = Gauge('vcenter_datastore_maintenancemode',
                                                                'vcenter_datastore_maintenancemode',
                                                                ['datastore_name',
                                                                 'datastore_type',
                                                                 'datastore_url'])
        self.gauge['vcenter_datastore_overallstatus'] = Gauge('vcenter_datastore_overallstatus',
                                                              'vcenter_datastore_overallstatus',
                                                              ['datastore_name',
                                                               'datastore_type',
                                                               'datastore_url'])

        # get datastore containerview
        self.view_ref = self.si.content.viewManager.CreateContainerView(
            container=self.container,
            type=[vim.Datastore],
            recursive=True
        )

    def setup_versions_and_api(self):

        self.gauge['vcenter_esx_node_info'] = Gauge('vcenter_esx_node_info',
                                                    'vcenter_esx_node_info',
                                                    ['hostname',
                                                     'version', 'build', 'region'])
        self.gauge['vcenter_vcenter_node_info'] = Gauge('vcenter_vcenter_node_info',
                                                        'vcenter_vcenter_node_info',
                                                        ['hostname',
                                                         'version', 'build', 'region'])
        self.gauge['vcenter_vcenter_api_session_info'] = Gauge('vcenter_vcenter_api_session_info',
                                                               'vcenter_vcenter_api_session_info',
                                                               ['session_key', 'hostname', 'userName', 
                                                                'ipAddress', 'userAgent'])

        self.gauge['vcenter_vcenter_api_active_count'] = Gauge('vcenter_vcenter_api_active_count',
                                                                'vcenter_vcenter_api_active_count',
                                                                ['hostname'])

        self.content = self.si.RetrieveContent()
        self.clusters = [cluster for cluster in
                         self.content.viewManager.CreateContainerView(
                             self.content.rootFolder, [vim.ComputeResource],
                             recursive=True).view
                         ]
        self.hosts = self.si.content.viewManager.CreateContainerView(
            container=self.container,
            type=[vim.HostSystem],
            recursive=True
        )

    def setup_vc_health(self):
        pass

    def setup_infra_esx(self):
        pass

    def get_cust_vm_metrics(self):

        # get data
        data = collect_properties(self.si, self.view_ref, vim.VirtualMachine,
                                  self.vm_properties, True)
        self.metric_count = 0

        # define the time range in seconds the metric data from the vcenter
        #  should be averaged across all based on vcenter time
        vch_time = self.si.CurrentTime()
        start_time = vch_time - \
            timedelta(seconds=(self.configs['main']['vc_polling_interval'] + 60))
        end_time = vch_time - timedelta(seconds=60)
        perf_manager = self.si.content.perfManager

        for item in data:

            try:
                if (item["runtime.powerState"] == "poweredOn" and
                        self.regexs['openstack_match_regex'].match(item["config.annotation"]) and
                        'production' in item["runtime.host"].parent.name
                        ) and not self.regexs['ignore_vm_match_regex'].match(item["config.name"]):
                    logging.debug('current vm processed - ' +
                                  item["config.name"])
                    logging.debug('==> running on vcenter node: ' +
                                  item["runtime.host"].name)

                    # split the multi-line annotation into a dict
                    # per property (name, project-id, ...)
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
                    datastore = item["summary.config.vmPathName"].split('[', 1)[1].split(']')[
                        0]

                    # get a list of metricids for this vm in preparation for the stats query
                    metric_ids = [
                        vim.PerformanceManager.MetricId(
                            counterId=i, instance="*") for i in self.counter_ids_to_collect
                    ]

                    # query spec for the metric stats query, the intervalId is the default one
                    logging.debug(
                        '==> vim.PerformanceManager.QuerySpec start: %s' %
                        datetime.now())
                    spec = vim.PerformanceManager.QuerySpec(
                        maxSample=1,
                        entity=item["obj"],
                        metricId=metric_ids,
                        intervalId=20,
                        startTime=start_time,
                        endTime=end_time)
                    logging.debug(
                        '==> vim.PerformanceManager.QuerySpec end: %s' %
                        datetime.now())

                    # get metric stats from vcenter
                    logging.debug('==> perfManager.QueryStats start: %s' %
                                  datetime.now())
                    result = perf_manager.QueryStats(querySpec=[spec])
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

                            self.gauge['vcenter_' +
                                       list(self.counter_info.keys())[list(self.counter_info.values())
                                                                 .index(val.id.counterId)]
                                       .replace('.', '_')].labels(
                                           annotations['name'],
                                           annotations['projectid'], self.datacentername,
                                           self.regexs['name_shortening_regex'].sub(
                                               '',
                                               item["runtime.host"].name),
                                           item["config.instanceUuid"],
                                           item["config.guestId"],
                                           datastore,
                                           metric_detail).set(val.value[0])
                    logging.debug('==> gauge loop end: %s' % datetime.now())
                    logging.debug("collected data for " + item['config.name'])

                else:
                    logging.debug("didn't collect info for " + item['config.name'] +
                                  " didn't meet requirements")
                self.metric_count += 1

            # some vms do not have config.name define - we are not interested in them and can ignore them
            except KeyError as e:
                logging.debug("property not defined for vm: " + str(e))

            except Exception as e:
                logging.info("couldn't get perf data: " + str(e))

    def get_cust_ds_metrics(self):

        # get data
        data = collect_properties(self.si, self.view_ref, vim.Datastore,
                                  self.datastore_properties, True)
        self.metric_count = 0

        # define the time range in seconds the metric data from the
        # vcenter should be averaged across all based on vcenter time
        vch_time = self.si.CurrentTime()
        start_time = vch_time - \
            timedelta(seconds=(self.configs['main']['vc_polling_interval'] + 60))
        end_time = vch_time - timedelta(seconds=60)

        for item in data:
            if not self.regexs['ignore_ds_match_regex'].match(item["summary.name"]):
                try:
                    logging.debug('current datastore processed - ' +
                                item["summary.name"])

                    logging.debug('==> accessible: ' +
                                str(item["summary.accessible"]))
                    # convert strings to numbers, so that we can generate a prometheus metric from them
                    if item["summary.accessible"]:
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
                        number_maintenance_mode = 0
                    else:
                        # fallback to note if we do not yet catch a value
                        number_maintenance_mode = -1
                        logging.info(
                            'unexpected maintenanceMode for datastore ' + item["summary.name"])
                    logging.debug('==> type: ' +
                                str(item["summary.type"]))
                    logging.debug('==> url: ' +
                                str(item["summary.url"]))
                    logging.debug('==> overallStatus: ' +
                                str(item["overallStatus"]))
                    # convert strings to numbers, so that we can generate a prometheus metric from them
                    if item["overallStatus"] == "green":
                        number_overall_status = 0
                    elif item["overallStatus"] == "yellow":
                        number_overall_status = 1
                    elif item["overallStatus"] == "red":
                        number_overall_status = 2
                    else:
                        # fallback to note if we do not yet catch a value
                        number_overall_status = -1
                        logging.info(
                            'unexpected overallStatus for datastore ' + item["summary.name"])

                    # set the gauges for the datastore properties
                    logging.debug('==> gauge start: %s' % datetime.now())
                    self.gauge['vcenter_datastore_accessible'].labels(item["summary.name"],
                                                                    item["summary.type"],
                                                                    item["summary.url"]
                                                                    ).set(number_accessible)
                    self.gauge['vcenter_datastore_capacity'].labels(item["summary.name"],
                                                                    item["summary.type"],
                                                                    item["summary.url"]
                                                                    ).set(item["summary.capacity"])
                    self.gauge['vcenter_datastore_freespace'].labels(item["summary.name"],
                                                                    item["summary.type"],
                                                                    item["summary.url"]
                                                                    ).set(item["summary.freeSpace"])
                    self.gauge['vcenter_datastore_maintenancemode'].labels(item["summary.name"],
                                                                        item["summary.type"],
                                                                        item["summary.url"]
                                                                        ).set(number_maintenance_mode)
                    self.gauge['vcenter_datastore_overallstatus'].labels(item["summary.name"],
                                                                        item["summary.type"],
                                                                        item["summary.url"]
                                                                        ).set(number_overall_status)
                    logging.debug('==> gauge end: %s' % datetime.now())

                    self.metric_count += 1

                except Exception as e:
                    logging.info("Couldn't get perf data: " + str(e))

    def get_versions_and_api_metrics(self):

        region = self.configs['main']['vcenter_host'].split('.')[2]
        self.metric_count = 0
        logging.debug('get clusters from content')

        logging.debug(self.configs['main']['vcenter_host'] +
                      ": " + self.content.about.version)
        self.gauge['vcenter_vcenter_node_info'].labels(self.configs['main']['vcenter_host'],
                                                       self.content.about.version,
                                                       self.content.about.build, region).set(1)
        self.metric_count += 1

        logging.debug('get version information for each esx host')

        host_data = collect_properties(self.si, self.hosts,
                                    vim.HostSystem, self.host_properties, True)
        for host in host_data:
            try:
                logging.debug(host['summary.config.name'] + ": " +
                                host['config.product.version'])
                self.gauge['vcenter_esx_node_info'].labels(host['summary.config.name'],
                                                            host['config.product.version'],
                                                            host['config.product.build'], region).set(1)
                self.metric_count += 1

            except Exception as e:
                logging.debug(
                    "Couldn't get information for a host: " + str(e))

        # Get current session information and check with saved sessions info
        logging.debug('getting api session information')

        try:
            current_sessions = [x for x in self.content.sessionManager.sessionList]
        except Exception as e:
            logging.debug('Error getting api session info' + str(e))

        for session in current_sessions:
            if self.sessions_dict.get(session.key):
                self.sessions_dict[session.key]['callsPerInterval'] = \
                    session.callCount - self.sessions_dict[session.key]['callsLastInterval']
                self.sessions_dict[session.key]['callsLastInterval'] = session.callCount
            else:
                dict_entry = {'userName': session.userName,
                                'ipAddress': session.ipAddress,
                                'userAgent': session.userAgent,
                                'callsPerInterval': 0,
                                'callsLastInterval': session.callCount}
                self.sessions_dict[session.key] = dict_entry
        

        # Cleanup ended sessions
        session_keys_current = [x.key for x in current_sessions]
        session_keys_in_dict = self.sessions_dict.keys()

        for key in session_keys_in_dict:
                if not key in session_keys_current:
                    try:
                        remove_data = self.sessions_dict.pop(key)
                        self.gauge['vcenter_vcenter_api_session_info'].remove(key[0:8], 
                            self.configs['main']['host'],
                            remove_data['userName'], 
                            remove_data['ipAddress'],
                            remove_data['userAgent']
                        )
                    except Exception as e:
                        logging.debug('Error removing gauge: ' + str(e))

        logging.debug('processing api session information')
        for session in self.sessions_dict:
            self.gauge['vcenter_vcenter_api_session_info'].labels(session[0:8],
                        self.configs['main']['vcenter_host'], 
                        self.sessions_dict[session]['userName'], 
                        self.sessions_dict[session]['ipAddress'],
                        self.sessions_dict[session]['userAgent']).set(self.sessions_dict[session]['callsPerInterval'])

        self.gauge['vcenter_vcenter_api_active_count'].labels(self.configs['main']['vcenter_host']).set(
            len(current_sessions)
        )  

    def get_vc_health_metrics(self):
        pass

    def get_infra_esx_metrics(self):
        pass

    def collect_metrics(self):

        # Configure gauges
        self.function_list[self.exporter_type][self.function_map['SETGAUGES']]()

        # Start infinite loop to get metrics
        while True:
            logging.debug('====> total loop start: %s' % datetime.now())
            # get the start time of the loop to be able to fill it to intervall exactly at the end
            loop_start_time = int(time.time())

            # Get the metrics
            self.function_list[self.exporter_type][self.function_map['GETMETRICS']](
            )

            loop_end_time = int(time.time())
            logging.info('number of ' + self.exporter_type + ' we got metrics for ' +
                         str(self.metric_count) + " " + self.exporter_type +
                         '\'s - actual runtime: ' + str(loop_end_time - loop_start_time) + 's')

            # this is the time we sleep to fill the loop runtime until it reaches "interval"
            # the 0.9 makes sure we have some overlap to the last interval to avoid gaps in
            # metrics coverage (i.e. we get the metrics quicker than the averaging time)
            loop_sleep_time = 0.9 * \
                self.configs['main']['vc_polling_interval'] - \
                (loop_end_time - loop_start_time)
            if loop_sleep_time < 0:
                logging.warn('getting the metrics takes around ' + str(
                    self.configs['main']['vc_polling_interval']) + ' seconds or longer - please increase the interval setting')
                loop_sleep_time = 0

            logging.debug('====> loop end before sleep: %s' % datetime.now())
            time.sleep(int(loop_sleep_time))
            logging.debug('====> total loop end: %s' % datetime.now())


if __name__ == "__main__":
    # config file parsing
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="Specify config file", metavar="FILE", default="config.yaml")
    parser.add_argument(
        "-t", "--type", help="The type of exporter [VM, versions, datastores]", default="versionsandapi")
    args, remaining_argv = parser.parse_known_args()
    config = YamlConfig(args.config, VcenterExporter.defaults)

    if args.type.upper() not in VcenterExporter.supported_types:
        sys.exit("Current supported exporter types [--t] are " +
                 ', '.join(VcenterExporter.supported_types))

    vcenter_exporter = VcenterExporter(config, args.type)
    vcenter_exporter.collect_metrics()
