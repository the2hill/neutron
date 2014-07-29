#
# Copyright 2014 Openstack Foundation.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import shutil
import socket
import uuid

import netaddr
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import exceptions
from neutron.common import utils as n_utils
from neutron import context
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import service
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer.drivers import driver_base
from neutron.services.loadbalancer.drivers.haproxy import jinja_cfg
from neutron.services.loadbalancer.drivers.haproxy import namespace_driver

LOG = logging.getLogger(__name__)
NS_PREFIX = 'nlbaas-'
STATS_TYPE_BACKEND_REQUEST = 2
STATS_TYPE_BACKEND_RESPONSE = '1'
STATS_TYPE_SERVER_REQUEST = 4
STATS_TYPE_SERVER_RESPONSE = '2'
STATE_PATH_DEFAULT = '$state_path/lbaas'
#Do not want v1 instances to be in same directory as v2
STATE_PATH_V2_APPEND = 'v2'
USER_GROUP_DEFAULT = 'nogroup'

OPTS = [
    cfg.StrOpt(
        'loadbalancer_state_path',
        default=STATE_PATH_DEFAULT,
        help=_('Location to store config and state files'),
        deprecated_opts=[cfg.DeprecatedOpt('loadbalancer_state_path')],
    ),
    cfg.StrOpt(
        'user_group',
        default=USER_GROUP_DEFAULT,
        help=_('The user group'),
        deprecated_opts=[cfg.DeprecatedOpt('user_group')],
    ),
    cfg.IntOpt(
        'send_gratuitous_arp',
        default=3,
        help=_('When delete and re-add the same vip, send this many '
               'gratuitous ARPs to flush the ARP cache in the Router. '
               'Set it below or equal to 0 to disable this feature.'),
    ),
    cfg.StrOpt('interface_driver',
               default='neutron.agent.linux.interface.OVSInterfaceDriver',
               help=_("The driver used to manage the virtual interface.")),
    cfg.IntOpt('periodic_interval',
               default=10,
               help=_('Seconds between periodic task runs'))

]
cfg.CONF.register_opts(OPTS, 'haproxy')
cfg.CONF.register_opts(interface.OPTS)
config.register_root_helper(cfg.CONF)


def get_ns_name(namespace_id):
    return NS_PREFIX + namespace_id


class HaproxySimpleService(service.Service):

    def __init__(self, driver):
        super(HaproxySimpleService, self).__init__()
        self.driver = driver

    def start(self):
        super(HaproxySimpleService, self).start()
        self.tg.add_timer(self.driver.conf.haproxy.periodic_interval,
                          self.driver.periodic_tasks,
                          None,
                          None)


class HaproxyNSDriver(driver_base.LoadBalancerBaseDriver):

    def __init__(self, plugin):
        super(HaproxyNSDriver, self).__init__(plugin)
        self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.state_path = '/'.join([self.conf.haproxy.loadbalancer_state_path,
                                    STATE_PATH_V2_APPEND])
        try:
            vif_driver = importutils.import_object(
                self.conf.haproxy.interface_driver, self.conf)
        except ImportError:
            with excutils.save_and_reraise_exception():
                msg = (_('Error importing interface driver: %s')
                       % self.conf.haproxy.interface_driver)
                LOG.error(msg)
        self.vif_driver = vif_driver

        # instantiate managers here

        self.deployed_loadbalancer_ids = []
        self._deploy_existing_instances()

        HaproxySimpleService(self).start()

    def _deploy_existing_instances(self):
        ctx = context.get_admin_context()
        dirs = [dir for dir in os.listdir(self.state_path)
                if os.path.isdir(os.path.join(self.state_path, dir))]
        loadbalancers = [self.plugin._get_resource(
            ctx, self.load_balancer.model_class, dir) for dir in dirs]
        loadbalancer_ids = [loadbalancer.id for loadbalancer in loadbalancers]
        self.deployed_loadbalancer_ids.extend(loadbalancer_ids)
        for loadbalancer in loadbalancers:
            self.update_instance(loadbalancer)

    def _plug_vip_port(self, context, port):
        port_dict = self.plugin._core_plugin.get_port(context, port['id'])
        self._build_port_dict()
        self.plugin._core_plugin.update_port(
            context,
            port['id'],
            {'port': port_dict}
        )

    def _build_port_dict(self):
        return {'admin_state_up': True,
                'device_owner': 'neutron:{0}'.format(
                    constants.LOADBALANCER),
                'device_id': str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                            str(self.conf.host))),
                portbindings.HOST_ID: self.conf.host}

    def _get_state_file_path(self, loadbalancer_id, kind,
                             ensure_state_dir=True):
        """Returns the file name for a given kind of config file."""
        confs_dir = os.path.abspath(os.path.normpath(self.state_path))
        conf_dir = os.path.join(confs_dir, loadbalancer_id)
        if ensure_state_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)
        return os.path.join(conf_dir, kind)

    def _populate_subnets(self, context, port):
        for fixed_ip in port['fixed_ips']:
            fixed_ip['subnet'] = self.plugin._core_plugin.get_subnet(
                context, fixed_ip['subnet_id'])

    def _plug(self, context, namespace, port, reuse_existing=True):
        self._plug_vip_port(context, port)

        interface_name = self.vif_driver.get_device_name(
            namespace_driver.Wrap(port))

        if ip_lib.device_exists(interface_name, self.root_helper,
                                namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name
                )
        else:
            self.vif_driver.plug(
                port['network_id'],
                port['id'],
                interface_name,
                port['mac_address'],
                namespace=namespace
            )

        self._populate_subnets(context, port)

        cidrs = [
            '%s/%s' % (ip['ip_address'],
                       netaddr.IPNetwork(ip['subnet']['cidr']).prefixlen)
            for ip in port['fixed_ips']
        ]
        self.vif_driver.init_l3(interface_name, cidrs,
                                namespace=namespace)

        gw_ip = port['fixed_ips'][0]['subnet'].get('gateway_ip')

        if not gw_ip:
            host_routes = port['fixed_ips'][0]['subnet'].get('host_routes', [])
            for host_route in host_routes:
                if host_route['destination'] == "0.0.0.0/0":
                    gw_ip = host_route['nexthop']
                    break

        if gw_ip:
            cmd = ['route', 'add', 'default', 'gw', gw_ip]
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=namespace)
            ip_wrapper.netns.execute(cmd, check_exit_code=False)
            # When delete and re-add the same vip, we need to
            # send gratuitous ARP to flush the ARP cache in the Router.
            gratuitous_arp = self.conf.haproxy.send_gratuitous_arp
            if gratuitous_arp > 0:
                for ip in port['fixed_ips']:
                    cmd_arping = ['arping', '-U',
                                  '-I', interface_name,
                                  '-c', gratuitous_arp,
                                  ip['ip_address']]
                    ip_wrapper.netns.execute(cmd_arping, check_exit_code=False)

    def _unplug(self, namespace, port_id):
        port_stub = {'id': port_id}
        interface_name = self.vif_driver.get_device_name(
            namespace_driver.Wrap(port_stub))
        self.vif_driver.unplug(interface_name, namespace=namespace)

    def _spawn(self, loadbalancer, extra_cmd_args=()):
        namespace = get_ns_name(loadbalancer.id)
        conf_path = self._get_state_file_path(loadbalancer.id, 'haproxy.conf')
        pid_path = self._get_state_file_path(loadbalancer.id,
                                             'haproxy.pid')
        sock_path = self._get_state_file_path(loadbalancer.id,
                                              'haproxy_stats.sock')
        user_group = self.conf.haproxy.user_group

        jinja_cfg.save_config(conf_path, loadbalancer, sock_path, user_group)
        cmd = ['haproxy', '-f', conf_path, '-p', pid_path]
        cmd.extend(extra_cmd_args)

        ns = ip_lib.IPWrapper(self.root_helper, namespace)
        ns.netns.execute(cmd)

        # remember deployed loadbalancer id
        self.deployed_loadbalancer_ids.append(loadbalancer.id)

    def _get_backend_stats(self, parsed_stats):
        for stats in parsed_stats:
            if stats.get('type') == STATS_TYPE_BACKEND_RESPONSE:
                unified_stats = dict((k, stats.get(v, ''))
                                     for k, v in jinja_cfg.STATS_MAP.items())
                return unified_stats

        return {}

    def _get_servers_stats(self, parsed_stats):
        res = {}
        for stats in parsed_stats:
            if stats.get('type') == STATS_TYPE_SERVER_RESPONSE:
                res[stats['svname']] = {
                    lb_const.STATS_STATUS: (constants.INACTIVE
                                            if stats['status'] == 'DOWN'
                                            else constants.ACTIVE),
                    lb_const.STATS_HEALTH: stats['check_status'],
                    lb_const.STATS_FAILED_CHECKS: stats['chkfail']
                }
        return res

    def _get_stats_from_socket(self, socket_path, entity_type):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(socket_path)
            s.send('show stat -1 %s -1\n' % entity_type)
            raw_stats = ''
            chunk_size = 1024
            while True:
                chunk = s.recv(chunk_size)
                raw_stats += chunk
                if len(chunk) < chunk_size:
                    break

            return self._parse_stats(raw_stats)
        except socket.error as e:
            LOG.warn(_('Error while connecting to stats socket: %s'), e)
            return {}

    def _parse_stats(self, raw_stats):
        stat_lines = raw_stats.splitlines()
        if len(stat_lines) < 2:
            return []
        stat_names = [name.strip('# ') for name in stat_lines[0].split(',')]
        res_stats = []
        for raw_values in stat_lines[1:]:
            if not raw_values:
                continue
            stat_values = [value.strip() for value in raw_values.split(',')]
            res_stats.append(dict(zip(stat_names, stat_values)))

        return res_stats

    def _collect_and_store_stats(self):
        ctx = context.get_admin_context()
        for loadbalancer_id in self.deployed_loadbalancer_ids:
            loadbalancer = self.plugin._get_resource(
                ctx, self.load_balancer.model_class, loadbalancer_id)
            stats = self.get_stats(loadbalancer)
            self.plugin.update_loadbalancer_stats(ctx, loadbalancer.id, stats)
            if 'members' in stats:
                self._set_member_status(ctx, loadbalancer, stats['members'])

    def _set_member_status(self, context, loadbalancer, members_stats):
        for listener in loadbalancer.listeners:
            if listener.default_pool:
                for member in listener.default_pool.members:
                    if member.id in members_stats:
                        status = members_stats[member.id].get('status')
                        if status and status == constants.ACTIVE:
                            self.plugin.update_status(
                                context,
                                self.member.model_class,
                                member.id, constants.ACTIVE)
                        else:
                            self.plugin.update_status(
                                context,
                                self.member.model_class,
                                member.id, constants.INACTIVE)

    def periodic_tasks(self, *args):
        self._collect_and_store_stats()

    @n_utils.synchronized('haproxy-no-agent-driver')
    def create_instance(self, context, loadbalancer):
        namespace = get_ns_name(loadbalancer.id)

        self._plug(context, namespace, loadbalancer.vip_port)
        self._spawn(loadbalancer)

    @n_utils.synchronized('haproxy-no-agent-driver')
    def update_instance(self, loadbalancer):
        pid_path = self._get_state_file_path(loadbalancer.id,
                                             'haproxy.pid')

        extra_args = ['-sf']
        extra_args.extend(p.strip() for p in open(pid_path, 'r'))
        self._spawn(loadbalancer, extra_args)

    @n_utils.synchronized('haproxy-no-agent-driver')
    def delete_instance(self, loadbalancer, cleanup_namespace=False):
        namespace = get_ns_name(loadbalancer.id)
        ns = ip_lib.IPWrapper(self.root_helper, namespace)
        pid_path = self._get_state_file_path(loadbalancer.id,
                                             'haproxy.pid')

        # kill the process
        namespace_driver.kill_pids_in_file(self.root_helper, pid_path)

        # unplug the ports
        if loadbalancer.vip_port_id:
            self._unplug(namespace, loadbalancer.vip_port_id)

        # delete all devices from namespace;
        # used when deleting orphans and port_id is not known for
        # loadbalancer_id
        if cleanup_namespace:
            for device in ns.get_devices(exclude_loopback=True):
                self.vif_driver.unplug(device.name, namespace=namespace)

        # remove the configuration directory
        conf_dir = os.path.dirname(
            self._get_state_file_path(loadbalancer.id, ''))
        if os.path.isdir(conf_dir):
            shutil.rmtree(conf_dir)
        ns.garbage_collect_namespace()

    def exists(self, loadbalancer):
        namespace = get_ns_name(loadbalancer.id)
        root_ns = ip_lib.IPWrapper(self.root_helper)

        socket_path = self._get_state_file_path(
            loadbalancer.id, 'haproxy_stats.sock', False)
        if root_ns.netns.exists(namespace) and os.path.exists(socket_path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(socket_path)
                return True
            except socket.error:
                pass
        return False

    def get_stats(self, loadbalancer):
        socket_path = self._get_state_file_path(loadbalancer.id,
                                                'haproxy_stats.sock',
                                                False)
        if os.path.exists(socket_path):
            parsed_stats = self._get_stats_from_socket(
                socket_path,
                entity_type=(STATS_TYPE_BACKEND_REQUEST |
                             STATS_TYPE_SERVER_REQUEST))
            lb_stats = self._get_backend_stats(parsed_stats)
            lb_stats['members'] = self._get_servers_stats(parsed_stats)
            return lb_stats
        else:
            LOG.warn(_('Stats socket not found for load balancer %s'),
                     loadbalancer.id)
            return {}
