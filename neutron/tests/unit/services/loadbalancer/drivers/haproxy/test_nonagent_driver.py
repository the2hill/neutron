# Copyright 2014 OpenStack Foundation
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
#

import collections
import contextlib
import uuid

import mock

from neutron.common import exceptions
from neutron.services.loadbalancer.drivers.haproxy \
    import namespace_driver as namespace_driver
from neutron.services.loadbalancer.drivers.haproxy \
    import nonagent_namespace_driver as nonagent_namespace_driver
from neutron.tests import base


class TestHaproxyNSDriver(base.BaseTestCase):
    def setUp(self):
        super(TestHaproxyNSDriver, self).setUp()

        conf = mock.Mock()
        conf.haproxy.loadbalancer_state_path = '/the/path'
        conf.interface_driver = 'intdriver'
        conf.haproxy.user_group = 'test_group'
        conf.haproxy.send_gratuitous_arp = 3
        conf.AGENT.root_helper = 'sudo_test'
        conf.haproxy.periodic_interval = 10
        conf.host = 'host1'
        self.conf = conf
        self.mock_importer = mock.patch.object(nonagent_namespace_driver,
                                               'importutils').start()

        self.context_mock = mock.Mock()
        self.plugin_mock = mock.Mock()
        self.core_plugin_mock = mock.Mock()
        self.mock_service = mock.patch.object(nonagent_namespace_driver,
                                              'HaproxySimpleService').start()
        self.mock_deploy = mock.patch.object(
            nonagent_namespace_driver.HaproxyNSDriver,
            '_deploy_existing_instances').start()
        self.driver = nonagent_namespace_driver.HaproxyNSDriver(
            self.plugin_mock)
        self.driver.state_path = '/the/path/v2'
        self.vif_driver = mock.Mock()
        self.driver.vif_driver = self.vif_driver

    def test_get_ns_name(self):
        self.assertEqual(namespace_driver.get_ns_name('ns_id_1'),
                         namespace_driver.NS_PREFIX + 'ns_id_1')

    def test_create_instance(self):
        with mock.patch.object(self.driver, '_plug') as plug:
            with mock.patch.object(self.driver, '_spawn') as spawn:
                with mock.patch.object(
                        nonagent_namespace_driver, 'get_ns_name') as ns_name:
                    self.driver.create_instance(self.context_mock,
                                                self._sample_in_loadbalancer())
                    ns_name.assert_called_once_with(
                        self._sample_in_loadbalancer().id)
                    plug.assert_called_once_with(
                        self.context_mock,
                        nonagent_namespace_driver.get_ns_name(),
                        self._sample_in_loadbalancer().vip_port)
                    spawn.assert_called_once_with(
                        self._sample_in_loadbalancer())

    def test_plug_vip_port(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'host_routes':
                                               [{'destination': '0.0.0.0/0',
                                                 'nexthop': '10.0.0.1'}]}}]}

        with mock.patch.object(self.driver, '_build_port_dict') as bpd:
            self.driver._plug_vip_port(self.context_mock, test_port)
            bpd.assert_called_once_with()
            self.driver.plugin._core_plugin.get_port.assert_called_once_with(
                self.context_mock, test_port['id'])

    def test_build_port_dict(self):
        self.driver.conf.host = 'host1'
        ret = {'admin_state_up': True,
               'device_owner': 'neutron:LOADBALANCER',
               'device_id': str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                           str(self.conf.host))),
               'binding:host_id': self.conf.host}
        self.assertEqual(ret, self.driver._build_port_dict())

    def test_update_instance(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(self.driver, '_spawn'),
            mock.patch('__builtin__.open')
        ) as (gsp, spawn, mock_open):
            mock_open.return_value = ['5']

            self.driver.update_instance(self._sample_in_loadbalancer())

            mock_open.assert_called_once_with(gsp.return_value, 'r')
            spawn.assert_called_once_with(
                self._sample_in_loadbalancer(), ['-sf', '5'])

    def test_spawn(self):
        with contextlib.nested(
            mock.patch.object(
                    nonagent_namespace_driver.jinja_cfg, 'save_config'),
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ) as (mock_save, gsp, ip_wrap):
            gsp.side_effect = lambda x, y: y

            self.driver._spawn(self._sample_in_loadbalancer())

            mock_save.assert_called_once_with('haproxy.conf',
                                              self._sample_in_loadbalancer(),
                                              'haproxy_stats.sock', 'nogroup')
            cmd = ['haproxy', '-f', 'haproxy.conf', '-p', 'haproxy.pid']
            ns_name = ''.join([nonagent_namespace_driver.NS_PREFIX,
                              self._sample_in_loadbalancer().id])
            ip_wrap.assert_has_calls([
                mock.call('sudo', ns_name),
                mock.call().netns.execute(cmd)
            ])

    def test_delete_instance(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(namespace_driver, 'kill_pids_in_file'),
            mock.patch.object(self.driver, '_unplug'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('os.path.isdir'),
            mock.patch('shutil.rmtree')
        ) as (gsp, kill, unplug, ip_wrap, isdir, rmtree):
            gsp.side_effect = lambda x, y: '/lbns/' + y

            lbid = self._sample_in_loadbalancer().id
            lbns = ''.join(
                [nonagent_namespace_driver.NS_PREFIX,
                 self._sample_in_loadbalancer().id])
            self.driver.deployed_loadbalancer_ids.append(lbid)
            isdir.return_value = True

            self.driver.delete_instance(self._sample_in_loadbalancer())

            kill.assert_called_once_with('sudo', '/lbns/haproxy.pid')
            unplug.assert_called_once_with(
                lbns, self._sample_in_loadbalancer().vip_port_id)
            isdir.assert_called_once_with('/lbns')
            rmtree.assert_called_once_with('/lbns')
            ip_wrap.assert_has_calls([
                mock.call('sudo', lbns),
                mock.call().garbage_collect_namespace()
            ])

    def test_delete_instance_with_ns_cleanup(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch.object(self.driver, 'vif_driver'),
            mock.patch.object(namespace_driver, 'kill_pids_in_file'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('os.path.isdir'),
            mock.patch('shutil.rmtree')
        ) as (gsp, vif, kill, ip_wrap, isdir, rmtree):
            device = mock.Mock()
            device_name = 'port_device'
            device.name = device_name
            ip_wrap.return_value.get_devices.return_value = [device]
            lbns = ''.join(
                [nonagent_namespace_driver.NS_PREFIX,
                 self._sample_in_loadbalancer().id])
            self.driver.delete_instance(self._sample_in_loadbalancer(),
                                        cleanup_namespace=True)
            vif.unplug.assert_any_calls([mock.call(device_name,
                                                   namespace=lbns)])
            self.assertEqual(2, vif.unplug.call_count)

    def test_exists(self):
        with contextlib.nested(
            mock.patch.object(self.driver, '_get_state_file_path'),
            mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
            mock.patch('socket.socket'),
            mock.patch('os.path.exists'),
        ) as (gsp, ip_wrap, socket, path_exists):
            gsp.side_effect = lambda x, y, z: '/pool/' + y

            ip_wrap.return_value.netns.exists.return_value = True
            path_exists.return_value = True

            self.driver.exists(self._sample_in_loadbalancer())
            lbns = ''.join(
                [nonagent_namespace_driver.NS_PREFIX,
                 self._sample_in_loadbalancer().id])
            ip_wrap.assert_has_calls([
                mock.call('sudo'),
                mock.call().netns.exists(lbns)
            ])

            self.assertTrue(
                self.driver.exists(self._sample_in_loadbalancer()))

    def test_get_stats(self):
        raw_stats = ('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,'
                     'dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,'
                     'act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,'
                     'sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,'
                     'check_status,check_code,check_duration,hrsp_1xx,'
                     'hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,'
                     'req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,\n'
                     '8e271901-69ed-403e-a59b-f53cf77ef208,BACKEND,1,2,3,4,0,'
                     '10,7764,2365,0,0,,0,0,0,0,UP,1,1,0,,0,103780,0,,1,2,0,,0'
                     ',,1,0,,0,,,,0,0,0,0,0,0,,,,,0,0,\n\n'
                     'a557019b-dc07-4688-9af4-f5cf02bb6d4b,'
                     '32a6c2a3-420a-44c3-955d-86bd2fc6871e,0,0,0,1,,7,1120,'
                     '224,,0,,0,0,0,0,UP,1,1,0,0,1,2623,303,,1,2,1,,7,,2,0,,'
                     '1,L7OK,200,98,0,7,0,0,0,0,0,,,,0,0,\n'
                     'a557019b-dc07-4688-9af4-f5cf02bb6d4b,'
                     'd9aea044-8867-4e80-9875-16fb808fa0f9,0,0,0,2,,12,0,0,,'
                     '0,,0,0,8,4,DOWN,1,1,0,9,2,308,675,,1,2,2,,4,,2,0,,2,'
                     'L4CON,,2999,0,0,0,0,0,0,0,,,,0,0,\n')
        raw_stats_empty = ('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,'
                           'bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,'
                           'status,weight,act,bck,chkfail,chkdown,lastchg,'
                           'downtime,qlimit,pid,iid,sid,throttle,lbtot,'
                           'tracked,type,rate,rate_lim,rate_max,check_status,'
                           'check_code,check_duration,hrsp_1xx,hrsp_2xx,'
                           'hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,'
                           'req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,'
                           '\n')
        with contextlib.nested(
                mock.patch.object(self.driver, '_get_state_file_path'),
                mock.patch('socket.socket'),
                mock.patch('os.path.exists'),
        ) as (gsp, socket, path_exists):
            gsp.side_effect = lambda x, y, z: '/lbns/' + y
            path_exists.return_value = True
            socket.return_value = socket
            socket.recv.return_value = raw_stats

            exp_stats = {'connection_errors': '0',
                         'active_connections': '3',
                         'current_sessions': '3',
                         'bytes_in': '7764',
                         'max_connections': '4',
                         'max_sessions': '4',
                         'bytes_out': '2365',
                         'response_errors': '0',
                         'total_sessions': '10',
                         'total_connections': '10',
                         'members': {
                             '32a6c2a3-420a-44c3-955d-86bd2fc6871e': {
                                 'status': 'ACTIVE',
                                 'health': 'L7OK',
                                 'failed_checks': '0'
                             },
                             'd9aea044-8867-4e80-9875-16fb808fa0f9': {
                                 'status': 'INACTIVE',
                                 'health': 'L4CON',
                                 'failed_checks': '9'
                             }
                         }
                         }
            stats = self.driver.get_stats(self._sample_in_loadbalancer())
            self.assertEqual(exp_stats, stats)

            socket.recv.return_value = raw_stats_empty
            self.assertEqual({'members': {}}, self.driver.get_stats(
                self._sample_in_loadbalancer()))

            path_exists.return_value = False
            socket.reset_mock()
            self.assertEqual({}, self.driver.get_stats(
                self._sample_in_loadbalancer()))
            self.assertFalse(socket.called)

    def test_plug(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet_id': 'subnet_id_1',
                                    'network_id': 'network_id_1',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'gateway_ip': '10.0.0.1'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
                mock.patch.object(self.driver, '_plug_vip_port'),
                mock.patch.object(self.driver, '_populate_subnets')
        ) as (dev_exists, ip_net, ip_wrap, vp_plug, pop_subnets):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug(self.context_mock, 'test_ns', test_port)
            vp_plug.assert_called_once_with(
                self.context_mock, test_port)
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            cmd_arping = ['arping', '-U', '-I',
                          'test_interface', '-c',
                          self.conf.haproxy.send_gratuitous_arp, '10.0.0.2']
            ip_wrap.assert_has_calls([
                mock.call('sudo', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False),
                mock.call().netns.execute(cmd_arping, check_exit_code=False),
            ])

            dev_exists.return_value = True
            self.assertRaises(exceptions.PreexistingDeviceFailure,
                              self.driver._plug, self.context_mock,
                              'test_ns', test_port, False)

    def test_plug_not_send_gratuitous_arp(self):
        self.driver.conf.haproxy.send_gratuitous_arp = 0
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet_id': 'subnet_id_1',
                                    'network_id': 'network_id_1',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'gateway_ip': '10.0.0.1'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
                mock.patch.object(self.driver, '_plug_vip_port'),
                mock.patch.object(self.driver, '_populate_subnets')
        ) as (dev_exists, ip_net, ip_wrap, vp_plug, pop_subnets):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug(self.context_mock, 'test_ns', test_port)
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            expected = [
                mock.call('sudo', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False)]
            self.assertEqual(expected, ip_wrap.mock_calls)

    def test_plug_no_gw(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet_id': 'subnet_id_1',
                                    'network_id': 'network_id_1',
                                    'subnet': {'cidr': '10.0.0.0/24'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
                mock.patch.object(self.driver, '_plug_vip_port'),
                mock.patch.object(self.driver, '_populate_subnets')
        ) as (dev_exists, ip_net, ip_wrap, vp_plug, pop_subnets):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug(self.context_mock, 'test_ns', test_port)
            self.driver._plug_vip_port.assert_called_once_with(
                self.context_mock, test_port)
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            self.assertFalse(ip_wrap.called)
            dev_exists.return_value = True
            self.assertRaises(exceptions.PreexistingDeviceFailure,
                              self.driver._plug, self.context_mock,
                              'test_ns', test_port, False)

    def test_plug_gw_in_host_routes(self):
        test_port = {'id': 'port_id',
                     'network_id': 'net_id',
                     'mac_address': 'mac_addr',
                     'fixed_ips': [{'ip_address': '10.0.0.2',
                                    'subnet_id': 'subnet_id_1',
                                    'network_id': 'network_id_1',
                                    'subnet': {'cidr': '10.0.0.0/24',
                                               'gateway_ip': '10.0.0.1'}}]}
        with contextlib.nested(
                mock.patch('neutron.agent.linux.ip_lib.device_exists'),
                mock.patch('netaddr.IPNetwork'),
                mock.patch('neutron.agent.linux.ip_lib.IPWrapper'),
                mock.patch.object(self.driver, '_plug_vip_port'),
                mock.patch.object(self.driver, '_populate_subnets')
        ) as (dev_exists, ip_net, ip_wrap, vp_plug, pop_subnets):
            self.vif_driver.get_device_name.return_value = 'test_interface'
            dev_exists.return_value = False
            ip_net.return_value = ip_net
            ip_net.prefixlen = 24

            self.driver._plug(self.context_mock, 'test_ns', test_port)
            self.driver._plug_vip_port.assert_called_once_with(
                self.context_mock, test_port)
            self.assertTrue(dev_exists.called)
            self.vif_driver.plug.assert_called_once_with('net_id', 'port_id',
                                                         'test_interface',
                                                         'mac_addr',
                                                         namespace='test_ns')
            self.vif_driver.init_l3.assert_called_once_with('test_interface',
                                                            ['10.0.0.2/24'],
                                                            namespace=
                                                            'test_ns')
            cmd = ['route', 'add', 'default', 'gw', '10.0.0.1']
            ip_wrap.assert_has_calls([
                mock.call('sudo', namespace='test_ns'),
                mock.call().netns.execute(cmd, check_exit_code=False),
            ])

    def test_unplug(self):
        self.vif_driver.get_device_name.return_value = 'test_interface'

        self.driver._unplug('test_ns', 'port_id')
        self.vif_driver.unplug('test_interface', namespace='test_ns')

    def test_kill_pids_in_file(self):
        with contextlib.nested(
            mock.patch('os.path.exists'),
            mock.patch('__builtin__.open'),
            mock.patch('neutron.agent.linux.utils.execute'),
            mock.patch.object(namespace_driver.LOG, 'exception'),
        ) as (path_exists, mock_open, mock_execute, mock_log):
            file_mock = mock.MagicMock()
            mock_open.return_value = file_mock
            file_mock.__enter__.return_value = file_mock
            file_mock.__iter__.return_value = iter(['123'])

            path_exists.return_value = False
            namespace_driver.kill_pids_in_file('sudo_test', 'test_path')
            path_exists.assert_called_once_with('test_path')
            self.assertFalse(mock_open.called)
            self.assertFalse(mock_execute.called)

            path_exists.return_value = True
            mock_execute.side_effect = RuntimeError
            namespace_driver.kill_pids_in_file('sudo_test', 'test_path')
            self.assertTrue(mock_log.called)
            mock_execute.assert_called_once_with(
                ['kill', '-9', '123'], 'sudo_test')

    def test_get_state_file_path(self):
        with mock.patch('os.makedirs') as mkdir:
            path = self.driver._get_state_file_path('loadbalancer_id', 'conf')
            self.assertEqual('/the/path/v2/loadbalancer_id/conf', path)
            mkdir.assert_called_once_with('/the/path/v2/loadbalancer_id',
                                          0o755)

    #TODO(ptoohill) put samples in reusable location
    def _sample_in_loadbalancer(self):
        in_lb = collections.namedtuple(
            'loadbalancer', 'id, name, vip_address, vip_port_id,'
                            'protocol, vip_port, '
                            'listeners')
        return in_lb(
            id='sample_loadbalancer_id_1',
            name='test-lb',
            vip_address='10.0.0.2',
            vip_port_id='vip_port_id_1',
            protocol='HTTP',
            vip_port=self._sample_in_vip_port(),
            listeners=[self._sample_in_listener()]
        )

    def _sample_in_vip_port(self):
        vip_port = collections.namedtuple('vip_port', 'id, network_id,'
                                                      'mac_address, fixed_ips')
        ip_address = collections.namedtuple('fixed_ips', 'ip_address, subnet')
        subnet = collections.namedtuple('subnet', 'cidr, gateway_ip,')
        in_subnet = subnet(cidr='10.0.0.0/24', gateway_ip='10.0.0.1')
        in_address = ip_address(ip_address='10.0.0.2', subnet=in_subnet)
        return vip_port(id='vip_port_id_1', network_id='nw_id_1',
                        mac_address='mac_address_1', fixed_ips=[in_address])

    def _sample_in_listener(self):
        in_listener = collections.namedtuple(
            'listener', 'id, protocol_port, protocol, default_pool, '
                        'connection_limit')
        return in_listener(
            id='sample_listener_id_1',
            protocol_port='80',
            protocol='HTTP',
            default_pool=self._sample_in_pool(),
            connection_limit='98'
        )

    def _sample_in_pool(self):
        in_pool = collections.namedtuple(
            'pool', 'id, protocol, lb_algorithm, members, health_monitor,'
                    'session_persistence, admin_state_up, status')
        return in_pool(
            id='sample_pool_id_1',
            protocol='HTTP',
            lb_algorithm='ROUND_ROBIN',
            members=[self._sample_in_member()],
            health_monitor=self._sample_in_health_monitor(),
            session_persistence=self._sample_in_session_persistence(),
            admin_state_up='true',
            status='ACTIVE')

    def _sample_in_member(self):
        in_member = collections.namedtuple('member',
                                           'id, address, protocol_port, '
                                           'weight, subnet_id, '
                                           'admin_state_up, status')
        return in_member(
            id='sample_member_id_1',
            address='10.0.0.99',
            protocol_port=82,
            weight=13,
            subnet_id='10.0.0.1/24',
            admin_state_up='true',
            status='ACTIVE')

    def _sample_in_session_persistence(self):
        spersistence = collections.namedtuple('SessionPersistence',
                                              'type, cookie_name')
        return spersistence(type='HTTP_COOKIE',
                            cookie_name='HTTP_COOKIE')

    def _sample_in_health_monitor(self):
        monitor = collections.namedtuple(
            'monitor', 'id, type, delay, timeout, max_retries, http_method, '
                       'url_path, expected_codes, admin_state_up')

        return monitor(id='sample_monitor_id_1', type='HTTP', delay='30',
                       timeout='31', max_retries='3', http_method='GET',
                       url_path='/index.html', expected_codes='500, 405, 404',
                       admin_state_up='true')
