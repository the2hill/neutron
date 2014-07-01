# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import logging

import mock
from oslo.config import cfg
import testtools
import webob.exc

from neutron.api import extensions
from neutron.common import config
from neutron import context
import neutron.db.l3_db  # noqa
from neutron.db.loadbalancer import loadbalancer_dbv2 as ldb
from neutron.db import servicetype_db as sdb
import neutron.extensions
from neutron.extensions import loadbalancerv2
from neutron.plugins.common import constants
from neutron.services.loadbalancer import (
    plugin as loadbalancer_plugin
)
from neutron.services.loadbalancer.drivers import abstract_driver
from neutron.services import provider_configuration as pconf
from neutron.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)

DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_LB_PLUGIN_KLASS = (
    "neutron.services.loadbalancer."
    "plugin.LoadBalancerPluginv2"
)
NOOP_DRIVER_KLASS = ('neutron.tests.unit.db.loadbalancer.'
                     'test_db_loadbalancerv2.NoopLbaaSDriver')

extensions_path = ':'.join(neutron.extensions.__path__)

_subnet_id = "0c798ed8-33ba-11e2-8b28-000c291c4d14"


class BaseManager(object):

    def __init__(self, plugin):
        self.plugin = plugin


class NoopLoadBalancerManager(BaseManager):

    def create(self, context, load_balancer):
        self.plugin.update_status(context, ldb.LoadBalancer,
                                  load_balancer.id, constants.ACTIVE)

    def delete(self, context, load_balancer):
        self.plugin._delete_db_loadbalancer(context, load_balancer.id)


class NoopListenerManager(BaseManager):

    def create(self, context, listener):
        self.plugin.update_status(context, ldb.Listener,
                                  listener.id, constants.ACTIVE)

    def update(self, context, listener, old_listener):
        self.plugin.update_status(context, ldb.Listener,
                                  listener.id, constants.ACTIVE)

    def delete(self, context, listener):
        self.plugin._delete_db_listener(context, listener.id)


class NoopNodePoolManager(BaseManager):

    def create(self, context, nodepool):
        self.plugin.update_status(context, ldb.NodePool,
                                  nodepool.id, constants.ACTIVE)

    def update(self, context, nodepool, old_nodepool):
        self.plugin.update_status(context, ldb.NodePool,
                                  nodepool.id, constants.ACTIVE)

    def delete(self, context, nodepool):
        self.plugin._delete_db_nodepool(context, nodepool.id)


class NoopMemberManager(BaseManager):

    def create(self, context, member):
        self.plugin.update_status(context, ldb.MemberV2,
                                  member.id, constants.ACTIVE)

    def update(self, context, member, old_member):
        self.plugin.update_status(context, ldb.MemberV2,
                                  member.id, constants.ACTIVE)

    def delete(self, context, member):
        self.plugin.delete_member(context, member.id)


class NoopHealthMonitorManager(BaseManager):

    def create(self, context, health_monitor):
        self.plugin.update_status(context, ldb.HealthMonitorV2,
                                  health_monitor.id, constants.ACTIVE)

    def update(self, context, health_monitor, old_health_monitor):
        self.plugin.update_status(context, ldb.HealthMonitorV2,
                                  health_monitor.id, constants.ACTIVE)

    def delete(self, context, health_monitor):
        self.plugin._delete_db_healthmonitor(context, health_monitor.id)


class NoopLbaaSDriver(object):
    """A dummy lbass driver that that only performs object deletion."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.load_balancer = NoopLoadBalancerManager(plugin)
        self.listener = NoopListenerManager(plugin)
        self.nodepool = NoopNodePoolManager(plugin)
        self.member = NoopMemberManager(plugin)
        self.health_monitor = NoopHealthMonitorManager(plugin)


class LbaasTestMixin(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.LOADBALANCERv2])
        for k in loadbalancerv2.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def _get_loadbalancer_optional_args(self):
        return ('description', 'vip_address', 'admin_state_up', 'name')

    def _create_loadbalancer(self, fmt, subnet_id,
                             expected_res_status=None, **kwargs):
        data = {'loadbalancer': {'vip_subnet_id': subnet_id,
                                 'tenant_id': self._tenant_id}}
        args = self._get_loadbalancer_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['loadbalancer'][arg] = kwargs[arg]

        lb_req = self.new_create_request('loadbalancers', data, fmt)
        lb_res = lb_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(lb_res.status_int, expected_res_status)

        return lb_res

    def _get_listener_optional_args(self):
        return ('name', 'description', 'default_pool_id, loadbalancer_id',
                'connection_limit', 'admin_state_up')

    def _create_listener(self, fmt, protocol, protocol_port,
                         expected_res_status=None, **kwargs):
        data = {'listener': {'protocol': protocol,
                             'protocol_port': protocol_port,
                             'tenant_id': self._tenant_id}}
        args = self._get_listener_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['listener'][arg] = kwargs[arg]

        listener_req = self.new_create_request('listeners', data, fmt)
        listener_res = listener_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(listener_res.status_int, expected_res_status)

        return listener_res

    def _get_nodepool_optional_args(self):
        return ('name', 'description', 'healthmonitor_id', 'admin_state_up')

    def _create_nodepool(self, fmt, protocol, lb_algorithm,
                         expected_res_status=None, **kwargs):
        data = {'nodepool': {'protocol': protocol,
                             'lb_algorithm': lb_algorithm,
                             'tenant_id': self._tenant_id}}

        args = self._get_nodepool_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['listener'][arg] = kwargs[arg]

        pool_req = self.new_create_request('nodepools', data, fmt)
        pool_res = pool_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(pool_res.status_int, expected_res_status)

        return pool_res

    def _get_member_optional_args(self):
        return ('weight', 'admin_state_up')

    def _create_member(self, fmt, pool_id, address, protocol_port, subnet_id,
                       expected_res_status=None, **kwargs):
        data = {'member': {'address': address,
                           'protocol_port': protocol_port,
                           'subnet_id': subnet_id,
                           'tenant_id': self._tenant_id}}

        args = self._get_member_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['member'][arg] = kwargs[arg]

        member_req = self.new_create_request('nodepools',
                                             data,
                                             fmt=fmt,
                                             id=pool_id,
                                             subresource='members')
        member_res = member_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(member_res.status_int, expected_res_status)

        return member_res

    def _get_healthmonitor_optional_args(self):
        return ('weight', 'admin_state_up', 'expected_codes', 'url_path',
                'http_method')

    def _create_healthmonitor(self, fmt, type, delay, timeout, max_retries,
                              expected_res_status=None, **kwargs):
        data = {'healthmonitor': {'type': type,
                                  'delay': delay,
                                  'timeout': timeout,
                                  'max_retries': max_retries,
                                  'tenant_id': self._tenant_id}}

        args = self._get_healthmonitor_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['healthmonitor'][arg] = kwargs[arg]

        hm_req = self.new_create_request('healthmonitors', data, fmt)
        hm_res = hm_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(hm_res.status_int, expected_res_status)

        return hm_res

    @contextlib.contextmanager
    def loadbalancer(self, fmt=None, subnet=None, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            res = self._create_loadbalancer(fmt,
                                            tmp_subnet['subnet']['id'],
                                            **kwargs)
            if res.status_int >= webob.exc.HTTPClientError.code:
                raise webob.exc.HTTPClientError(
                    explanation=_("Unexpected error code: %s") %
                    res.status_int
                )
            lb = self.deserialize(fmt or self.fmt, res)
            yield lb
            if not no_delete:
                self._delete('loadbalancers', lb['loadbalancer']['id'])

    @contextlib.contextmanager
    def listener(self, fmt=None, protocol='HTTP', protocol_port=80,
                 no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_listener(fmt,
                                    protocol=protocol,
                                    protocol_port=protocol_port,
                                    **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        listener = self.deserialize(fmt or self.fmt, res)
        yield listener
        if not no_delete:
            self._delete('listeners', listener['listener']['id'])

    @contextlib.contextmanager
    def nodepool(self, fmt=None, protocol='TCP', lb_algorithm='ROUND_ROBIN',
                 no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_nodepool(fmt,
                                    protocol=protocol,
                                    lb_algorithm=lb_algorithm,
                                    **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        nodepool = self.deserialize(fmt or self.fmt, res)
        yield nodepool
        if not no_delete:
            self._delete('nodepools', nodepool['nodepool']['id'])

    @contextlib.contextmanager
    def member(self, fmt=None, pool_id='pool1id', address='127.0.0.1',
               protocol_port=80, subnet=None, no_delete=False,
               **kwargs):
        if not fmt:
            fmt = self.fmt
        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            res = self._create_member(fmt,
                                      pool_id=pool_id,
                                      address=address,
                                      protocol_port=protocol_port,
                                      subnet_id=tmp_subnet['subnet']['id'],
                                      **kwargs)
            if res.status_int >= webob.exc.HTTPClientError.code:
                raise webob.exc.HTTPClientError(
                    explanation=_("Unexpected error code: %s") % res.status_int
                )

            member = self.deserialize(fmt or self.fmt, res)
        yield member
        if not no_delete:
            del_req = self.new_delete_request(
                'nodepools',
                fmt=fmt,
                id=pool_id,
                subresource='members',
                sub_id=member['member']['id'])
            del_res = del_req.get_response(self.ext_api)
            self.assertEqual(del_res.status_int,
                             webob.exc.HTTPNoContent.code)

    @contextlib.contextmanager
    def healthmonitor(self, fmt=None, type='TCP', delay=1, timeout=1,
                      max_retries=1, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_healthmonitor(fmt,
                                         type=type,
                                         delay=delay,
                                         timeout=timeout,
                                         max_retries=max_retries,
                                         **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        healthmonitor = self.deserialize(fmt or self.fmt, res)
        yield healthmonitor
        if not no_delete:
            self._delete('healthmonitors',
                         healthmonitor['healthmonitor']['id'])


class LbaasPluginDbTestCase(LbaasTestMixin,
                            test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, core_plugin=None, lb_plugin=None, lbaas_provider=None,
              ext_mgr=None):
        service_plugins = {'lb_plugin_name': DB_LB_PLUGIN_KLASS}
        if not lbaas_provider:
            lbaas_provider = (
                constants.LOADBALANCERv2 +
                ':lbaas:' + NOOP_DRIVER_KLASS + ':default')
        cfg.CONF.set_override('service_provider',
                              [lbaas_provider],
                              'service_providers')
        #force service type manager to reload configuration:
        sdb.ServiceTypeManager._instance = None

        super(LbaasPluginDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            self.plugin = loadbalancer_plugin.LoadBalancerPluginv2()
            ext_mgr = extensions.PluginAwareExtensionManager(
                extensions_path,
                {constants.LOADBALANCERv2: self.plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        # get_lbaas_agent_patcher = mock.patch(
        #     'neutron.services.loadbalancer.agent_scheduler'
        #     '.LbaasAgentSchedulerDbMixin.get_lbaas_agent_hosting_pool')
        # mock_lbaas_agent = mock.MagicMock()
        # get_lbaas_agent_patcher.start().return_value = mock_lbaas_agent
        # mock_lbaas_agent.__getitem__.return_value = {'host': 'host'}

        self._subnet_id = _subnet_id


class TestLbaas(LbaasPluginDbTestCase):

    def test_create_loadbalancer(self, **extras):
        expected = {
            'name': 'vip1',
            'description': '',
            'admin_state_up': True,
            'status': 'ACTIVE',
            'tenant_id': self._tenant_id
        }

        expected.update(extras)

        with self.subnet() as subnet:
            expected['vip_subnet_id'] = subnet['subnet']['id']
            name = expected['name']

            with self.loadbalancer(name=name, subnet=subnet, **extras) as lb:
                for k in ('id', 'vip_address', 'vip_subnet_id'):
                    self.assertTrue(lb['loadbalancer'].get(k, None))

                actual = {k: v for k, v in lb['loadbalancer'].items()
                          if k in expected}
                self.assertEqual(actual, expected)
            return lb

    def test_create_listener(self, **extras):
        expected = {
            'protocol': 'HTTP',
            'protocol_port': 80,
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.listener() as listener:
            self.assertTrue(listener['listener'].get('id'))

            actual = {k: v for k, v in listener['listener'].items()
                      if k in expected}
            self.assertEqual(actual, expected)
        return listener

    def test_create_nodepool(self, **extras):
        expected = {
            'name': '',
            'description': '',
            'protocol': 'TCP',
            'lb_algorithm': 'ROUND_ROBIN',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'healthmonitor_id': None,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.nodepool() as nodepool:
            self.assertTrue(nodepool['nodepool'].get('id'))

            actual = {k: v for k, v in nodepool['nodepool'].items()
                      if k in expected}
            self.assertEqual(actual, expected)
        return nodepool

    def test_create_member(self, **extras):
        expected = {
            'address': '127.0.0.1',
            'protocol_port': 80,
            'weight': 1,
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE,
            'subnet_id': ''
        }

        expected.update(extras)

        with self.subnet() as subnet:
            expected['subnet_id'] = subnet['subnet']['id']
            with self.nodepool() as nodepool:
                nodepool_id = nodepool['nodepool']['id']
                with self.member(pool_id=nodepool_id,
                                 subnet=subnet) as member:
                    self.assertTrue(member['member'].get('id'))

                    actual = {k: v for k, v in member['member'].items()
                              if k in expected}
                    self.assertEqual(actual, expected)
        return member

    def test_create_healthmonitor(self, **extras):
        expected = {
            'type': 'TCP',
            'delay': 1,
            'timeout': 1,
            'max_retries': 1,
            'http_method': 'GET',
            'url_path': '/',
            'expected_codes': '200',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.healthmonitor() as healthmonitor:
            self.assertTrue(healthmonitor['healthmonitor'].get('id'))

            actual = {k: v for k, v in healthmonitor['healthmonitor'].items()
                      if k in expected}
            self.assertEqual(expected, actual)
        return healthmonitor


class TestLoadBalancerXML(TestLbaas):
    fmt = 'xml'
