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
                                  load_balancer['id'], constants.ACTIVE)

    def delete(self, context, load_balancer):
        self.plugin._delete_loadbalancer(context, load_balancer['id'])


class NoopLbaaSDriver(object):
    """A dummy lbass driver that that only performs object deletion."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.load_balancer = NoopLoadBalancerManager(plugin)


class LbaasTestMixin(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.LOADBALANCERv2])
        for k in loadbalancerv2.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def _get_loadbalancer_optional_args(self):
        return ('description', 'vip_address')

    def _create_loadbalancer(self, fmt, name, admin_state_up, subnet_id,
                             expected_res_status=None, **kwargs):
        data = {'loadbalancer': {'name': name,
                                 'admin_state_up': admin_state_up,
                                 'vip_subnet_id': subnet_id,
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

    @contextlib.contextmanager
    def loadbalancer(self, fmt=None, name='lb1', subnet=None,
                     admin_state_up=True, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            res = self._create_loadbalancer(fmt,
                                            name,
                                            admin_state_up,
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


class TestLoadBalancerXML(TestLbaas):
    fmt = 'xml'
