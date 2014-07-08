#
# Copyright 2014 OpenStack Foundation.  All rights reserved
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


from oslo.db import exception
import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import validates

from neutron.api.v2 import attributes
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import servicetype_db as st_db
from neutron.extensions import loadbalancerv2
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const


LOG = logging.getLogger(__name__)


class SessionPersistenceV2(model_base.BASEV2):

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_sessionpersistences"

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("lbaas_pools.id"),
                        primary_key=True,
                        nullable=False)
    type = sa.Column(sa.Enum(*lb_const.SUPPORTED_SP_TYPES,
                             name="lbaas_sesssionpersistences_type"),
                     nullable=False)
    cookie_name = sa.Column(sa.String(1024), nullable=True)

    def to_dict(self, pool=False):
        sp_dict = super(SessionPersistenceV2, self).to_dict(
            exclude=['pool_id'])
        if pool and self.pool:
            sp_dict['pool'] = self.pool.to_dict(members=True,
                                                listener=True,
                                                healthmonitor=True)
        return sp_dict


class LoadBalancerStatistics(model_base.BASEV2):
    """Represents load balancer statistics."""

    NAME = 'loadbalancer_stats'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_loadbalancer_statistics"

    loadbalancer_id = sa.Column(sa.String(36),
                                sa.ForeignKey("lbaas_loadbalancers.id"),
                                primary_key=True,
                                nullable=False)
    bytes_in = sa.Column(sa.BigInteger, nullable=False)
    bytes_out = sa.Column(sa.BigInteger, nullable=False)
    active_connections = sa.Column(sa.BigInteger, nullable=False)
    total_connections = sa.Column(sa.BigInteger, nullable=False)

    @validates('bytes_in', 'bytes_out',
               'active_connections', 'total_connections')
    def validate_non_negative_int(self, key, value):
        if value < 0:
            data = {'key': key, 'value': value}
            raise ValueError(_('The %(key)s field can not have '
                               'negative value. '
                               'Current value is %(value)d.') % data)
        return value

    def to_dict(self, loadbalancer=False):
        stats_dict = super(LoadBalancerStatistics, self).to_dict(
            exclude=['loadbalancer_id'])
        if loadbalancer and self.loadbalancer:
            stats_dict['loadbalancer'] = self.loadbalancer.to_dict(
                listeners=True)

        return stats_dict


class MemberV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer member."""

    NAME = 'member'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_members"

    __table_args__ = (
        sa.schema.UniqueConstraint('pool_id', 'address', 'protocol_port',
                                   name='uniq_pool_address_port_v2'),
    )
    pool_id = sa.Column(sa.String(36), sa.ForeignKey("lbaas_pools.id"),
                        nullable=False)
    address = sa.Column(sa.String(64), nullable=False)
    protocol_port = sa.Column(sa.Integer, nullable=False)
    weight = sa.Column(sa.Integer, nullable=True)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    subnet_id = sa.Column(sa.String(36), nullable=True)
    status = sa.Column(sa.String(16), nullable=False)

    def to_dict(self, pool=False):
        member_dict = super(MemberV2, self).to_dict(exclude=['pool_id'])
        if pool and self.pool:
            member_dict['pool'] = self.pool.to_dict(members=True,
                                                    listener=True,
                                                    healthmonitor=True,
                                                    sessionpersistence=True)
        return member_dict

    def attached_to_loadbalancer(self):
        return bool(self.pool and self.pool.listener and
                    self.pool.listener.loadbalancer)


class HealthMonitorV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer healthmonitor."""

    NAME = 'healthmonitor'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_healthmonitors"

    type = sa.Column(sa.Enum(*lb_const.SUPPORTED_HEALTH_MONITOR_TYPES,
                             name="healthmonitors_type"),
                     nullable=False)
    delay = sa.Column(sa.Integer, nullable=False)
    timeout = sa.Column(sa.Integer, nullable=False)
    max_retries = sa.Column(sa.Integer, nullable=False)
    http_method = sa.Column(sa.String(16), nullable=True)
    url_path = sa.Column(sa.String(255), nullable=True)
    expected_codes = sa.Column(sa.String(64), nullable=True)
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)

    def to_dict(self, pool=False):
        hm_dict = super(HealthMonitorV2, self).to_dict()
        if pool and self.pool:
            hm_dict['pool'] = self.pool.to_dict(listener=True,
                                                members=True,
                                                sessionpersistence=True)
        return hm_dict

    def attached_to_loadbalancer(self):
        return bool(self.pool and self.pool.listener and
                    self.pool.listener.loadbalancer)


class PoolV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer pool."""

    NAME = 'pool'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_pools"

    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)
    healthmonitor_id = sa.Column(sa.String(36),
                                 sa.ForeignKey("lbaas_healthmonitors.id"),
                                 unique=True,
                                 nullable=True)
    protocol = sa.Column(sa.Enum(*lb_const.SUPPORTED_PROTOCOLS,
                                 name="lb_protocols"),
                         nullable=False)
    lb_algorithm = sa.Column(sa.Enum(*lb_const.SUPPORTED_LB_ALGORITHMS,
                                     name="lb_algorithms"),
                             nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    members = orm.relationship(MemberV2,
                               backref=orm.backref("pool", uselist=False),
                               cascade="all, delete-orphan",
                               lazy='joined')
    healthmonitor = orm.relationship(
        HealthMonitorV2,
        backref=orm.backref("pool", uselist=False),
        lazy='joined')
    sessionpersistence = orm.relationship(
        SessionPersistenceV2,
        uselist=False,
        backref=orm.backref("pool", uselist=False),
        cascade="all, delete-orphan",
        lazy='joined')

    def to_dict(self, members=False, healthmonitor=False, listener=False,
                sessionpersistence=True):
        pool_dict = super(PoolV2, self).to_dict()
        if members:
            member_list = self.members or []
            pool_dict['members'] = [member.to_dict()
                                    for member in member_list]
        if healthmonitor and self.healthmonitor:
            pool_dict['healthmonitor'] = self.healthmonitor.to_dict()
        if listener and self.listener:
            pool_dict['listener'] = self.listener.to_dict(loadbalancer=True)
        if sessionpersistence and self.sessionpersistence:
            pool_dict['session_persistence'] = (
                self.sessionpersistence.to_dict())
        return pool_dict

    def attached_to_loadbalancer(self):
        return bool(self.listener and self.listener.loadbalancer)


class LoadBalancer(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer."""

    NAME = 'loadbalancer'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_loadbalancers"

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    vip_subnet_id = sa.Column(sa.String(36), nullable=False)
    vip_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    vip_address = sa.Column(sa.String(36))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vip_port = orm.relationship(models_v2.Port)
    stats = orm.relationship(
        LoadBalancerStatistics,
        uselist=False,
        backref=orm.backref("loadbalancer", uselist=False),
        cascade="all, delete-orphan",
        lazy='joined')
    provider = orm.relationship(
        st_db.ProviderResourceAssociation,
        uselist=False,
        lazy="joined",
        primaryjoin="LoadBalancer.id==ProviderResourceAssociation.resource_id",
        foreign_keys=[st_db.ProviderResourceAssociation.resource_id],
        #this is only for old API backwards compatibility because when a load
        #balancer is deleted the pool ID should be the same as the load
        #balancer ID and should not be cleared out in this table
        viewonly=True
    )

    def to_dict(self, listeners=False, stats=False):
        lb_dict = super(LoadBalancer, self).to_dict()
        if listeners and self.listeners:
            lb_dict['listeners'] = [listener.to_dict(default_pool=True)
                                    for listener in self.listeners]
        if stats and self.stats:
            lb_dict['stats'] = self.stats.to_dict()
        return lb_dict


class Listener(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron listener."""

    NAME = 'listener'

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_listeners"

    __table_args__ = (
        sa.schema.UniqueConstraint('loadbalancer_id', 'protocol_port',
                                   name='uniq_loadbalancer_listener_port'),
    )

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    default_pool_id = sa.Column(sa.String(36), sa.ForeignKey("lbaas_pools.id"),
                                unique=True)
    loadbalancer_id = sa.Column(sa.String(36), sa.ForeignKey(
        "lbaas_loadbalancers.id"))
    protocol = sa.Column(sa.Enum(*lb_const.SUPPORTED_PROTOCOLS,
                                 name="lb_protocols"),
                         nullable=False)
    protocol_port = sa.Column(sa.Integer, nullable=False)
    connection_limit = sa.Column(sa.Integer)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    default_pool = orm.relationship(
        PoolV2, backref=orm.backref("listener", uselist=False), lazy='joined')
    loadbalancer = orm.relationship(
        LoadBalancer, backref=orm.backref("listeners"), lazy='joined')

    def to_dict(self, loadbalancer=False, default_pool=False):
        listener_dict = super(Listener, self).to_dict()
        if loadbalancer and self.loadbalancer:
            listener_dict['loadbalancer'] = self.loadbalancer.to_dict(
                listeners=True, stats=True)
        if default_pool and self.default_pool:
            listener_dict['default_pool'] = self.default_pool.to_dict(
                members=True, healthmonitor=True, sessionpersistence=True)
        return listener_dict

    def attached_to_loadbalancer(self):
        return bool(self.loadbalancer)


class LoadBalancerPluginDbv2(loadbalancerv2.LoadBalancerPluginBaseV2,
                             base_db.CommonDbMixin):
    """Wraps loadbalancer with SQLAlchemy models.

    A class that wraps the implementation of the Neutron loadbalancer
    plugin database access interface using SQLAlchemy models.
    """

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_resource(self, context, model, id, for_update=False):
        resource = None
        try:
            if for_update:
                query = self._model_query(context, model).filter(
                    model.id == id).with_lockmode('update')
                resource = query.one()
            else:
                resource = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, (LoadBalancer, Listener, PoolV2, MemberV2,
                                      HealthMonitorV2, LoadBalancerStatistics,
                                      SessionPersistenceV2)):
                    raise loadbalancerv2.EntityNotFound(name=model.NAME, id=id)
                ctx.reraise = True
        return resource

    def _resource_exists(self, context, model, id):
        try:
            self._get_by_id(context, model, id)
        except exc.NoResultFound:
            return False
        return True

    def _get_resources(self, context, model, filters=None):
        query = self._get_collection_query(context, model,
                                           filters=filters)
        return [model_instance for model_instance in query]

    def _create_port_for_load_balancer(self, context, lb_db, ip_address):
        # resolve subnet and create port
        subnet = self._core_plugin.get_subnet(context, lb_db.vip_subnet_id)
        fixed_ip = {'subnet_id': subnet['id']}
        if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
            fixed_ip['ip_address'] = ip_address

        port_data = {
            'tenant_id': lb_db.tenant_id,
            'name': 'loadbalancer-' + lb_db.id,
            'network_id': subnet['network_id'],
            'mac_address': attributes.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': '',
            'device_owner': '',
            'fixed_ips': [fixed_ip]
        }

        port = self._core_plugin.create_port(context, {'port': port_data})
        lb_db.vip_port_id = port['id']
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['subnet_id'] == lb_db.vip_subnet_id:
                lb_db.vip_address = fixed_ip['ip_address']
                break

        # explicitly sync session with db
        context.session.flush()

    def _create_loadbalancer_stats(self, context, loadbalancer_id, data=None):
        # This is internal method to add load balancer statistics.  It won't
        # be exposed to API
        data = data or {}
        stats_db = LoadBalancerStatistics(
            loadbalancer_id=loadbalancer_id,
            bytes_in=data.get(lb_const.STATS_IN_BYTES, 0),
            bytes_out=data.get(lb_const.STATS_OUT_BYTES, 0),
            active_connections=data.get(lb_const.STATS_ACTIVE_CONNECTIONS, 0),
            total_connections=data.get(lb_const.STATS_TOTAL_CONNECTIONS, 0)
        )
        return stats_db

    def _delete_loadbalancer_stats(self, context, loadbalancer_id):
        # This is internal method to delete pool statistics. It won't
        # be exposed to API
        with context.session.begin(subtransactions=True):
            stats_qry = context.session.query(LoadBalancerStatistics)
            try:
                stats = stats_qry.filter_by(
                    loadbalancer_id=loadbalancer_id).one()
            except exc.NoResultFound:
                raise loadbalancerv2.EntityNotFound(
                    name=LoadBalancerStatistics.NAME, id=loadbalancer_id)
            context.session.delete(stats)

    def _load_id_and_tenant_id(self, context, model_dict):
        model_dict['id'] = uuidutils.generate_uuid()
        model_dict['tenant_id'] = self._get_tenant_id_for_create(
            context, model_dict)

    def assert_modification_allowed(self, obj):
        status = getattr(obj, 'status', None)
        if status in [constants.PENDING_DELETE, constants.PENDING_UPDATE,
                      constants.PENDING_CREATE]:
            id = getattr(obj, 'id', None)
            raise loadbalancerv2.StateInvalid(id=id, state=status)

    def test_and_set_status(self, context, model, id, status):
        with context.session.begin(subtransactions=True):
            model_db = self._get_resource(context, model, id, for_update=True)
            self.assert_modification_allowed(model_db)
            if model_db.status != status:
                model_db.status = status

    def update_status(self, context, model, id, status):
        with context.session.begin(subtransactions=True):
            if issubclass(model, LoadBalancer):
                try:
                    model_db = (self._model_query(context, model).
                                filter(model.id == id).
                                options(orm.noload('vip_port')).
                                one())
                except exc.NoResultFound:
                    raise loadbalancerv2.EntityNotFound(
                        name=LoadBalancer.NAME, id=id)
            else:
                model_db = self._get_resource(context, model, id)
            if model_db.status != status:
                model_db.status = status

    def create_loadbalancer(self, context, loadbalancer):
        with context.session.begin(subtransactions=True):
            self._load_id_and_tenant_id(context, loadbalancer)
            vip_address = loadbalancer.pop('vip_address')
            loadbalancer['status'] = constants.PENDING_CREATE
            lb_db = LoadBalancer(**loadbalancer)
            context.session.add(lb_db)
            context.session.flush()
            lb_db.stats = self._create_loadbalancer_stats(
                context, lb_db.id)
            context.session.add(lb_db)

        # create port outside of lb create transaction since it can sometimes
        # cause lock wait timeouts
        try:
            self._create_port_for_load_balancer(context, lb_db, vip_address)
        except Exception:
            with excutils.save_and_reraise_exception():
                context.session.delete(lb_db)
                context.session.flush()
        return lb_db

    def update_loadbalancer(self, context, id, loadbalancer):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, LoadBalancer, id)
            lb_db.update(loadbalancer)
        return lb_db

    def delete_loadbalancer(self, context, id):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, LoadBalancer, id)
            context.session.delete(lb_db)
        if lb_db.vip_port:
            self._core_plugin.delete_port(context, lb_db.vip_port_id)

    def get_loadbalancers(self, context, filters=None):
        return self._get_resources(context, LoadBalancer, filters=filters)

    def get_loadbalancer(self, context, id):
        return self._get_resource(context, LoadBalancer, id)

    def create_listener(self, context, listener):
        try:
            with context.session.begin(subtransactions=True):
                self._load_id_and_tenant_id(context, listener)
                listener['status'] = constants.PENDING_CREATE
                #Check for unspecified loadbalancer_id and listener_id and
                #set to None
                for id in ['loadbalancer_id', 'default_pool_id']:
                    if listener.get(id) == attributes.ATTR_NOT_SPECIFIED:
                        listener[id] = None
                pool_id = listener.get('default_pool_id')
                lb_id = listener.get('loadbalancer_id')
                if lb_id:
                    if not self._resource_exists(context, LoadBalancer, lb_id):
                        raise loadbalancerv2.EntityNotFound(
                            name=LoadBalancer.NAME, id=lb_id)
                if pool_id:
                    if not self._resource_exists(context, PoolV2, pool_id):
                        raise loadbalancerv2.EntityNotFound(
                            name=PoolV2.NAME, id=pool_id)
                    pool = self._get_resource(context, PoolV2, pool_id)
                    if pool.protocol != listener.get('protocol'):
                        raise loadbalancerv2.ListenerPoolProtocolMismatch(
                            listener_proto=listener['protocol'],
                            pool_proto=pool.protocol)
                    filters = {'default_pool_id': [pool_id]}
                    listenerpools = self._get_resources(context,
                                                        Listener,
                                                        filters=filters)
                    if listenerpools:
                        raise loadbalancerv2.PoolInUse(pool_id=pool_id)

                listener_db_entry = Listener(**listener)
                context.session.add(listener_db_entry)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.LoadBalancerListenerProtocolPortExists(
                lb_id=listener['loadbalancer_id'],
                protocol_port=listener['protocol_port'])
        return listener_db_entry

    def update_listener(self, context, id, listener):
        with context.session.begin(subtransactions=True):
            listener_db = self._get_resource(context, Listener, id)

            pool_id = listener.get('default_pool_id')
            lb_id = listener.get('loadbalancer_id')

            # Do not allow changing loadbalancer ids
            if listener_db.loadbalancer_id and lb_id:
                raise loadbalancerv2.AttributeIDImmutable(
                    attribute='loadbalancer_id')
            # Do not allow changing pool ids
            if listener_db.default_pool_id and pool_id:
                raise loadbalancerv2.AttributeIDImmutable(
                    attribute='default_pool_id')
            if lb_id:
                if not self._resource_exists(context, LoadBalancer, lb_id):
                    raise loadbalancerv2.EntityNotFound(name=LoadBalancer.NAME,
                                                        id=lb_id)
            if pool_id:
                if not self._resource_exists(context, PoolV2, pool_id):
                    raise loadbalancerv2.EntityNotFound(name=PoolV2.NAME,
                                                        id=pool_id)
                pool = self._get_resource(context, PoolV2, pool_id)
                protocol = listener.get('protocol') or listener_db.protocol
                if pool.protocol != protocol:
                    raise loadbalancerv2.ListenerPoolProtocolMismatch(
                        listener_proto=protocol,
                        pool_proto=pool.protocol)
                filters = {'default_pool_id': [pool_id]}
                listenerpools = self._get_resources(context,
                                                    Listener,
                                                    filters=filters)
                if listenerpools:
                    raise loadbalancerv2.PoolInUse(pool_id=pool_id)

            listener_db.update(listener)
        context.session.refresh(listener_db)
        return listener_db

    def delete_listener(self, context, id):
        listener_db_entry = self._get_resource(context, Listener, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(listener_db_entry)

    def get_listeners(self, context, filters=None):
        return self._get_resources(context, Listener, filters=filters)

    def get_listener(self, context, id):
        return self._get_resource(context, Listener, id)

    def _check_session_persistence_info(self, info):
        """Performs sanity check on session persistence info.

        :param info: Session persistence info
        """
        if info['type'] == lb_const.SESSION_PERSISTENCE_APP_COOKIE:
            if not info.get('cookie_name'):
                raise ValueError(_("'cookie_name' should be specified for this"
                                   " type of session persistence."))
        else:
            if 'cookie_name' in info:
                raise ValueError(_("'cookie_name' is not allowed for this type"
                                   " of session persistence"))

    def _create_session_persistence_db(self, session_info, pool_id):
        self._check_session_persistence_info(session_info)
        session_info['pool_id'] = pool_id
        sp_db = SessionPersistenceV2(**session_info)
        return sp_db

    def _update_pool_session_persistence(self, context, pool_id, info):
        self._check_session_persistence_info(info)
        pool = self._get_resource(context, PoolV2, pool_id)
        with context.session.begin(subtransactions=True):
            # Update sessionPersistence table
            sess_qry = context.session.query(SessionPersistenceV2)
            sesspersist_db = sess_qry.filter_by(pool_id=pool_id).first()

            # Insert a None cookie_info if it is not present to overwrite an
            # an existing value in the database.
            if 'cookie_name' not in info:
                info['cookie_name'] = None

            if sesspersist_db:
                sesspersist_db.update(info)
            else:
                info['pool_id'] = pool_id
                sesspersist_db = SessionPersistenceV2(**info)
                context.session.add(sesspersist_db)
                # Update pool table
                pool.session_persistence = sesspersist_db
            context.session.add(pool)

    def _delete_session_persistence(self, context, pool_id):
        with context.session.begin(subtransactions=True):
            sess_qry = context.session.query(SessionPersistenceV2)
            sess_qry.filter_by(pool_id=pool_id).delete()

    def create_pool(self, context, pool):
        with context.session.begin(subtransactions=True):
            self._load_id_and_tenant_id(context, pool)
            pool['status'] = constants.PENDING_CREATE
            if pool['healthmonitor_id'] == attributes.ATTR_NOT_SPECIFIED:
                pool['healthmonitor_id'] = None
            hm_id = pool['healthmonitor_id']
            if hm_id:
                if not self._resource_exists(context, HealthMonitorV2, hm_id):
                    raise loadbalancerv2.EntityNotFound(
                        name=HealthMonitorV2.NAME, id=hm_id)

                filters = {'healthmonitor_id': [hm_id]}
                hmpools = self._get_resources(context,
                                              PoolV2,
                                              filters=filters)
                if hmpools:
                    raise loadbalancerv2.HealthMonitorInUse(monitor_id=hm_id)

            session_info = pool.pop('session_persistence')
            pool_db = PoolV2(**pool)

            if session_info:
                s_p = self._create_session_persistence_db(session_info,
                                                          pool_db.id)
                pool_db.sessionpersistence = s_p

            context.session.add(pool_db)
        return pool_db

    def update_pool(self, context, id, pool):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, PoolV2, id)
            hm_id = pool.get('healthmonitor_id')
            if hm_id:
                if pool_db.healthmonitor and hm_id:
                    raise loadbalancerv2.AttributeIDImmutable(
                        attribute='healthmonitor_id')
                if not self._resource_exists(context, HealthMonitorV2, hm_id):
                    raise loadbalancerv2.EntityNotFound(
                        name=HealthMonitorV2.NAME,
                        id=hm_id)
                filters = {'healthmonitor_id': [hm_id]}
                hmpools = self._get_resources(context,
                                              PoolV2,
                                              filters=filters)
                if hmpools:
                    raise loadbalancerv2.HealthMonitorInUse(monitor_id=hm_id)

            sp = pool.pop('session_persistence', None)
            if sp:
                self._update_pool_session_persistence(context, id, sp)
            else:
                self._delete_session_persistence(context, id)

            pool_db.update(pool)
        context.session.refresh(pool_db)
        return pool_db

    def delete_pool(self, context, id):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, PoolV2, id)
            context.session.delete(pool_db)

    def get_pools(self, context, filters=None):
        return self._get_resources(context, PoolV2, filters=filters)

    def get_pool(self, context, id):
        return self._get_resource(context, PoolV2, id)

    def create_pool_member(self, context, member, pool_id):
        try:
            with context.session.begin(subtransactions=True):
                if not self._resource_exists(context, PoolV2, pool_id):
                    raise loadbalancerv2.EntityNotFound(name=PoolV2.NAME,
                                                        id=pool_id)
                self._load_id_and_tenant_id(context, member)
                member['pool_id'] = pool_id
                member['status'] = constants.PENDING_CREATE
                member_db = MemberV2(**member)
                context.session.add(member_db)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.MemberExists(address=member['address'],
                                              port=member['protocol_port'],
                                              pool=pool_id)
        return member_db

    def update_pool_member(self, context, id, member, pool_id):
        with context.session.begin(subtransactions=True):
            if not self._resource_exists(context, PoolV2, pool_id):
                raise loadbalancerv2.MemberNotFoundForPool(pool_id=pool_id,
                                                           member_id=id)
            member_db = self._get_resource(context, MemberV2, id)
            member_db.update(member)
        context.session.refresh(member_db)
        return member_db

    def delete_pool_member(self, context, id, pool_id):
        with context.session.begin(subtransactions=True):
            if not self._resource_exists(context, PoolV2, pool_id):
                raise loadbalancerv2.MemberNotFoundForPool(pool_id=pool_id,
                                                           member_id=id)
            member_db = self._get_resource(context, MemberV2, id)
            context.session.delete(member_db)

    def get_pool_members(self, context, pool_id, filters=None):
        if filters:
            filters.update(filters)
        else:
            filters = {'pool_id': [pool_id]}
        return self._get_resources(context, MemberV2, filters=filters)

    def get_pool_member(self, context, id, pool_id, filters=None):
        member = self._get_resource(context, MemberV2, id)
        if member.pool_id != pool_id:
            raise loadbalancerv2.MemberNotFoundForPool(member_id=id,
                                                       pool_id=pool_id)
        return member

    def delete_member(self, context, id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, MemberV2, id)
            context.session.delete(member_db)

    def create_healthmonitor(self, context, healthmonitor):
        with context.session.begin(subtransactions=True):
            self._load_id_and_tenant_id(context, healthmonitor)
            healthmonitor['status'] = constants.PENDING_CREATE
            hm_db_entry = HealthMonitorV2(**healthmonitor)
            context.session.add(hm_db_entry)
        return hm_db_entry

    def update_healthmonitor(self, context, id, healthmonitor):
        with context.session.begin(subtransactions=True):
            hm_db = self._get_resource(context, HealthMonitorV2, id)
            hm_db.update(healthmonitor)
        context.session.refresh(hm_db)
        return hm_db

    def delete_healthmonitor(self, context, id):
        with context.session.begin(subtransactions=True):
            hm_db_entry = self._get_resource(context, HealthMonitorV2, id)
            context.session.delete(hm_db_entry)

    def get_healthmonitor(self, context, id):
        return self._get_resource(context, HealthMonitorV2, id)

    def get_healthmonitors(self, context, filters=None):
        return self._get_resources(context, HealthMonitorV2, filters=filters)

    def update_loadbalancer_stats(self, context, loadbalancer_id, stats_data):
        stats_data = stats_data or {}
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, LoadBalancer, loadbalancer_id)
            self.assert_modification_allowed(lb_db)
            lb_db.stats = self._create_loadbalancer_stats(context,
                                                          loadbalancer_id,
                                                          data=stats_data)

    def stats(self, context, loadbalancer_id):
        with context.session.begin(subtransactions=True):
            loadbalancer = self._get_resource(context, LoadBalancer,
                                              loadbalancer_id)
        return loadbalancer.stats
