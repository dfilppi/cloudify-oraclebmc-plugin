########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

import sys

# Third-party Imports
import oraclebmc

# Cloudify imports
from cloudify import ctx
from cloudify.exceptions import NonRecoverableError
from cloudify.decorators import operation


@operation
def create_vcn(**kwargs):

    ctx.logger.info("Creating VCN")
    vcn_details = oraclebmc.core.models.CreateVcnDetails()
    vcn_details.cidr_block = ctx.node.properties['cidr_block']
    vcn_details.compartment_id = ctx.node.properties['compartment_id']
    vcn_details.display_name = ctx.node.properties['name']
    response = None

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                  ctx.node.properties['bmc_config']))

    try:
        response = vcn_client.create_vcn(vcn_details)
    except:
        ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
        raise NonRecoverableError("VCN create failed: {}".
                                  format(sys.exc_info()[0]))

    vcn = response.data
    ctx.logger.info("Created VCN {} {}".format(ctx.node.properties['name'],
                                               vcn.id))
    ctx.instance.runtime_properties['id'] = vcn.id


@operation
def delete_vcn(**kwargs):

    ctx.logger.info("Deleting VCN")

    try:
        vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
        vcn_client.delete_vcn(
            ctx.instance.runtime_properties['id'])
    except:
        ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
        raise NonRecoverableError("VCN create failed: {}".
                                  format(sys.exc_info()[0]))


@operation
def wait_for_vcn_terminated(**kwargs):

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
               ctx.node.properties['bmc_config']))

    # instance doesn't have a terminated state.  just vanishes
    # and api throws exception
    try:
        instance = vcn_client.get_vcn(ctx.instance.runtime_properties['id'])
        return ctx.operation.retry(
            message="Waiting for instance to terminate ({}). \
            Retrying...".format(instance.data.lifecycle_state),
            retry_after=kwargs['terminate_retry_interval'])

    except:
        pass

#@with_vcn_client


@operation
def create_subnet(**kwargs):
    ctx.logger.info("Creating subnet")

    details = oraclebmc.core.models.CreateSubnetDetails()
    details.cidr_block = ctx.node.properties['cidr_block']
    details.availability_domain = ctx.node.properties['availability_domain']
    details.compartment_id = ctx.node.properties['compartment_id']
    details.display_name = ctx.node.properties['name']
    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
    vcn = vcn_client.get_vcn(
        ctx.instance.runtime_properties['vcn_id']).data
    details.route_table_id = vcn.default_route_table_id
    details.vcn_id = ctx.instance.runtime_properties['vcn_id']
    response = vcn_client.create_subnet(details)

    ctx.instance.runtime_properties["id"] = response.data.id
    ctx.logger.info("Created subnet {}".format(details.display_name))


@operation
def delete_subnet(**kwargs):
    ctx.logger.info("Deleting subnet")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
    vcn_client.delete_subnet(ctx.instance.runtime_properties['id'])


@operation
def wait_for_subnet_terminated(**kwargs):
    vcn_client = (oraclebmc.core.VirtualNetworkClient(
               ctx.node.properties['bmc_config']))

    # instance doesn't have a terminated state.  just vanishes
    # and api throws exception
    try:
        instance = vcn_client.get_subnet(ctx.instance.runtime_properties['id'])
        return ctx.operation.retry(
            message="Waiting for instance to terminate ({}). \
            Retrying...".format(instance.data.lifecycle_state),
            retry_after=kwargs['terminate_retry_interval'])
    except:
        pass


def addto_route_table(vcn_client, vcn_id, cidrs, gateway_id):
    rules = []
    for cidr in cidrs:
        route_rule = oraclebmc.core.models.RouteRule()
        route_rule.network_entity_id = gateway_id
        route_rule.cidr_block = cidr
        rules.append(route_rule)
    details = oraclebmc.core.models.UpdateRouteTableDetails()
    details.route_rules = rules
    vcn = vcn_client.get_vcn(vcn_id)
    resp = vcn_client.update_route_table(
        vcn.data.default_route_table_id, details)
    ctx.instance.runtime_properties['route_table_id'] = resp.data.id


def delfrom_route_table(vcn_client, vcn_id, cidrs, gateway_id):

    vcn = vcn_client.get_vcn(vcn_id)
    resp = vcn_client.get_route_table(vcn.data.default_route_table_id)
    new_rules = []
    rules = resp.data.route_rules
    for rule in rules:
        if rule.cidr_block not in cidrs:
            new_rules.append(rule)
        else:
            ctx.logger.debug("removing route rule: {}".
                             format(rule.cidr_block))
    details = oraclebmc.core.models.UpdateRouteTableDetails()
    details.route_rules = new_rules
    vcn_client.update_route_table(
        vcn.data.default_route_table_id, details)


@operation
def create_gateway(**kwargs):
    ctx.logger.info("Creating internet gateway")

    details = oraclebmc.core.models.CreateInternetGatewayDetails()
    details.compartment_id = ctx.node.properties['compartment_id']
    details.display_name = ctx.node.properties['name']
    details.is_enabled = ctx.node.properties['enabled']
    details.vcn_id = ctx.instance.runtime_properties['vcn_id']
    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
    response = vcn_client.create_internet_gateway(details)

    ctx.instance.runtime_properties["id"] = response.data.id
    ctx.logger.info("Created internet gateway {}".format(details.display_name))

    ctx.logger.info("Updating route table")
    if len(ctx.node.properties['route_cidrs']) > 0:
        addto_route_table(vcn_client, details.vcn_id,
                          ctx.node.properties['route_cidrs'],
                          response.data.id)


@operation
def delete_gateway(**kwargs):
    ctx.logger.info("Deleting gateway")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
    if len(ctx.node.properties['route_cidrs']) > 0:
        delfrom_route_table(vcn_client,
                            ctx.instance.runtime_properties['vcn_id'],
                            ctx.node.properties['route_cidrs'],
                            ctx.instance.runtime_properties['id'])
    vcn_client.delete_internet_gateway(ctx.instance.runtime_properties['id'])


@operation
def connect_subnet_to_network(**kwargs):
    ctx.source.instance.runtime_properties['vcn_id'] = \
        ctx.target.instance.runtime_properties['id']


@operation
def connect_gateway_to_network(**kwargs):
    ctx.source.instance.runtime_properties['vcn_id'] = \
        ctx.target.instance.runtime_properties['id']


@operation
def connect_instance_to_subnet(**kwargs):
    ctx.source.instance.runtime_properties[(
        'subnet_'+ctx.target.instance.id)] = \
        ctx.target.instance.runtime_properties['id']
