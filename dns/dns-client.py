
#
# Command line usage:
# $ python3 dns-client.py --help
#

import json
import os
import sys
import click

# import from the 21 Developer Library
from two1.commands.config import Config
from two1.lib.wallet import Wallet
from two1.lib.bitrequests import BitTransferRequests

# set up bitrequest client for BitTransfer requests
wallet = Wallet()
username = Config().username
requests = BitTransferRequests(wallet, username)

DNSCLI_VERSION = '0.1'
DEFAULT_ENDPOINT = 'http://localhost:12005/'

@click.group()
@click.option('--endpoint', '-e',
              default=DEFAULT_ENDPOINT,
              metavar='STRING',
              show_default=True,
              help='API endpoint URI')
@click.option('--debug', '-d',
              is_flag=True,
              help='Turns on debugging messages.')
@click.version_option(DNSCLI_VERSION)
@click.pass_context
def main(ctx, endpoint, debug):
    """ Command-line Interface for the DDNS API service
    """

    if ctx.obj is None:
        ctx.obj = {}

    ctx.obj['endpoint'] = endpoint

@click.command(name='info')
@click.pass_context
def cmd_info(ctx):
    sel_url = ctx.obj['endpoint']
    answer = requests.get(url=sel_url.format())
    print(answer.text)

@click.command(name='domains')
@click.pass_context
def cmd_domains(ctx):
    sel_url = ctx.obj['endpoint'] + 'domains'
    answer = requests.get(url=sel_url.format())
    print(answer.text)

@click.command(name='register')
@click.argument('name')
@click.argument('days')
@click.argument('pkh_and_records', nargs=-1)
@click.pass_context
def cmd_register(ctx, name, days, pkh_and_records):
    addr = None
    records = []
    for arg in pkh_and_records:
        if addr is None:
            addr = arg
        else:
            words = arg.split(',')
            host_obj = {
                'ttl': int(words[0]),
                'rec_type': words[1],
                'address': words[2],
            }
            records.append(host_obj)

    req_obj = {
        'name': name,
        'days': int(days),
        'hosts': records,
    }
    if addr:
        req_obj['pkh'] = addr
    sel_url = ctx.obj['endpoint'] + 'host.register'
    body = json.dumps(req_obj)
    headers = {'Content-Type': 'application/json'}
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)

@click.command(name='update')
@click.argument('name')
@click.argument('records', nargs=-1)
@click.pass_context
def cmd_update(ctx, name, records):
    req_obj = {
        'name': name,
        'hosts': [],
    }
    for record in records:
        words = record.split(',')
        host_obj = {
            'ttl': int(words[0]),
            'rec_type': words[1],
            'address': words[2],
        }
        req_obj['hosts'].append(host_obj)

    sel_url = ctx.obj['endpoint'] + 'host.update'
    body = json.dumps(req_obj)
    headers = {'Content-Type': 'application/json'}
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)

main.add_command(cmd_info)
main.add_command(cmd_domains)
main.add_command(cmd_register)
main.add_command(cmd_update)

if __name__ == "__main__":
    main()

