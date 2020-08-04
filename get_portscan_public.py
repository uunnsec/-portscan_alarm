#!/usr/bin/python3
# coding=utf-8
import requests
import json
import redis
import re
import warnings
from config import dict, redis_host, port, db
r = redis.StrictRedis(host=redis_host, port=port, db=db)
warnings.filterwarnings("ignore")

def get_portscans_list():
    for k, v in dict.items():
        url = 'https://0.0.0.0:443/scans/%s/plugins/11219' % v
        accesskey = '*************************************'
        secretkey = '*************************************'
        headers = {
            'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=accesskey, secretkey=secretkey),
            'Content-type': 'application/json',
            'Accept': 'text/plain',
        }
        resp = requests.get(url, headers=headers, verify=False)

        if resp.status_code == 200:
            portList = []
            i = 0
            result = json.loads(resp.text)['outputs']

            if result is not None:
                while i < len(result):
                    plugin_output = result[i]['plugin_output']
                    plugin_output = re.sub('\D', '', plugin_output)
                    portList.append(plugin_output)
                    i += 1
                val = ",".join(portList)
                print(val)
                # 第一次执行
                r.set(k, val)
            else:
                # 第一次执行
                r.set(k, '')
        else:
            print('not vpc')

portscan = get_portscans_list()