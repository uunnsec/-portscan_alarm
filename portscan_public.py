#!/usr/bin/python3
# coding=utf-8
import requests
import json
import redis
import smtplib
import re
import warnings
from email.mime.text import MIMEText
from email.header import Header
from config import dict, redis_host, port, db, mail_host, mail_pass, mail_user, sender, receivers

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
                # 日常端口监控，对比上一次扫描结果
                oldVal = r.get(k)
                oldVal = str(oldVal, encoding='utf-8')
                if val != oldVal:
                    r.set(k, val)

                    print(k, 'oldscan', oldVal, 'currentscan', val)

                    message = MIMEText('vpc: %s\nLast      Scan: %s\nCurrent Scan: %s' % (k, oldVal, val), 'plain', 'utf-8')
                    message['From'] = Header(sender, 'utf-8')
                    message['To'] = Header(receivers, 'utf-8')
                    subject = '【端口监测】'
                    message['Subject'] = Header(subject, 'utf-8')
                    smtpObj = smtplib.SMTP()
                    smtpObj.connect(mail_host, 25)
                    smtpObj.login(mail_user, mail_pass)
                    smtpObj.sendmail(sender, receivers, message.as_string())
                else:
                    print(k, 'port eq and oldscan = currentscan')
            else:
                # 日常端口监控，对比上一次扫描结果
                oldVal = r.get(k)
                oldVal = str(oldVal, encoding='utf-8')
                if "" != oldVal:
                    r.set(k, "")

                    print(k, 'oldscan', oldVal, 'currentscan', '')

                    message = MIMEText('vpc: %s\nLast      Scan: %s\nCurrent Scan: %s' % (k, oldVal, ''), 'plain','utf-8')
                    message['From'] = Header(sender, 'utf-8')
                    message['To'] = Header(receivers, 'utf-8')
                    subject = '【端口监测】'
                    message['Subject'] = Header(subject, 'utf-8')
                    smtpObj = smtplib.SMTP()
                    smtpObj.connect(mail_host, 25)
                    smtpObj.login(mail_user, mail_pass)
                    smtpObj.sendmail(sender, receivers, message.as_string())
                else:
                    print(k, 'port eq and oldscan = currentscan and none')
        else:
            print('not vpc')

portscan = get_portscans_list()