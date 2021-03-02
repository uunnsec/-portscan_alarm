#!/usr/bin/python3
# coding=utf-8
import requests
import json
import redis
import os
import datetime
import smtplib
import re
import warnings
from email.mime.text import MIMEText
from email.header import Header
from config import dict, redis_host, port, db, mail_host, mail_pass, mail_user, sender, receivers

r = redis.StrictRedis(host=redis_host, port=port, db=db)
warnings.filterwarnings("ignore")

def get_portscans_list():
    mark1 = 0
    mark2 = 0
    data = datetime.date.today()
    filename = str(data) + '.txt'

    for k, v in dict.items():
        url = 'https://139.198.5.19:443/scans/%s/plugins/11219' % v
        accesskey = '0cc5f98277fbb1ed1a531b2583b59a71a919916ac28f2623665219685be77719'
        secretkey = '175651c3a34a8eb835e2cbb8246bcc54e9f8a6c5e331ddc20725841b9950ecc3'
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
                    mark1 += 1
                    r.set(k, val)

                    # 将本次端口对比结果保存到txt文件中
                    content = ('vpc: %s\nLast      Scan: %s\nCurrent Scan: %s' % (k, oldVal, val))
                    print(content)
                    f = open(filename, 'a')
                    f.writelines('\n' + content + '\n')
                    f.close()

                    # print(k, 'oldscan', oldVal, 'currentscan', val)

                else:
                    print(k, 'port eq and oldscan = currentscan')
            else:
                # 日常端口监控，对比上一次扫描结果
                oldVal = r.get(k)
                oldVal = str(oldVal, encoding='utf-8')
                if "" != oldVal:
                    mark2 += 1
                    r.set(k, "")
                    # 将本次端口对比结果保存到txt文件中
                    content = ('vpc: %s\nLast      Scan: %s\nCurrent Scan: %s' % (k, oldVal, val))
                    print(content)
                    f = open(filename, 'a')
                    f.writelines('\n' + content + '\n')
                    f.close()

                    # print(k, 'oldscan', oldVal, 'currentscan', '')

                else:
                    print(k, 'port eq and oldscan = currentscan and none')
        else:
            print('not vpc')

    if os.path.isfile(filename) == True:
        # 读取txt文件内容
        with open(filename) as f:
            content = f.read()
            # 发送告警邮件
            message = MIMEText(content, 'plain','utf-8')
            message['From'] = Header(sender, 'utf-8')
            message['To'] = Header(receivers, 'utf-8')
            subject = '【端口监测】'
            message['Subject'] = Header(subject, 'utf-8')
            smtpObj = smtplib.SMTP()
            smtpObj.connect(mail_host, 25)
            smtpObj.login(mail_user, mail_pass)
            smtpObj.sendmail(sender, receivers, message.as_string())
    else:
        message = MIMEText('本次扫描各vpc已开启端口无变化', 'plain', 'utf-8')
        message['From'] = Header(sender, 'utf-8')
        message['To'] = Header(receivers, 'utf-8')
        subject = '【端口监测】'
        message['Subject'] = Header(subject, 'utf-8')
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, 25)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())

portscan = get_portscans_list()
