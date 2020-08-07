# portscan_alarm_public
公网nessus扫描公司ip地址，匹配前后两次端口不同进行告警

#### 服务器定时任务进行监控
- 使用定时任务每周执行两次，并将其执行结果记录日志文件
```
0 9 * * 3,5 python3 /opt/portscan_alarm/portscan.py > /opt/portscan_alarm/portscan.log
```
