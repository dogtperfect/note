## 1、Prometheus

#### 二进制安装

wget https://github.com/prometheus/prometheus/releases/download/v3.3.0/prometheus-3.3.0.linux-amd64.tar.gz

tar -zxvf prometheus-3.3.0.linux-amd64.tar.gz

mv prometheus-3.3.0.linux-amd64 /opt/monitor/prometheus



添加访问时账号认证

```
yum install -y httpd-tools
htpasswd -nBC 12 '' | tr -d ':\n'

输入的密码
ULT9BS159BUAQKijqq
生成的密码
$2y$12$l6YvjuaCpmu8ggX3.9PCrO1rsG7JGu.KlslwljUAPRGaVbDSwYnze
```

生成证书

```
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout node_exporter.key -out node_exporter.crt -subj "/C=CN/ST=Beijing/L=Beijing/O=lyvc.edu.cn/CN=localhost"
```



```
cat > /opt/monitor/prometheus/prometheus.yaml << EOF

global:
    scrape_interval: 1m
    scrape_timeout: 1m
    evaluation_interval: 1m
    
alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - localhost:9093

rule_files:
  - "rules.yml"
  
scrape_configs:
  - job_name: 'prometheus'
	basic_auth:
	  username: admin
	  password: ULT9BS159BUAQKijqq
	static_configs:
	- targets: ['prometheus:9090']
	
  - job_name: 'node_exporter'
    scheme: https
    tls_config:
      ca_file: node_exporter.crt
      insecure_skip_verify: true
    basic_auth:
      username: admin
      password: ULT9BS159BUAQKijqq
    static_configs:
    - targets: ['10.128.4.214:9100']
   
EOF
```



```
vi /usr/lib/systemd/system/prometheus.service

[Unit]
Description=prometheus
[Service]
ExecStart=/opt/monitor/prometheus/prometheus --config.file=/opt/monitor/prometheus/prometheus.yaml --web.config.file=/opt/monitor/prometheus/config.yml --storage.tsdb.retention.time=365d
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
[Install]
WantedBy=multi-user.target

systemctl daemon-reload
systemctl start prometheus
systemctl enable prometheus
```



```
# 检查配置文件是否正确
./promtool check config prometheus.yaml
```



#### k8s 安装 prometheus

下载镜像

```
docker pull swr.cn-north-4.myhuaweicloud.com/ddn-k8s/quay.io/prometheus/prometheus:v3.2.1
docker tag  swr.cn-north-4.myhuaweicloud.com/ddn-k8s/quay.io/prometheus/prometheus:v3.2.1  quay.io/prometheus/prometheus:v3.2.1
docker pull swr.cn-north-4.myhuaweicloud.com/ddn-k8s/quay.io/prometheus/alertmanager:v0.28.1
docker tag  swr.cn-north-4.myhuaweicloud.com/ddn-k8s/quay.io/prometheus/alertmanager:v0.28.1  quay.io/prometheus/alertmanager:v0.28.1
docker pull swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/grafana/grafana:11.6.0
docker tag  swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/grafana/grafana:11.6.0  docker.io/grafana/grafana:11.6.0
```

建服务账号

```
kubectl create ns monitor-sa #名称空间
kubectl create serviceaccount monitor -n monitor-sa #服务账号
kubectl create clusterrolebinding monitor-clusterrolebinding -n monitor-sa --clusterrole=cluster-admin  --serviceaccount=monitor-sa:monitor #集群角色，有必要给集群管理员权限？
```



##### Prometheus 推送告警规则

挂载在 /etc/prometheus/rules/*.rules

```
#不用cat 输入，$太多了 
vi prometheus-rules.yaml  

apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rules
  namespace: monitor-sa
data:

  general.rules: |
    groups:
    - name: general.rules
      rules:
      - alert: InstanceDown
        expr: up == 0
        for: 15m
        labels:
          severity: error 
        annotations:
          summary: "Instance {{ $labels.instance }} 停止工作"
          description: "{{ $labels.instance }} job {{ $labels.job }} 已经停止15分钟以上."

  node.rules: |
    groups:
    - name: linux.rules
      rules:
      - alert: NodeFilesystemUsage
        expr: 100 - (node_filesystem_free_bytes{fstype=~"ext4|xfs"} / node_filesystem_size_bytes{fstype=~"ext4|xfs"} * 100) > 90 
        for: 5m
        labels:
          severity: warning 
        annotations:
          summary: "Instance {{ $labels.instance }} : {{ $labels.mountpoint }} 分区使用率过高"
          description: "{{ $labels.instance }}: {{ $labels.mountpoint }} 分区使用大于90% (当前值: {{ $value }})"

      - alert: NodeMemoryUsage
        expr: 100 - (node_memory_MemFree_bytes+node_memory_Cached_bytes+node_memory_Buffers_bytes) / node_memory_MemTotal_bytes * 100 > 90
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Instance {{ $labels.instance }} 内存使用率过高"
          description: "{{ $labels.instance }}内存使用大于90% (当前值: {{ $value }})"

      - alert: NodeCPUUsage    
        expr: 100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[15m])) by (instance) * 100) > 80 
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Instance {{ $labels.instance }} CPU使用率过高"       
          description: "{{ $labels.instance }}CPU使用大于80% (当前值: {{ $value }})"
    
    - name: windows.rules
      rules:
        - alert: WindowsCPUUsageHigh
          expr: 100 - (avg by(instance) (rate(windows_cpu_time_total{mode="idle"}[15m])) * 100) > 80
          for: 15m
          labels:
            severity: critical
          annotations:
            summary: "Windows 节点 CPU 使用率过高 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的 CPU 使用率持续 15 分钟超过 80% (当前值: {{ $value }}%)"

        - alert: WindowsMemoryUsageHigh
          expr: 100 - (windows_memory_physical_free_bytes / windows_cs_physical_memory_bytes * 100) > 90
          for: 30m
          labels:
            severity: critical
          annotations:
            summary: "Windows 节点内存使用率过高 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的内存使用率持续 30 分钟超过 90% (当前值: {{ $value }}%)"

        - alert: WindowsDiskUsageHigh
          expr: 100 - (windows_logical_disk_free_bytes{volume=~"C:|D:|E:|F:"} / windows_logical_disk_size_bytes{volume=~"C:|D:|E:|F:"}* 100) > 90
          for: 30m
          labels:
            severity: warning
          annotations:
            summary: "Windows 节点磁盘使用率过高 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的磁盘 ({{ $labels.volume }}) 使用率持续 30 分钟超过 90% (当前值: {{ $value }}%)"

  web.rules: |
    groups:
    - name: web.rules
      rules:
        - alert: HTTPStatusUnhealthy
          expr: probe_http_status_code{job="blackbox-http"} < 200 or probe_http_status_code{job="blackbox-http"} >= 400
          for: 30m
          labels:
            severity: critical
          annotations:
            summary: "HTTP 服务状态码异常 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的 HTTP 状态码持续 30 分钟非 2xx/3xx (当前值: {{ $value }})"

        - alert: HTTPResponseTimeHigh
          expr: probe_http_duration_seconds{job="blackbox-http"} > 5
          for: 30m
          labels:
            severity: warning
          annotations:
            summary: "HTTP 响应时间过长 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的 HTTP 响应时间持续 30 分钟超过 5 秒 (当前值: {{ $value }}秒)"

        - alert: HTTPSCertificateExpiringSoon
          expr: probe_ssl_earliest_cert_expiry{job="blackbox-http"} - time() < 86400 * 15
          for: 1h
          labels:
            severity: warning
          annotations:
            summary: "HTTPS 证书即将过期 ({{ $labels.instance }})"
            description: "{{ $labels.instance }} 的 HTTPS 证书将在 15 天内过期"

  net.rules: |
    groups:
    - name: line.rules
      rules:
      - alert: IcmpPingFailed
        expr: probe_success{job="blackbox-icmp"} == 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} ping 失败"
          description: "{{ $labels.instance }} 已经连续 15 分钟无法 ping 通"

      - alert: IcmpHighLatency
        expr: probe_duration_seconds{job="blackbox-icmp"} > 0.5  # 延迟超过500毫秒
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} ICMP 延迟过高"
          description: "{{ $labels.instance }} 的 ICMP 延迟持续超过 500ms (当前值: {{ $value }}s)"

      - alert: IcmpPacketLoss
        expr: probe_packet_loss{job="blackbox-icmp"} > 10  # 丢包率超过10%
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} ICMP 丢包率过高"
          description: "{{ $labels.instance }} 的 ICMP 丢包率持续超过 10% (当前值: {{ $value }}%)"

      - alert: IcmpLatencyVariance
        expr: stddev_over_time(probe_duration_seconds{job="blackbox-icmp"}[5m]) > 0.2
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} ICMP 响应时间不稳定"
          description: "{{ $labels.instance }} 的 ICMP 响应时间波动过大 (标准差: {{ $value }}s)"



kubectl apply -f prometheus-rules.yaml
```



##### prometheus 配置文件

```
mkdir /prometheus && chmod 777 /prometheus

cat > prometheus-cfg.yaml << EOF
---
kind: ConfigMap
apiVersion: v1
metadata:
  labels:
    app: prometheus
  name: prometheus-config
  namespace: monitor-sa
data:
  prometheus.yaml: |
    global:
      scrape_interval: 3m
      scrape_timeout: 3m
      evaluation_interval: 3m
    
    alerting:
      alertmanagers:
      - static_configs:
        - targets: ['10.128.4.212:30093']
    
    rule_files:
    - /etc/prometheus/rules/*.rules
    
    scrape_configs:
      - job_name: 'node_exporter'
        scheme: https
        metrics_path: "/metrics" 
        tls_config:
          ca_file: /prometheus/node_exporter.crt
          insecure_skip_verify: true
        basic_auth:
          username: admin
          password: ULT9BS159BUAQKijqq
        file_sd_configs:
        - files:
          - /prometheus/targets/nodes/*.json
          refresh_interval: 1m

      - job_name: 'blackbox-http'
        metrics_path: "/probe"
        params:
          module: [http_2xx]
        file_sd_configs:
          - files:
            - /prometheus/targets/blackbox/blackbox-http.json
            refresh_interval: 1m
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: blackbox-exporter:9115

      - job_name: 'blackbox-tcp'
        metrics_path: "/probe"
        params:
          module: [tcp_connect]
        file_sd_configs:
          - files:
            - /prometheus/targets/blackbox/blackbox-tcp.json
            refresh_interval: 1m
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: blackbox-exporter:9115

      - job_name: 'blackbox-icmp'
        metrics_path: "/probe"
        params:
          module: [icmp]
        file_sd_configs:
          - files:
            - /prometheus/targets/blackbox/blackbox-icmp.json
            refresh_interval: 1m
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: blackbox-exporter:9115 

EOF

cat > /prometheus/targets/nodes/linux.json << EOF
[{
  "targets": [
    "10.128.2.17:9100",
    "10.128.2.251:9100"
  ],
  "labels": {
    "server": "linux"
  }
}]

EOF

kubectl delete -f prometheus-cfg.yaml
kubectl apply -f prometheus-cfg.yaml
kubectl edit -f prometheus-cfg.yaml -n monitor-sa
```



##### prometheus deployment

```
cat > prometheus-deployment.yaml << EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-server
  namespace: monitor-sa
  labels:
    app: prometheus
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
      annotations:
        prometheus.io/scrape: 'false'
    spec:
      nodeName: w1
      serviceAccountName: monitor
      containers:
      - name: prometheus
        image: quay.io/prometheus/prometheus:v3.2.1
        command:
          - prometheus
          - --config.file=/etc/prometheus/prometheus.yaml
          - --storage.tsdb.path=/prometheus
          - --storage.tsdb.retention.time=365d
          - --web.enable-lifecycle
        ports:
        - containerPort: 9090
          protocol: TCP
        volumeMounts:
        - name: prometheus-config
          mountPath: /etc/prometheus/prometheus.yaml
          subPath: prometheus.yaml
        - name: prometheus-storage-volume
          mountPath: /prometheus/
        - name: prometheus-rules
          mountPath: /etc/prometheus/rules
          subPath: ""
      volumes:
        - name: prometheus-config
          configMap:
            name: prometheus-config
            items:
              - key: prometheus.yaml
                path: prometheus.yaml
                mode: 0644
        - name: prometheus-storage-volume
          hostPath:
           path: /prometheus
           type: Directory
        - name: prometheus-rules
          configMap:
            name: prometheus-rules

EOF

kubectl apply -f prometheus-deployment.yaml
kubectl get deployment -o wide -n monitor-sa
kubectl delete -f prometheus-deployment.yaml
kubectl get pods -o wide -n monitor-sa
kubectl logs prometheus-server-74b7f56667-fp2ph -n monitor-sa
kubectl edit -f prometheus-cfg.yaml -n monitor-sa

kubectl exec -it prometheus-server-74b7f56667-z4g8x -n monitor-sa -- /bin/sh
```

##### promethues service

```
cat prometheus-service.yaml
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: monitor-sa
  labels:
    app: prometheus
spec:
  type: NodePort
  ports:
    - port: 9090
      targetPort: 9090
      nodePort: 30090
      protocol: TCP
  selector:
    app: prometheus

	
kubectl apply -f prometheus-service.yaml
kubectl get services -o wide -n monitor-sa
```

http://10.128.4.212:30090



重启deployment

```
kubectl delete -f prometheus-deployment.yaml
kubectl apply -f prometheus-deployment.yaml
```

热加载配置文件

```
kubectl get pods -n monitor-sa -o wide
curl -X POST http://192.168.190.117:9090/-/reload
kubectl logs -n monitor-sa prometheus-server-794585455f-ctjt4
```



## 2、grafana

#### 二进制安装

```
wget https://dl.grafana.com/enterprise/release/grafana-enterprise-11.6.1.linux-amd64.tar.gz
tar -zxvf grafana-enterprise-11.6.1.linux-amd64.tar.gz
mv grafana-v11.6.1 /opt/monitor/grafana
cd /opt/monitor/grafana/bin
./grafana cli admin reset-admin-password ULT9BS159BUAQKijqq
groupadd grafana
useradd -M -s /bin/false -g grafana grafana

vi /usr/lib/systemd/system/grafana.service

[Unit]
Description=grafana
[Service]
User=grafana
Group=grafana
ExecStart=/opt/monitor/grafana/bin/grafana-server --home-path=/opt/monitor/grafana
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
[Install]
WantedBy=multi-user.target


systemctl daemon-reload
systemctl enable grafana
systemctl start grafana
systemctl status grafana
```



#### k8s安装grafana

先查看docker 容器里需要挂载出去的目录， 复制目录里的文件

```
docker pull swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/grafana/grafana:11.6.0
docker tag  swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/grafana/grafana:11.6.0  docker.io/grafana/grafana:11.6.0

docker run -d --name grafana grafana/grafana:11.6.0
docker ps | grep grafana
docker inspect 37edfe

"GF_PATHS_CONFIG=/etc/grafana/grafana.ini",
"GF_PATHS_DATA=/var/lib/grafana",
"GF_PATHS_HOME=/usr/share/grafana",
"GF_PATHS_LOGS=/var/log/grafana", 
"GF_PATHS_PLUGINS=/var/lib/grafana/plugins",
"GF_PATHS_PROVISIONING=/etc/grafana/provisioning"

mkdir -p /grafana/{data,log,lib}
chmod 777 -R /grafana
docker cp 37edfe:/etc/grafana /grafana/etc
docker cp 37edfe:/var/lib/grafana /grafana/lib
docker cp 37edfe:/var/log/grafana /grafana/log

docker rm -f 37edfe
```

deployment 和 service 在一个yaml 里

cat grafana.yaml 

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana-server
  namespace: monitor-sa
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      nodeName: w2   #容器固定在w2
      containers:
      - name: grafana
        image: docker.io/grafana/grafana:11.6.0
        ports:
        - containerPort: 3000
          protocol: TCP
        volumeMounts:
        - name: grafana-etc
          mountPath: /etc/grafana
        - name: grafana-lib
          mountPath: /var/lib/ 
        - name: grafana-log
          mountPath: /var/log/                
      volumes:
      - name: grafana-etc
        hostPath:
          path: /grafana/etc/grafana
      - name: grafana-lib
        hostPath:
          path: /grafana/lib/
      - name: grafana-log
        hostPath:
          path: /grafana/log
---
apiVersion: v1
kind: Service
metadata:
  labels:
    kubernetes.io/cluster-service: 'true'
    kubernetes.io/name: grafana
  name: grafana
  namespace: monitor-sa
spec:
  ports:
  - port: 80
    targetPort: 3000
    nodePort: 30030
  selector:
    app: grafana
  type: NodePort

```



```
kubectl apply -f grafana.yaml
kubectl get deployment -o wide -n monitor-sa
kubectl get services -o wide -n monitor-sa

kubectl exec -it grafana-server-c94c6476d-bz7bj -n monitor-sa -- /bin/bash
```

只有数据库所在的Node 能访问， http://10.128.4.213:30030/， 为什么？



## 3、alertmanager

#### 二进制安装

```
wget https://github.com/prometheus/alertmanager/releases/download/v0.28.1/alertmanager-0.28.1.linux-amd64.tar.gz -C /opt/monitor/altermanager

cat > /usr/lib/systemd/system/alertmanager.service << EOF 
 
[Unit]
Description=alertmanager

[Service]
Restart=on-failure
ExecStart=/usr/local/alertmanager/alertmanager --config.file=/usr/local/alertmanager/alertmanager.yml
 
[Install]                      
WantedBy=multi-user.target

EOF 

systemctl daemon-reload
systemctl start alertmanager
systemctl enable alertmanager
```



#### k8s安装alertmanager

##### alertmanager 告警配置文件

```
cat > alertmanager-configmap.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: alertmanager-config
  namespace: monitor-sa
  labels:
    app: alertmanager
data:
  alertmanager.yaml: |
    global:
      resolve_timeout: 5m
      smtp_smarthost: 'smtp.qq.com:587'
      smtp_from: 'xutaon@qq.com'
      smtp_auth_username: 'xutaon@qq.com'
      smtp_auth_password: 'gjnpqltakejvcbea'

    route:
      receiver: 'wechat'
      group_by: ['alertname']
      group_wait: 1m
      group_interval: 5m
      repeat_interval: 12h
      routes:
        - match_re:
            severity: ^warning|critical$
          receiver: 'wechat'
          continue: true

    receivers:
      - name: 'email'
        email_configs:
          - to: 'xutaon@qq.com'
      - name: 'wechat' 
        webhook_configs:
          - url: 'http://wechat-webhook-svc/alertinfo'
            send_resolved: true

    inhibit_rules:
      - source_match:
          severity: 'error'
        target_match:
          severity: 'warning'
        equal: ['alertname','severity']

EOF

kubectl apply -f alertmanager-configmap.yaml
```



##### alertmanager deployment

```
cat > alertmanager-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alertmanager
  namespace: monitor-sa
  labels:
    app: alertmanager
spec:
  replicas: 1
  selector:
    matchLabels:
      app: alertmanager
  template:
    metadata:
      labels:
        app: alertmanager
    spec:
      nodeName: w1
      containers:
        - name: alertmanager-deployment
          image: quay.io/prometheus/alertmanager
          imagePullPolicy: "IfNotPresent"
          args:
            - --config.file=/etc/alertmanager/alertmanager.yaml
            - --storage.path=/alertmanager
          ports:
            - containerPort: 9093
          readinessProbe:
            httpGet:
              path: /#/status
              port: 9093
            initialDelaySeconds: 30
            timeoutSeconds: 30
          volumeMounts:
            - name: alertmanager-config
              mountPath: /etc/alertmanager/alertmanager.yaml
              subPath: alertmanager.yaml
            - name: alertmanager-storage-volume
              mountPath: /alertmanager
            - name: alertmanager-templates
              mountPath: /etc/alertmanager/templates/wechat.tmpl
              subPath: wechat.tmpl

      volumes:
        - name: alertmanager-config
          configMap:
            name: alertmanager-config
            items:
              - key: alertmanager.yaml
                path: alertmanager.yaml
                mode: 0644

        - name: alertmanager-templates
          configMap:
            name: alertmanager-templates
            items:
              - key: wechat.tmpl
                path: wechat.tmpl
                mode: 0644

        - name: alertmanager-storage-volume
          hostPath:
            path: /alertmanager
            type: Directory
EOF

kubectl apply -f alertmanager-deployment.yaml
```



##### alertmanager service

```
cat > alertmanager-service.yaml << EOF
apiVersion: v1
kind: Service
metadata:
  name: alertmanager
  namespace: monitor-sa
  labels:
    app: alertmanager
spec:
  ports:
    - port: 80
      targetPort: 9093
      nodePort: 30093
      protocol: TCP
  selector:
    app: alertmanager 
  type: NodePort
 
EOF

kubectl apply -f alertmanager-service.yaml
```



## 4、node_exporter

### systemd 安装脚本

```
#wget https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz
mkdir /opt/
cd /opt/
curl -o node_exporter.tar.gz http://10.128.4.214:30081/node_exporter-1.9.1.linux-amd64.tar.gz
tar -zxvf node_exporter.tar.gz
mv node_exporter-1.9.1.linux-amd64 node_exporter
cd /opt/node_exporter
curl -o node_exporter.crt http://10.128.4.214:30081/node_exporter.crt
curl -o node_exporter.key http://10.128.4.214:30081/node_exporter.key

# $前加 \ 转义
cat > /opt/node_exporter/config.yaml << EOF
tls_server_config:
  cert_file: node_exporter.crt
  key_file: node_exporter.key
basic_auth_users:
  admin: \$2y\$12\$l6YvjuaCpmu8ggX3.9PCrO1rsG7JGu.KlslwljUAPRGaVbDSwYnze 
EOF

cat > /usr/lib/systemd/system/node_exporter.service << EOF 

[Unit]
Description=node_exporter
[Service]
ExecStart=/opt/node_exporter/node_exporter --web.listen-address=0.0.0.0:9100 --web.config.file=/opt/node_exporter/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
[Install]
WantedBy=multi-user.target

EOF

systemctl daemon-reload
systemctl start node_exporter
systemctl enable node_exporter
```



### 兼容systemd 和 init 的安装脚本

```
#!/bin/bash

# 定义变量
NODE_EXPORTER_VERSION="1.9.1"
NODE_EXPORTER_DIR="/opt/node_exporter"
CONFIG_FILE="/opt/node_exporter/config.yaml"
SYSTEMD_SERVICE_FILE="/usr/lib/systemd/system/node_exporter.service"
INIT_SERVICE_FILE="/etc/init.d/node_exporter"
DOWNLOAD_URL="http://10.128.4.214:30081"
TAR_FILE="node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
FIREWALL_PORT=9100

# 创建安装目录
mkdir -p /opt/
mkdir -p /usr/lib/systemd/system/node_exporter
cd /opt/

# 下载并解压node_exporter
if [ ! -f "$TAR_FILE" ]; then
    echo "正在下载 node_exporter..."
    curl -o "$TAR_FILE" "$DOWNLOAD_URL/$TAR_FILE" || { echo "下载失败"; exit 1; }
fi

echo "正在解压 node_exporter..."
tar -zxvf "$TAR_FILE" || { echo "解压失败"; exit 1; }
mv "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64" "node_exporter"

# 进入安装目录
cd "$NODE_EXPORTER_DIR"

# 下载证书文件
echo "正在下载证书文件..."
curl -o node_exporter.crt "$DOWNLOAD_URL/node_exporter.crt" || { echo "下载证书失败"; exit 1; }
curl -o node_exporter.key "$DOWNLOAD_URL/node_exporter.key" || { echo "下载密钥失败"; exit 1; }

# 创建配置文件
echo "正在创建配置文件..."
cat > "$CONFIG_FILE" << EOF
tls_server_config:
  cert_file: node_exporter.crt
  key_file: node_exporter.key
basic_auth_users:
  admin: \$2y\$12\$l6YvjuaCpmu8ggX3.9PCrO1rsG7JGu.KlslwljUAPRGaVbDSwYnze 
EOF

# 配置防火墙
echo "正在配置防火墙，开放 $FIREWALL_PORT 端口..."
if command -v firewall-cmd >/dev/null 2>&1; then
    echo "检测到 firewalld，正在开放端口..."
    firewall-cmd --permanent --add-port=$FIREWALL_PORT/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "firewalld 配置完成"
elif command -v iptables >/dev/null 2>&1; then
    echo "检测到 iptables，正在开放端口..."
    iptables -I INPUT -p tcp --dport $FIREWALL_PORT -j ACCEPT >/dev/null 2>&1 || true
    
    # 保存规则 (兼容不同系统)
    if command -v service >/dev/null 2>&1 && service iptables status >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 || true
    elif command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/sysconfig/iptables >/dev/null 2>&1 || true
    fi
    echo "iptables 配置完成"
else
    echo "未检测到 firewalld 或 iptables，跳过防火墙配置"
fi

# 检测系统使用的初始化系统
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo "检测到 systemd 初始化系统"
    
    # 创建 systemd 服务文件
    echo "正在创建 systemd 服务文件..."
    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=node_exporter
[Service]
ExecStart=$NODE_EXPORTER_DIR/node_exporter --web.listen-address=0.0.0.0:$FIREWALL_PORT --web.config.file=$CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    
    # 重载 systemd 并启动服务
    systemctl daemon-reload
    
    # 定义服务管理函数
    start_service() {
        systemctl start node_exporter
    }
    
    stop_service() {
        systemctl stop node_exporter
    }
    
    enable_service() {
        systemctl enable node_exporter
    }
    
    check_status() {
        systemctl is-active --quiet node_exporter
        return $?
    }
else
    echo "检测到 SysVinit 初始化系统"
    
    # 创建 SysVinit 服务脚本
    echo "正在创建 SysVinit 服务脚本..."
    cat > "$INIT_SERVICE_FILE" << EOF
#!/bin/bash
# chkconfig: 2345 90 10
# description: node_exporter service

### BEGIN INIT INFO
# Provides:          node_exporter
# Required-Start:    \$network \$local_fs \$remote_fs
# Required-Stop:     \$network \$local_fs \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: node_exporter
# Description:       Prometheus node_exporter
### END INIT INFO

NODE_EXPORTER="$NODE_EXPORTER_DIR/node_exporter"
CONFIG_FILE="$CONFIG_FILE"
PIDFILE="/var/run/node_exporter.pid"
LOGFILE="/var/log/node_exporter.log"

start() {
    echo -n "Starting node_exporter: "
    if [ -f "\$PIDFILE" ]; then
        read -r pid < "\$PIDFILE"
        if ps -p "\$pid" > /dev/null; then
            echo "already running"
            return 0
        fi
    fi
    
    \$NODE_EXPORTER --web.listen-address=0.0.0.0:$FIREWALL_PORT --web.config.file=\$CONFIG_FILE >"\$LOGFILE" 2>&1 &
    echo \$! > "\$PIDFILE"
    echo "OK"
}

stop() {
    echo -n "Stopping node_exporter: "
    if [ -f "\$PIDFILE" ]; then
        read -r pid < "\$PIDFILE"
        if ps -p "\$pid" > /dev/null; then
            kill -9 "\$pid"
            rm -f "\$PIDFILE"
            echo "OK"
        else
            echo "not running"
        fi
    else
        echo "not running"
    fi
}

status() {
    if [ -f "\$PIDFILE" ]; then
        read -r pid < "\$PIDFILE"
        if ps -p "\$pid" > /dev/null; then
            echo "node_exporter is running with PID \$pid"
            return 0
        else
            echo "node_exporter is not running, but PID file exists"
            return 1
        fi
    else
        echo "node_exporter is not running"
        return 3
    fi
}

case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
EOF
    
    # 设置权限和 chkconfig
    chmod +x "$INIT_SERVICE_FILE"
    if command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add node_exporter
    elif command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d node_exporter defaults
    fi
    
    # 定义服务管理函数
    start_service() {
        service node_exporter start
    }
    
    stop_service() {
        service node_exporter stop
    }
    
    enable_service() {
        if command -v chkconfig >/dev/null 2>&1; then
            chkconfig node_exporter on
        elif command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d node_exporter enable
        fi
    }
    
    check_status() {
        service node_exporter status >/dev/null 2>&1
        return $?
    }
fi

# 启动并启用服务
echo "正在启动 node_exporter 服务..."
start_service

# 检查服务是否启动成功
if check_status; then
    echo "node_exporter 服务已成功启动"
    
    # 启用服务自启动
    echo "正在设置 node_exporter 服务开机自启动..."
    enable_service
    echo "node_exporter 服务已设置为开机自启动"
else
    echo "启动 node_exporter 服务失败，请检查配置和日志"
    exit 1
fi

echo "node_exporter 安装完成！"
echo "服务运行在端口: $FIREWALL_PORT"
```



## 5、blackbox_exporter

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: blackbox-exporter-config
  namespace: monitor-sa
data:
  blackbox.yml: |
    modules:
      http_2xx:
        prober: http
        timeout: 5s
        http:
          headers:
            User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            Accept-Language: "zh-CN,zh;q=0.9,en;q=0.8"
            Accept-Encoding: "gzip, deflate, br"
            Cookie: "session_id=1234567890"
            Origin: "https://example.com" 
          valid_status_codes: [200, 301, 302]
          tls_config:
            insecure_skip_verify: true
          follow_redirects: false
          method: GET
          preferred_ip_protocol: "ip4"

      tcp_connect:
        prober: tcp
        timeout: 5s
        
      icmp:
        prober: icmp
        timeout: 5s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-exporter
  namespace: monitor-sa
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-exporter
  template:
    metadata:
      labels:
        app: blackbox-exporter
    spec:
      nodeName: w1 
      containers:
        - name: blackbox-exporter
          image: quay.io/prometheus/blackbox-exporter:v0.26.0
          args:
            - '--config.file=/etc/blackbox_exporter/blackbox.yml'
          ports:
            - containerPort: 9115
          volumeMounts:
            - name: config
              mountPath: /etc/blackbox_exporter
      volumes:
        - name: config
          configMap:
            name: blackbox-exporter-config
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-exporter
  namespace: monitor-sa
  labels:
    app: blackbox-exporter
spec:
  selector:
    app: blackbox-exporter
  ports:
    - name: http
      port: 9115
      targetPort: 9115
```



## 6、企业微信webhook

### 制作flask镜像

```
git clone https://github.com/hsggj002/prometheus-flask.git
cd prometheus-flask/

vi app/Alert.py

# -*- coding: UTF-8 -*-
from doctest import debug_script
from pydoc import describe
from flask import jsonify
import requests
import json
import datetime


def parse_time(date_str):
    if len(date_str.split('.')) >= 2:
        if 'Z' in date_str.split('.')[1]:
            s_eta = date_str.split('.')[0] + '.' + date_str.split('.')[1][-5:]
            fd = datetime.datetime.strptime(s_eta, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            # 修正赋值错误
            date_str = date_str.split('.')[0] + '.000Z'
            fd = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        fd = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")

    # 转换为东八区时间并格式化
    eta = (fd + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return eta

def alert(status,alertnames,levels,starttime,ins,instance,description):

    params = json.dumps(
        {

            "msgtype": "markdown",
            "markdown":
                {
                    "content":
'''## <font color="red">告警通知:</font>
**{4}:** {5}
**告警名称:** <font color="warning">{1}</font>
**告警级别:** {2}
**告警时间:** {3}
**告警详情:** <font color="comment">{6}</font>'''
                        .format(status,alertnames,levels,starttime,ins,instance,description)
                }
        }
    )

    return params

def resolved(status,alertnames,levels,starttime,endtime,ins,instance,description):

    params = json.dumps(
        {

            "msgtype": "markdown",
            "markdown":
                {
                    "content":
'''## <font color="info">恢复通知:</font>
**{5}:** {6}
**告警名称:** <font color="warning">{1}</font>
**告警级别:** {2}
**告警时间:** {3}
**恢复时间:** {4}
**告警详情:** <font color="comment">{7}</font>'''
                    .format(status, alertnames, levels, starttime, endtime, ins, instance, description)
            }
        }
    )

    return params

def webhook_url(params,url_key):
    headers = {"Content-type": "application/json"}
    """
    *****重要*****
    """
    url = "{}".format(url_key)
    r = requests.post(url,params,headers)

def send_alert(json_re,url_key):
    for i in json_re['alerts']:
        if i['status'] == 'firing':
            if "instance" in i['labels']:
                if "description" in i['annotations']:
                    params = alert(i['status'], i['labels']['alertname'], i['labels']['severity'], parse_time(i['startsAt']),
                          '故障实例', i['labels']['instance'], i['annotations']['description'])
                    webhook_url(params,url_key)
                elif "message" in i['annotations']:
                    params = alert(i['status'], i['labels']['alertname'], i['labels']['severity'], parse_time(i['startsAt']),
                          '故障实例', i['labels']['instance'], i['annotations']['message'])
                    webhook_url(params,url_key)
                else:
                    params = alert(i['status'], i['labels']['alertname'], i['labels']['severity'], parse_time(i['startsAt']),
                          '故障实例', i['labels']['instance'], 'Service is wrong')
                    webhook_url(params,url_key)
            elif "namespace" in i['labels']:
                webhook_url(alert(i['status'], i['labels']['alertname'],i['labels']['severity'],parse_time(i['startsAt']),'名称空间',i['labels']['namespace'],i['annotations']['description']),url_key)
            elif "Watchdog" in i['labels']['alertname']:
                webhook_url(alert(i['status'], i['labels']['alertname'],'0','0','0','0','0'),url_key)
        elif i['status'] == 'resolved':
            if "instance" in i['labels']:
                if "description" in i['annotations']:
                    webhook_url(resolved(i['status'], i['labels']['alertname'],i['labels']['severity'],parse_time(i['startsAt']),parse_time(i['endsAt']),'故障实例',i['labels']['instance'],i['annotations']['description']),url_key)
                elif "message" in i['annotations']:
                    webhook_url(resolved(i['status'], i['labels']['alertname'],i['labels']['severity'],parse_time(i['startsAt']),parse_time(i['endsAt']),'故障实例',i['labels']['instance'],i['annotations']['message']),url_key)
                else:
                    webhook_url(resolved(i['status'], i['labels']['alertname'],i['labels']['severity'],parse_time(i['startsAt']),parse_time(i['endsAt']),'故障实例',i['labels']['instance'],'Service is wrong'),url_key)
            elif "namespace" in i['labels']:
                webhook_url(resolved(i['status'], i['labels']['alertname'],i['labels']['severity'],parse_time(i['startsAt']),parse_time(i['endsAt']),'名称空间',i['labels']['namespace'],i['annotations']['description']),url_key)
            elif "Watchdog" in i['labels']['alertname']:
                webhook_url(alert(i['status'], i['labels']['alertname'],'0','0','0','0','0'),url_key)




docker build -t lyvc/prometheus-flask:latest .
docker images

#image 在pod 所在的服务器上也要有
docker save b3b8 > pro-flask.tar
scp pro-flask.tar root@10.128.4.212:/root/

docker load < pro-flask.tar
docker tag b3b8 lyvc/prometheus-flask:latest
```



### 部署flask应用

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wechat-webhook
  namespace: monitor-sa
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wechat-webhook
  template:
    metadata:
      labels:
        app: wechat-webhook 
    spec:
      nodeName: w1
      containers:
      - name: wechat-webhook
        image: lyvc/prometheus-flask:latest
        imagePullPolicy: IfNotPresent
        ports:
          - name: http
            containerPort: 80
            protocol: TCP
        command: ["python", "/app/main.py"]
        args:
          - "-k https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=5cba2202-85f1-4b48-b644-512532643a5b"
          - "-p 80"
---
apiVersion: v1
kind: Service
metadata:
  name: wechat-webhook-svc
  namespace: monitor-sa
spec:
  selector:
    app: wechat-webhook
  type: ClusterIP
  ports:
  - name: http 
    targetPort: 80
    port: 80
```

