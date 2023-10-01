---
layout: post
title: Monitoring
---

## Prometheus
### Config prometheus.yml
```yml
global:
  scrape_interval: 10s
scrape_configs:
 - job_name: prometheus
   static_configs:
    - targets:
       - prometheus:9090
 - job_name: nodejs-app
   static_configs:
    - targets: ["192.168.1.7:8080"]
```

```yml
version: '3'
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - "./prometheus.yml:/etc/prometheus/prometheus.yml"
    ports:
      - 9090:9090
```

### Nodejs Metrics
```shell
npm i prom-client
```

```javascript
const { collectDefaultMetrics, register } = require('prom-client');

collectDefaultMetrics();

app.get('/metrics', (req, res) => {
  res.set('Content-Type', register.contentType);
  register.metrics().then(data => res.send(data));
});
```

### Grafana
```yml
version: '3'
services:
  grafana:
    image: grafana/grafana
    ports:
      - 3000:3000
    restart: always
    depends_on:
      - prometheus
```
