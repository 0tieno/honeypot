# Operations

## Deployment phases

Everything was built in this order, so that monitoring was verified **before** anything was exposed.

```mermaid
flowchart TB
    n["infra/deploy.sh network<br/>RG, VNet, NSG locked to admin IP, public IP"]
    v["infra/deploy.sh vm<br/>Ubuntu VM, SSH key auth"]
    s["vm/setup.sh on the VM<br/>sshd → 22022, Cowrie, iptables, nginx, web app"]
    m["infra/deploy.sh monitor<br/>Log Analytics, custom tables, DCE, DCR, AMA"]
    t1{"tests/selftest.sh<br/>services + ingestion"}
    e["infra/deploy.sh egress<br/>deny outbound Internet"]
    t2{"tests/selftest.sh<br/>still ingesting?"}
    d["infra/deploy.sh dashboard<br/>workbook"]
    x["infra/deploy.sh expose<br/>Honeypot-Ingress → Internet<br/>writes EXPOSURE_TIME.txt"]

    n --> v --> s --> m --> t1
    t1 -- pass --> e --> t2
    t1 -- fail --> m
    t2 -- pass --> d --> x
    t2 -- fail --> e
```

## Experiment timeline

```mermaid
gantt
    title Operation Cloud Bait
    dateFormat YYYY-MM-DD HH:mm
    axisFormat %a %d %H:%M

    section Build
    Infra, VM, monitoring, tests       :done, b1, 2026-10-11 05:20, 47m
    section Collect
    EXPOSED 06.07.20 UTC               :milestone, m1, 2026-10-11 06:07, 0m
    First attack 06.12.08 UTC, SSH     :milestone, m2, 2026-10-11 06:12, 0m
    Leave it alone, check daily        :active, c1, 2026-10-11 06:07, 2026-10-15 06:00
    section Present
    Final queries and screenshots      :p0, 2026-10-15 06:00, 2h
    Thursday session                   :milestone, p1, 2026-10-15 09:00, 0m
    section Clean up
    az group delete cloud-bait-rg      :crit, d1, 2026-10-15 12:00, 2026-10-16 12:00
```

**Time to first attack: 4 min 48 s.** The NSG opened at 06:07:20Z. The first SSH connection came from 77.91.71.92 at 06:12:08Z.

## Daily check

```mermaid
flowchart LR
    a["tests/selftest.sh"] --> b{"15/15 pass?"}
    b -- yes --> c["Open workbook<br/>record totals in notebook"]
    b -- no --> d{"What failed?"}
    d -- "admin SSH times out" --> e["Home IP changed:<br/>update Allow-Admin-SSH +<br/>excluded IP in queries"]
    d -- "ingestion" --> f["ssh :22022, check<br/>/var/opt/microsoft/azuremonitoragent/log"]
    d -- "service" --> g["systemctl status cowrie<br/>cloudbait-web nginx"]
```

## Kill switch

```mermaid
stateDiagram-v2
    [*] --> Collecting
    Collecting --> Investigate: unexpected outbound traffic,<br/>unknown process, cost spike
    Investigate --> Collecting: false alarm
    Investigate --> Deallocated: az vm deallocate
    Collecting --> Presented: Thursday
    Deallocated --> Presented: telemetry is already in Log Analytics
    Presented --> Deleted: az group delete -n cloud-bait-rg --yes
    Deleted --> [*]
```

Deallocating the VM loses nothing that matters: the evidence is already in `cb-law`. Delete the whole resource group after the talk. That removes the VM, network, workspace and dashboard together, so export screenshots or query results first.
