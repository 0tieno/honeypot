# Architecture

Operation: Cloud Bait is one disposable Ubuntu VM that pretends to be an interesting production server. Everything it observes is shipped to Log Analytics, which keeps the evidence even if the VM is compromised or deleted.

## Components

```mermaid
flowchart LR
    subgraph sub["Azure subscription"]
        subgraph rg["cloud-bait-rg"]
            direction TB
            subgraph net["Network"]
                vnet["cb-vnet 10.50.0.0/16"]
                snet["cb-subnet 10.50.1.0/24"]
                nsg{{"cb-nsg"}}
                pip["cb-public-ip<br/>20.87.210.98 static"]
            end
            subgraph compute["Compute"]
                vm["cb-vm-01<br/>Standard_B2als_v2<br/>Ubuntu 24.04"]
                mi["System-assigned identity<br/>0 role assignments"]
            end
            subgraph mon["Monitoring"]
                dce["cb-dce<br/>data collection endpoint"]
                dcr["cb-dcr<br/>data collection rule"]
                law[("cb-law<br/>Log Analytics, 30-day retention")]
                wb["Workbook<br/>13 panels"]
            end
        end
        prod["Other resource groups<br/>rg-coi-prod, businessos-rg, ..."]
    end

    vnet --- snet --- vm
    nsg --- vm
    pip --- vm
    mi --- vm
    vm -- "AMA" --> dce --> dcr --> law --> wb
    rg ~~~ prod
    prod -. "no peering, no shared identity,<br/>no shared keys" .- rg
```

| Layer | Choice | Why |
|---|---|---|
| Isolation | Dedicated resource group and VNet, no peering | One `az group delete` removes everything. No path to production. |
| Identity | System-assigned identity with **zero** roles | AMA needs it to authenticate. A stolen token can do nothing. |
| Compute | One small VM | The VM is bait, not a workload |
| Telemetry | AMA + DCR → Log Analytics | Evidence leaves the box within about a minute |

## Inside the VM

```mermaid
flowchart TB
    subgraph vm["cb-vm-01"]
        direction TB
        subgraph kernel["netfilter (iptables nat PREROUTING)"]
            r22["dport 22 → REDIRECT 2222"]
            r23["dport 23 → REDIRECT 2223"]
        end

        subgraph honeypot["Deception services"]
            cowrie["cowrie.service<br/>user: cowrie<br/>:2222 SSH · :2223 Telnet<br/>persona: kd-api-prod01, Debian 11"]
            nginx["nginx<br/>:80 · :443 self-signed"]
            app["cloudbait-web.service<br/>user: cloudbait<br/>127.0.0.1:8080"]
        end

        subgraph real["Real management"]
            sshd["ssh.socket → sshd<br/>:22022, key-only, no root"]
        end

        subgraph logs["Log files"]
            clog[("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")]
            wlog[("/var/log/cloudbait/web.json")]
            sys[("syslog / journald")]
        end

        ama["Azure Monitor Agent<br/>mdsd + fluent-bit"]
    end

    r22 --> cowrie
    r23 --> cowrie
    nginx -- "X-Forwarded-For" --> app
    cowrie --> clog
    app --> wlog
    sshd --> sys
    clog --> ama
    wlog --> ama
    sys --> ama
```

Hardening details:

- Cowrie and the web app run as unprivileged users. Their systemd units use `NoNewPrivileges` and `ProtectSystem=strict`, and can write only to their own log directories.
- The web app uses only the Python standard library, so there are no third-party packages to exploit.
- Nothing on the box is real: the "customer", "employee" and "transaction" files contain placeholder IDs, and `.env` has no secrets.

## Network boundaries

```mermaid
flowchart LR
    inet(["Internet"])
    admin(["Admin IP"])
    vm["cb-vm-01"]
    azmon(["Azure Monitor<br/>AzureResourceManager<br/>Entra ID"])

    inet -- "✅ 22, 23, 80, 443<br/>Honeypot-Ingress · pri 200" --> vm
    admin -- "✅ 22022<br/>Allow-Admin-SSH · pri 100" --> vm
    inet -- "❌ everything else<br/>default deny" --x vm

    vm -- "✅ Allow-AzureMonitor-Out · 100<br/>✅ Allow-AzureRM-Out · 110<br/>✅ Allow-Entra-Out · 120" --> azmon
    vm -- "❌ Deny-Internet-Out · 4000" --x inet
```

The outbound deny matters most. A compromised honeypot can't be used to attack anyone else, and Cowrie's emulated `wget`/`curl` can't pull payloads. The attempted commands and URLs are still logged.

Known gap: DNS lookups go through Azure's platform resolver (168.63.129.16), which NSGs can't filter. That's acceptable for a short experiment.

## Identity model

```mermaid
flowchart LR
    attacker(["Attacker with root on the VM"]) --> imds["IMDS 169.254.169.254"]
    imds --> token["Managed identity token"]
    token --> arm["Azure Resource Manager"]
    arm --> result["403 everywhere<br/>0 role assignments"]
```

This is a lesson for the talk: *a workload should have only the permissions it needs.* This one needs none.
