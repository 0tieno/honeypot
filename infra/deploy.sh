#!/usr/bin/env bash
# Operation: Cloud Bait - Azure infrastructure.
# Usage: infra/deploy.sh <phase>
#   network   resource group, VNet, NSG (locked to MY_IP), public IP
#   vm        Ubuntu VM (no role assignments, no peering)
#   monitor   Log Analytics, custom tables, DCE, DCR, AMA
#   egress    deny outbound Internet except Azure Monitor
#   expose    open honeypot ports (22,23,80,443) to the Internet
#   status    show NSG rules and IPs
set -euo pipefail
set -f  # port lists like "22 23" are word-split on purpose; '*' must not glob

RG=cloud-bait-rg
LOC=${LOC:-southafricanorth}
VNET=cb-vnet; SUBNET=cb-subnet; NSG=cb-nsg; PIP=cb-public-ip; VM=cb-vm-01
LAW=cb-law; DCE=cb-dce; DCR=cb-dcr
ADMIN_USER=cloudbaitadmin; ADMIN_PORT=22022
VM_SIZE=${VM_SIZE:-Standard_B2als_v2}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="$ROOT/keys/cloudbait_ed25519"
MY_IP=${MY_IP:-$(curl -s https://api.ipify.org)}
TAGS="project=cloud-bait purpose=honeypot delete-after=2026-10-16"

rule() { # name priority direction access ports source dest
    az network nsg rule create -g "$RG" --nsg-name "$NSG" -n "$1" --priority "$2" \
        --direction "$3" --access "$4" --protocol "${8:-Tcp}" --destination-port-ranges $5 \
        --source-address-prefixes "$6" --destination-address-prefixes "$7" -o none
}

case "${1:-}" in
network)
    az group create -n "$RG" -l "$LOC" --tags $TAGS -o none
    az network nsg create -g "$RG" -n "$NSG" -l "$LOC" --tags $TAGS -o none
    rule Allow-Admin-SSH      100 Inbound Allow "$ADMIN_PORT" "$MY_IP" '*'
    # Real sshd sits on 22 until setup.sh moves it; 22/23/80/443 are tester-only until "expose".
    rule Honeypot-Ingress     200 Inbound Allow "22 23 80 443" "$MY_IP" '*'
    az network vnet create -g "$RG" -n "$VNET" -l "$LOC" --address-prefixes 10.50.0.0/16 \
        --subnet-name "$SUBNET" --subnet-prefixes 10.50.1.0/24 --tags $TAGS -o none
    az network public-ip create -g "$RG" -n "$PIP" -l "$LOC" --sku Standard \
        --allocation-method Static --tags $TAGS -o none
    ;;
vm)
    mkdir -p "$ROOT/keys"
    [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C cloudbait-admin -f "$KEY"
    az vm create -g "$RG" -n "$VM" -l "$LOC" --image Canonical:ubuntu-24_04-lts:server:latest \
        --size "$VM_SIZE" --admin-username "$ADMIN_USER" --ssh-key-values "$(cat "$KEY.pub")" \
        --vnet-name "$VNET" --subnet "$SUBNET" --public-ip-address "$PIP" \
        --nsg "$NSG" --security-type Standard --os-disk-size-gb 30 \
        --storage-sku StandardSSD_LRS --tags $TAGS -o table
    ;;
monitor)
    ARM=https://management.azure.com
    SUB=$(az account show --query id -o tsv)
    INS="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights"
    WIN_ROOT=$(cygpath -m "$ROOT")
    az monitor log-analytics workspace create -g "$RG" -n "$LAW" -l "$LOC" \
        --retention-time 30 --tags $TAGS -o none
    LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)
    for t in CowrieLogs_CL CloudBaitWeb_CL; do
        az rest --method put --url "$ARM${LAW_ID}/tables/${t}?api-version=2022-10-01" \
            --body @"$WIN_ROOT/infra/table-${t}.json" -o none
    done
    DCE_ID="$INS/dataCollectionEndpoints/$DCE"
    az rest --method put --url "$ARM$DCE_ID?api-version=2023-03-11" \
        --body "{\"location\":\"$LOC\",\"properties\":{\"networkAcls\":{\"publicNetworkAccess\":\"Enabled\"}}}" -o none
    sed -e "s#__LOC__#$LOC#g" -e "s#__DCE_ID__#$DCE_ID#g" -e "s#__LAW_ID__#$LAW_ID#g" \
        "$ROOT/infra/dcr.template.json" > "$ROOT/infra/.dcr.rendered.json"
    DCR_ID="$INS/dataCollectionRules/$DCR"
    az rest --method put --url "$ARM$DCR_ID?api-version=2023-03-11" \
        --body @"$WIN_ROOT/infra/.dcr.rendered.json" -o none
    # AMA authenticates with a system-assigned identity. It gets NO role assignments.
    az vm identity assign -g "$RG" -n "$VM" -o none
    az vm extension set -g "$RG" --vm-name "$VM" --name AzureMonitorLinuxAgent \
        --publisher Microsoft.Azure.Monitor --enable-auto-upgrade true -o none
    VM_ID=$(az vm show -g "$RG" -n "$VM" --query id -o tsv)
    ASSOC="$ARM$VM_ID/providers/Microsoft.Insights/dataCollectionRuleAssociations"
    az rest --method put --url "$ASSOC/configurationAccessEndpoint?api-version=2023-03-11" \
        --body "{\"properties\":{\"dataCollectionEndpointId\":\"$DCE_ID\"}}" -o none
    az rest --method put --url "$ASSOC/cb-dcr-assoc?api-version=2023-03-11" \
        --body "{\"properties\":{\"dataCollectionRuleId\":\"$DCR_ID\"}}" -o none
    ;;
egress)
    rule Allow-AzureMonitor-Out  100 Outbound Allow '*' VirtualNetwork AzureMonitor '*'
    rule Allow-AzureRM-Out       110 Outbound Allow 443 VirtualNetwork AzureResourceManager
    rule Allow-Entra-Out         120 Outbound Allow 443 VirtualNetwork AzureActiveDirectory
    rule Deny-Internet-Out      4000 Outbound Deny  '*' '*' Internet '*'
    ;;
egress-open) # temporary, for apt/pip during maintenance
    az network nsg rule delete -g "$RG" --nsg-name "$NSG" -n Deny-Internet-Out
    ;;
dashboard)
    LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)
    SUB=$(az account show --query id -o tsv)
    node "$(cygpath -m "$ROOT")/infra/workbook.js" "$LAW_ID" "$LOC" > "$ROOT/infra/.workbook.rendered.json"
    az rest --method put --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks/e388bfce-0a3e-447d-8af0-cb2cd0e43046?api-version=2022-04-01"         --body @"$(cygpath -m "$ROOT")/infra/.workbook.rendered.json" -o none
    echo "Workbook: https://portal.azure.com/#@/resource/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks/e388bfce-0a3e-447d-8af0-cb2cd0e43046/workbook"
    ;;
expose)
    az network nsg rule update -g "$RG" --nsg-name "$NSG" -n Honeypot-Ingress \
        --source-address-prefixes Internet -o none
    T=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "EXPOSED at $T" | tee -a "$ROOT/EXPOSURE_TIME.txt"
    set +f; sed -i "s/^let exposed = todatetime(\"[^\"]*\")/let exposed = todatetime(\"$T\")/" "$ROOT"/queries/*.kql
    "$0" dashboard
    ;;
status)
    az network nsg rule list -g "$RG" --nsg-name "$NSG" \
        --query "sort_by([],&priority)[].{name:name,pri:priority,dir:direction,access:access,ports:join(',',destinationPortRanges||[destinationPortRange]),src:sourceAddressPrefix||join(',',sourceAddressPrefixes),dst:destinationAddressPrefix}" -o table
    az network public-ip show -g "$RG" -n "$PIP" --query ipAddress -o tsv
    ;;
*) sed -n '2,12p' "$0"; exit 1 ;;
esac
