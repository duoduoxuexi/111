#!/bin/bash

# Function to print characters with delay
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}
#notice
show_notice() {
    local message="$1"
    echo "#######################################################################################################################"
    echo "                                                                                                                       "
    printf "                                %s\n" "${message}"
    echo "                                                                                                                       "
    echo "#######################################################################################################################"
}
# Introduction animation
print_with_delay "sing-reality-hy2-box (Dual IP & Cloudflared MOD)" 0.05
echo ""

# install base
install_base(){
  if ! command -v jq &> /dev/null; then
      echo "jq is not installed. Installing..."
      if [ -n "$(command -v apt)" ]; then
          apt-get update > /dev/null 2>&1
          apt-get install -y jq > /dev/null 2>&1
      elif [ -n "$(command -v yum)" ]; then
          yum install -y epel-release; yum install -y jq
      elif [ -n "$(command -v dnf)" ]; then
          dnf install -y jq
      else
          echo "Cannot install jq. Please install jq manually and rerun the script."; exit 1
      fi
  fi
}

# --- MOD START: Function to detect and select IPs ---
select_ips() {
    all_ips=$(hostname -I | tr ' ' '\n' | grep -v '127.0.0.1' | grep -E '^[0-9]' | grep -v '^172\.' | grep -v '^10\.')
    ip_count=$(echo "$all_ips" | wc -l)

    if [ "$ip_count" -lt 2 ]; then
        show_notice "此脚本为双IP服务器定制, 但只检测到 $ip_count 个公网IP. 将使用此IP作为单IP运行."
        IP_A=$(echo "$all_ips")
        IP_B=$IP_A
        return
    fi

    show_notice "检测到多个公网IP，请选择主副IP"
    
    echo "请选择主IP (IP_A), 用于生成默认链接:"
    select ip in $all_ips; do
        if [ -n "$ip" ]; then IP_A=$ip; break; else echo "无效选择，请重试。"; fi
    done
    echo "主IP (IP_A) 设置为: $IP_A"

    remaining_ips=$(echo "$all_ips" | grep -v "$IP_A")
    if [ -z "$remaining_ips" ]; then
        IP_B=$IP_A
        echo "只有一个IP，辅助IP与主IP相同。"
    else
        echo -e "\n请选择辅助IP (IP_B), 用于生成第二个链接:"
        select ip in $remaining_ips; do
            if [ -n "$ip" ]; then IP_B=$ip; break; else echo "无效选择，请重试。"; fi
        done
        echo "辅助IP (IP_B) 设置为: $IP_B"
    fi
    echo ""
}
# --- MOD END ---

regenarte_cloudflared_argo(){
  pid=$(pgrep -f cloudflared)
  if [ -n "$pid" ]; then kill "$pid"; fi
  vmess_port=$(jq -r '.inbounds[] | select(.tag=="vmess-in") .listen_port' /root/sbox/sbconfig_server.json)
  /root/sbox/cloudflared-linux tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol h2mux > argo.log 2>&1 &
  sleep 5
  echo "等待Cloudflare Argo生成地址..."
  sleep 5
  argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
  echo "$argo" | base64 > /root/sbox/argo.txt.b64
  rm -rf argo.log
}

download_singbox(){
  arch=$(uname -m)
  case ${arch} in
      x86_64) arch="amd64" ;; aarch64) arch="arm64" ;; armv7l) arch="armv7" ;;
  esac
  latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | grep -Po '"tag_name": "\K.*?(?=")' | sort -V | tail -n 1)
  latest_version=${latest_version_tag#v}
  echo "Downloading Sing-box v$latest_version for $arch..."
  package_name="sing-box-${latest_version}-linux-${arch}"
  url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
  curl -sLo "/root/${package_name}.tar.gz" "$url"
  tar -xzf "/root/${package_name}.tar.gz" -C /root && mv "/root/${package_name}/sing-box" /root/sbox/
  rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"
  chmod +x /root/sbox/sing-box
}

download_cloudflared(){
  arch=$(uname -m)
  case ${arch} in
      x86_64) cf_arch="amd64" ;; aarch64) cf_arch="arm64" ;; armv7l) cf_arch="arm" ;;
  esac
  echo "Downloading Cloudflared for $cf_arch..."
  cf_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cf_arch}"
  curl -sLo "/root/sbox/cloudflared-linux" "$cf_url"
  chmod +x /root/sbox/cloudflared-linux
}

show_client_configuration() {
  # --- MOD START: Get IPs and other configs ---
  IP_A=$(jq -r '.inbounds[] | select(.tag=="vless-in-A") .listen' /root/sbox/sbconfig_server.json)
  IP_B=$(jq -r '.inbounds[] | select(.tag=="vless-in-B") .listen' /root/sbox/sbconfig_server.json)

  listen_port=$(jq -r '.inbounds[] | select(.tag=="vless-in-A") .listen_port' /root/sbox/sbconfig_server.json)
  server_name=$(jq -r '.inbounds[] | select(.tag=="vless-in-A") .tls.server_name' /root/sbox/sbconfig_server.json)
  uuid=$(jq -r '.inbounds[] | select(.tag=="vless-in-A") .users[0].uuid' /root/sbox/sbconfig_server.json)
  public_key=$(base64 --decode /root/sbox/public.key.b64)
  short_id=$(jq -r '.inbounds[] | select(.tag=="vless-in-A") .tls.reality.short_id[0]' /root/sbox/sbconfig_server.json)
  
  hy_listen_port=$(jq -r '.inbounds[] | select(.tag=="hy2-in-A") .listen_port' /root/sbox/sbconfig_server.json)
  hy_server_name=$(openssl x509 -in /root/self-cert/cert.pem -noout -subject -nameopt RFC2253 | awk -F'=' '{print $NF}')
  hy_password=$(jq -r '.inbounds[] | select(.tag=="hy2-in-A") .users[0].password' /root/sbox/sbconfig_server.json)

  argo=$(base64 --decode /root/sbox/argo.txt.b64)
  vmess_uuid=$(jq -r '.inbounds[] | select(.tag=="vmess-in") .users[0].uuid' /root/sbox/sbconfig_server.json)
  ws_path=$(jq -r '.inbounds[] | select(.tag=="vmess-in") .transport.path' /root/sbox/sbconfig_server.json)
  
  link_vless_A="vless://$uuid@$IP_A:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp#$IP_A-VLESS"
  link_vless_B="vless://$uuid@$IP_B:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp#$IP_B-VLESS"
  link_hy2_A="hysteria2://$hy_password@$IP_A:$hy_listen_port?insecure=1&sni=$hy_server_name#$IP_A-HY2"
  link_hy2_B="hysteria2://$hy_password@$IP_B:$hy_listen_port?insecure=1&sni=$hy_server_name#$IP_B-HY2"
  link_vmess_ws='vmess://'$(echo '{"add":"speed.cloudflare.com","aid":"0","host":"'$argo'","id":"'$vmess_uuid'","net":"ws","path":"'$ws_path'","port":"443","ps":"CF-VMESS","tls":"tls","type":"none","v":"2"}' | base64 -w 0)
  
  show_notice "主IP ($IP_A) 直连节点"
  echo "VLESS Reality: $link_vless_A"
  echo "Hysteria2:     $link_hy2_A"

  if [ "$IP_A" != "$IP_B" ]; then
    show_notice "辅助IP ($IP_B) 直连节点"
    echo "VLESS Reality: $link_vless_B"
    echo "Hysteria2:     $link_hy2_B"
  fi

  show_notice "通用 Cloudflare Vmess 隧道节点 (隐藏IP)"
  echo "Vmess+WS:      $link_vmess_ws"
  
  show_notice "双IP Clash.Meta 配置文件"
cat << EOF
port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns: {enable: true, listen: :53, enhanced-mode: redir-host, nameserver: [8.8.8.8, 1.1.1.1]}

proxies:
  - {name: VLESS-$IP_A, type: vless, server: $IP_A, port: $listen_port, uuid: $uuid, tls: true, servername: $server_name, flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: $public_key, short-id: $short_id}}
  - {name: VLESS-$IP_B, type: vless, server: $IP_B, port: $listen_port, uuid: $uuid, tls: true, servername: $server_name, flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: $public_key, short-id: $short_id}}
  - {name: HY2-$IP_A, type: hysteria2, server: $IP_A, port: $hy_listen_port, password: $hy_password, sni: $hy_server_name, skip-cert-verify: true}
  - {name: HY2-$IP_B, type: hysteria2, server: $IP_B, port: $hy_listen_port, password: $hy_password, sni: $hy_server_name, skip-cert-verify: true}
  - {name: CF-VMESS, type: vmess, server: speed.cloudflare.com, port: 443, uuid: $vmess_uuid, alterId: 0, cipher: auto, tls: true, servername: $argo, network: ws, ws-opts: {path: "$ws_path", headers: {Host: $argo}}}

proxy-groups:
  - {name: 节点选择, type: select, proxies: [VLESS-$IP_A, VLESS-$IP_B, HY2-$IP_A, HY2-$IP_B, CF-VMESS, DIRECT]}

rules:
    - GEOIP,CN,DIRECT
    - MATCH,节点选择
EOF
}

uninstall_singbox() {
    echo "Uninstalling..."
    systemctl stop sing-box
    systemctl disable sing-box > /dev/null 2>&1
    pid=$(pgrep -f cloudflared)
    if [ -n "$pid" ]; then kill "$pid"; fi
    rm -f /etc/systemd/system/sing-box.service
    rm -rf /root/sbox/ /root/self-cert/
    echo "DONE!"
}

install_base

if [ -f "/root/sbox/sbconfig_server.json" ]; then
    echo "sing-box-reality-hysteria2已安装"
    echo "1. 重新安装"
    echo "2. 显示客户端配置"
    echo "3. 卸载"
    echo "4. 更新sing-box内核"
    echo "5. 重启Cloudflared隧道"
    read -p "Enter your choice: " choice
    case $choice in
        1) uninstall_singbox ;;
        2) show_client_configuration; exit 0 ;;
        3) uninstall_singbox; exit 0 ;;
        4) download_singbox; systemctl restart sing-box; echo "内核已更新并重启"; exit 0 ;;
        5) regenarte_cloudflared_argo; echo "隧道已重启"; show_client_configuration; exit 0 ;;
        *) echo "无效选择."; exit 1 ;;
    esac
fi

mkdir -p /root/sbox/ /root/self-cert/

# --- MOD: Call IP selection function ---
select_ips

download_singbox
download_cloudflared

key_pair=$(/root/sbox/sing-box generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
echo "$public_key" | base64 > /root/sbox/public.key.b64
uuid=$(/root/sbox/sing-box generate uuid)
short_id=$(/root/sbox/sing-box generate rand --hex 8)
hy_password=$(/root/sbox/sing-box generate rand --hex 8)
vmess_uuid=$(/root/sbox/sing-box generate uuid)
ws_path=$(/root/sbox/sing-box generate rand --hex 6)

read -p "Enter Reality port (default: 443): " listen_port; listen_port=${listen_port:-443}
read -p "Enter Reality SNI (default: itunes.apple.com): " server_name; server_name=${server_name:-itunes.apple.com}
read -p "Enter Hysteria2 port (default: 8443): " hy_listen_port; hy_listen_port=${hy_listen_port:-8443}
read -p "Enter Hysteria2 cert domain (default: bing.com): " hy_server_name; hy_server_name=${hy_server_name:-bing.com}
read -p "Enter Vmess port for tunnel (default: 15555): " vmess_port; vmess_port=${vmess_port:-15555}

openssl ecparam -genkey -name prime256v1 -out /root/self-cert/private.key && openssl req -new -x509 -days 36500 -key /root/self-cert/private.key -out /root/self-cert/cert.pem -subj "/CN=${hy_server_name}"

/root/sbox/cloudflared-linux tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol h2mux > argo.log 2>&1 &
sleep 5
echo "等待Cloudflare Argo生成地址..."
sleep 5
argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
echo "$argo" | base64 > /root/sbox/argo.txt.b64
rm -rf argo.log

# --- MOD START: Create server config with dual IP and marks ---
jq -n \
  --arg listen_port "$listen_port" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" --arg uuid "$uuid" \
  --arg hy_listen_port "$hy_listen_port" --arg hy_password "$hy_password" \
  --arg vmess_port "$vmess_port" --arg vmess_uuid "$vmess_uuid" --arg ws_path "$ws_path" \
  --arg ip_a "$IP_A" --arg ip_b "$IP_B" \
'{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless", "tag": "vless-in-A", "listen": $ip_a, "listen_port": ($listen_port | tonumber), "sniff": true, "sockopt": { "mark": 1 },
      "users": [ { "uuid": $uuid, "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": $server_name, "reality": { "enabled": true, "handshake": { "server": $server_name, "server_port": 443 }, "private_key": $private_key, "short_id": [$short_id] } }
    },
    {
      "type": "vless", "tag": "vless-in-B", "listen": $ip_b, "listen_port": ($listen_port | tonumber), "sniff": true, "sockopt": { "mark": 2 },
      "users": [ { "uuid": $uuid, "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": $server_name, "reality": { "enabled": true, "handshake": { "server": $server_name, "server_port": 443 }, "private_key": $private_key, "short_id": [$short_id] } }
    },
    {
      "type": "hysteria2", "tag": "hy2-in-A", "listen": $ip_a, "listen_port": ($hy_listen_port | tonumber), "sockopt": { "mark": 1 },
      "users": [ { "password": $hy_password } ],
      "tls": { "enabled": true, "alpn": [ "h3" ], "certificate_path": "/root/self-cert/cert.pem", "key_path": "/root/self-cert/private.key" }
    },
    {
      "type": "hysteria2", "tag": "hy2-in-B", "listen": $ip_b, "listen_port": ($hy_listen_port | tonumber), "sockopt": { "mark": 2 },
      "users": [ { "password": $hy_password } ],
      "tls": { "enabled": true, "alpn": [ "h3" ], "certificate_path": "/root/self-cert/cert.pem", "key_path": "/root/self-cert/private.key" }
    },
    {
      "type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1", "listen_port": ($vmess_port | tonumber),
      "users": [ { "uuid": $vmess_uuid, "alterId": 0 } ],
      "transport": { "type": "ws", "path": $ws_path }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "rules": [ { "protocol": "dns", "outbound": "direct" } ], "final": "direct" }
}' > /root/sbox/sbconfig_server.json
# --- MOD END ---

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
    echo "Configuration checked successfully. Starting sing-box service..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    show_client_configuration
else
    echo "Error in configuration. Aborting"
fi