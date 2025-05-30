#!/bin/bash

# ========================
# 配置参数
# ========================
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
FIXED_IFACE="wg0"
LOG_FILE="/var/log/wireguard-lite.log"
ROUTE_MAPPING="$CONFIG_DIR/route_mappings.json"

# ========================
# 初始化函数
# ========================
init_resources() {
    [ ! -f "$PUBLIC_IP_FILE" ] && detect_public_ips
    touch "$USED_IP_FILE"
    [ ! -f "$ROUTE_MAPPING" ] && echo "{}" > "$ROUTE_MAPPING"
}

# ========================
# 公网IP自动检测
# ========================
detect_public_ips() {
    echo "正在自动检测公网IP..."
    log "开始检测公网IP"
    
    local public_ips=()
    while IFS= read -r ip; do
        IFS=. read -r a b c d <<< "$ip"
        private=false
        [[ $a -eq 10 ]] && private=true
        [[ $a -eq 172 && $b -ge 16 && $b -le 31 ]] && private=true
        [[ $a -eq 192 && $b -eq 168 ]] && private=true
        [[ $a -eq 127 ]] && private=true
        [[ $a -eq 169 && $b -eq 254 ]] && private=true

        if ! $private; then
            public_ips+=("$ip")
        fi
    done < <(ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)

    if [ ${#public_ips[@]} -eq 0 ]; then
        log "尝试通过metadata获取云厂商公网IP"
        cloud_ip=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 || true)
        [ -n "$cloud_ip" ] && public_ips+=("$cloud_ip")
    fi

    if [ ${#public_ips[@]} -gt 0 ]; then
        printf "%s\n" "${public_ips[@]}" > "$PUBLIC_IP_FILE"
        echo "检测到公网IP：${public_ips[*]}"
        log "公网IP已保存"
    else
        echo "错误: 未检测到公网IP，请手动创建 $PUBLIC_IP_FILE"
        log "公网IP检测失败"
        exit 1
    fi
}

# ========================
# 通用功能函数
# ========================
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

validate_subnet() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || {
        echo "错误: 子网格式无效（示例：192.168.1.0/24）"
        return 1
    }
}

show_remaining_public_ips() {
    remaining=($(comm -23 <(sort "$PUBLIC_IP_FILE") <(sort "$USED_IP_FILE")))
    echo "剩余可用公网IP数量: ${#remaining[@]}"
}

# ========================
# 依赖安装
# ========================
install_dependencies() {
    echo "正在安装依赖..."
    log "开始安装依赖"
    export DEBIAN_FRONTEND=noninteractive

    add-apt-repository -y ppa:wireguard/wireguard >/dev/null 2>&1
    apt-get update >/dev/null 2>&1
    apt-get install -y --install-recommends \
        wireguard-tools iptables iptables-persistent \
        sipcalc qrencode curl iftop jq >/dev/null 2>&1 || { 
        echo "错误: 依赖安装失败"
        log "依赖安装失败"
        exit 1
    }

    systemctl enable --now netfilter-persistent >/dev/null 2>&1

    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1

    echo "系统配置完成！"
    log "依赖安装完成"
}

# ========================
# IP分配管理
# ========================
allocate_public_ips() {
    local count=$1
    available=($(comm -23 <(sort "$PUBLIC_IP_FILE") <(sort "$USED_IP_FILE")))
    [ ${#available[@]} -lt $count ] && {
        echo "错误: 公网IP不足（需要 $count，剩余 ${#available[@]}）"
        return 1
    }
    ips=($(shuf -e "${available[@]}" -n $count))
    printf "%s\n" "${ips[@]}" >> "$USED_IP_FILE"
    echo "${ips[@]}"
}

# ========================
# 核心功能函数
# ========================
create_interface() {
    init_resources
    echo "正在创建WireGuard接口..."
    log "创建接口开始"

    [ -f "$CONFIG_DIR/$FIXED_IFACE.conf" ] && {
        echo "错误: 接口已存在"
        return 1
    }

    read -p "请输入服务器私有IP地址（例如10.0.0.1）: " server_ip
    [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo "错误: IP地址格式无效"
        return 1
    }

    # 确保服务器IP以/24结尾
    [[ "$server_ip" =~ /[0-9]+$ ]] || server_ip="$server_ip/24"

    ext_if=$(ip route show default | awk '/default/ {print $5; exit}')
    port=$(shuf -i 51620-52000 -n 1)
    server_private=$(wg genkey)

    # 修复：添加NAT规则
    cat > "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF
[Interface]
Address = $server_ip
PrivateKey = $server_private
ListenPort = $port
# 由系统内核处理路由转发
PostUp = iptables -t nat -A POSTROUTING -o $ext_if -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o $ext_if -j MASQUERADE
EOF

    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf"
    systemctl enable --now "wg-quick@$FIXED_IFACE" >/dev/null && {
        echo "接口创建成功！"
        log "接口创建成功"
    } || {
        echo "错误: 服务启动失败"
        rm -f "$CONFIG_DIR/$FIXED_IFACE.conf"
        return 1
    }
}

# ========================
# 添加客户端（路由器）
# ========================
add_client() {
    echo "正在添加路由型客户端..."
    log "添加路由型客户端开始"
    [ ! -f "$CONFIG_DIR/$FIXED_IFACE.conf" ] && {
        echo "错误: 请先创建接口"
        return 1
    }

    read -p "客户端名称（例如office-router）: " client_name
    [[ "$client_name" =~ [/\\] ]] && {
        echo "错误: 名称包含非法字符"
        return 1
    }

    read -p "请输入客户端需路由的子网（例如192.168.1.0/24）: " client_subnet
    validate_subnet "$client_subnet" || return 1

    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    server_public=$(wg show "$FIXED_IFACE" public-key)

    server_subnet=$(grep 'Address' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk -F= '{print $2}' | tr -d ' ')
    base_net=$(echo $server_subnet | cut -d'/' -f1 | sed 's/\.[0-9]*$//')
    
    # 修复：获取所有已使用的隧道IP（包括服务器IP）
    used_ips=(
        $(grep 'Address' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk -F= '{print $2}' | cut -d'/' -f1)
        $(grep 'AllowedIPs' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk -F= '{print $2}' | tr ',' '\n' | awk '{print $1}' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    )
    
    # 查找可用的隧道IP（从.2开始）
    for i in {2..254}; do
        candidate_ip="${base_net}.$i"
        if ! printf '%s\n' "${used_ips[@]}" | grep -q "^${candidate_ip}$"; then
            client_tunnel_ip="$candidate_ip"
            break
        fi
    done
    
    [ -z "$client_tunnel_ip" ] && {
        echo "错误: 找不到可用的隧道IP地址"
        return 1
    }

    # 修复：在服务器配置中添加Peer
    {
        echo -e "\n[Peer]"
        echo "PublicKey = $client_public"
        echo "AllowedIPs = $client_subnet, $client_tunnel_ip/32"
    } >> "$CONFIG_DIR/$FIXED_IFACE.conf"

    mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
    client_file="$CLIENT_DIR/$FIXED_IFACE/$client_name.conf"
    
    server_port=$(grep 'ListenPort' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk -F= '{print $2}' | tr -d ' ')
    server_public_ip=$(head -n 1 "$PUBLIC_IP_FILE")

    # 修复：客户端配置使用正确的隧道IP
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_tunnel_ip/32

[Peer]
PublicKey = $server_public
Endpoint = ${server_public_ip}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    qrencode -t ansiutf8 < "$client_file"
    chmod 600 "$client_file"

    wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE") >/dev/null
    echo "路由型客户端添加成功！"
    echo "客户端子网: $client_subnet"
    echo "隧道端点IP: $client_tunnel_ip（仅用于建立连接）"
    log "路由型客户端 $client_name 添加成功"
}

# ========================
# 下游设备管理（使用SNAT）
# ========================
add_downstream() {
    echo "正在添加下游设备（SNAT）..."
    log "添加下游设备开始"
    [ ! -f "$CONFIG_DIR/$FIXED_IFACE.conf" ] && {
        echo "错误: 请先创建接口"
        return 1
    }

    read -p "输入客户端子网（例如192.168.1.0/24）: " client_subnet
    validate_subnet "$client_subnet" || return 1

    read -p "需要分配的公网IP数量: " ip_count
    [[ "$ip_count" =~ ^[0-9]+$ ]] || {
        echo "错误: 请输入有效数字"
        return 1
    }

    public_ips=($(allocate_public_ips "$ip_count")) || {
        echo "$public_ips"
        return 1
    }

    base_ip=$(echo "$client_subnet" | awk -F'[./]' '{print $1"."$2"."$3"."}')
    mappings=()

    for i in $(seq 2 $((ip_count+1))); do
        downstream_ip="${base_ip}${i}"
        public_ip="${public_ips[$((i-2))]}"

        # 添加SNAT规则
        iptables -t nat -A POSTROUTING -s "$downstream_ip" -j SNAT --to-source "$public_ip"
        mappings+=("$downstream_ip:$public_ip")
    done

    # 保存规则
    netfilter-persistent save >/dev/null

    # 更新映射文件
    for map in "${mappings[@]}"; do
        dip=$(echo "$map" | cut -d: -f1)
        pub=$(echo "$map" | cut -d: -f2)
        jq --arg dip "$dip" --arg pub "$pub" \
           '. + { ($dip): $pub }' "$ROUTE_MAPPING" > tmp.json && mv tmp.json "$ROUTE_MAPPING"
    done

    echo "下游设备添加成功！"
    echo "子网: $client_subnet"
    echo "分配的公网IP: ${public_ips[@]}"
    show_remaining_public_ips
    log "添加下游设备完成"
}

delete_downstream() {
    echo "正在删除下游设备（SNAT）..."
    log "删除下游设备开始"
    read -p "输入下游设备私有IP（或输入 all 删除所有）: " downstream_ip

    if [ "$downstream_ip" = "all" ]; then
        jq -r 'keys[]' "$ROUTE_MAPPING" | while read -r dip; do
            public_ip=$(jq -r ".\"$dip\"" "$ROUTE_MAPPING")
            # 删除SNAT规则
            iptables -t nat -D POSTROUTING -s "$dip" -j SNAT --to-source "$public_ip"
            sed -i "/^$public_ip$/d" "$USED_IP_FILE"
        done

        echo "{}" > "$ROUTE_MAPPING"
        echo "已删除所有下游设备"
        show_remaining_public_ips
        log "所有下游设备已删除"
    else
        public_ip=$(jq -r ".\"$downstream_ip\"" "$ROUTE_MAPPING")
        [ -z "$public_ip" ] || [ "$public_ip" = "null" ] && {
            echo "错误: 未找到映射记录"
            return 1
        }

        # 删除SNAT规则
        iptables -t nat -D POSTROUTING -s "$downstream_ip" -j SNAT --to-source "$public_ip"
        sed -i "/^$public_ip$/d" "$USED_IP_FILE"
        jq "del(.\"$downstream_ip\")" "$ROUTE_MAPPING" > tmp.json && mv tmp.json "$ROUTE_MAPPING"
        
        echo "已删除下游设备 $downstream_ip"
        show_remaining_public_ips
        log "下游设备 $downstream_ip 已删除"
    fi

    # 保存规则
    netfilter-persistent save >/dev/null
}

# ========================
# 状态管理
# ========================
show_mappings() {
    echo "当前路由映射状态："
    jq -r 'to_entries[] | "\(.key) => \(.value)"' "$ROUTE_MAPPING"
    [ $(jq length "$ROUTE_MAPPING") -eq 0 ] && echo "无映射记录"
}

restart_interface() {
    systemctl restart "wg-quick@$FIXED_IFACE" && echo "接口已重启" || echo "接口重启失败"
}

delete_interface() {
    read -p "确认删除接口？(y/N) " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    systemctl stop "wg-quick@$FIXED_IFACE"
    rm -f "$CONFIG_DIR/$FIXED_IFACE.conf"
    echo "接口已删除"
}

uninstall_wireguard() {
    read -p "确认完全卸载？(y/N) " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    systemctl stop "wg-quick@$FIXED_IFACE"
    apt-get purge -y wireguard-tools iptables-persistent qrencode jq
    rm -rf "$CONFIG_DIR"
    echo "WireGuard已卸载"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=(
        "安装依赖"
        "创建接口" 
        "添加客户端（路由器）"
        "添加下游设备"
        "删除下游设备"
        "查看路由映射"
        "重启接口"
        "删除接口"
        "完全卸载"
        "退出"
    )
    
    while true; do
        select opt in "${options[@]}"; do
            case $REPLY in
                1) install_dependencies ;;
                2) create_interface ;;
                3) add_client ;;
                4) add_downstream ;;
                5) delete_downstream ;;
                6) show_mappings ;;
                7) restart_interface ;;
                8) delete_interface ;;
                9) uninstall_wireguard ;;
                10) exit 0 ;;
                *) echo "无效选项" ;;
            esac
            break
        done
    done
}

# ========================
# 脚本入口
# ========================
mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
init_resources
main_menu