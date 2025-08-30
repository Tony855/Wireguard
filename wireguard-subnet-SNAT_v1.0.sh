#!/bin/bash

# ========================
# 配置参数
# ========================
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
LOG_FILE="/var/log/wireguard-lite.log"

# ========================
# 初始化函数
# ========================
init_resources() {
    [ ! -f "$PUBLIC_IP_FILE" ] && detect_public_ips
    touch "$USED_IP_FILE"
    
    # 为每个接口初始化路由映射文件
    for iface_conf in "$CONFIG_DIR"/*.conf; do
        [ ! -f "$iface_conf" ] && continue
        iface=$(basename "$iface_conf" .conf)
        local route_mapping="$CONFIG_DIR/route_mappings_${iface}.json"
        [ ! -f "$route_mapping" ] && echo "{}" > "$route_mapping"
    done
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
# 接口管理函数
# ========================
list_interfaces() {
    ls /etc/wireguard/*.conf 2>/dev/null | sed 's/.*\///; s/\.conf$//' | grep -v '^wg-snat-restore$'
}

select_interface() {
    local interfaces=($(list_interfaces))
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo "没有可用的WireGuard接口，请先创建一个。"
        return 1
    fi

    PS3="请选择接口: "
    select iface in "${interfaces[@]}" "返回主菜单"; do
        if [[ $REPLY -ge 1 && $REPLY -le ${#interfaces[@]} ]]; then
            selected_iface="${interfaces[$((REPLY-1))]}"
            break
        elif [[ $REPLY -eq $((${#interfaces[@]}+1)) ]]; then
            return 2
        else
            echo "无效的选择，请重新输入。"
        fi
    done
    
    echo "$selected_iface"
    return 0
}

get_route_mapping() {
    local iface=$1
    echo "$CONFIG_DIR/route_mappings_${iface}.json"
}

# ========================
# 规则持久化管理
# ========================
install_persistence() {
    # 创建规则恢复脚本（使用新版本）
    cat > /usr/local/bin/restore-wg-snat.sh <<'EOF'
#!/bin/bash
CONFIG_DIR="/etc/wireguard"
LOG_FILE="/var/log/wireguard-lite.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 只在必要时恢复SNAT规则（后台执行，不阻塞wg-quick）
restore_snat_rules() {
    for route_mapping in "$CONFIG_DIR"/route_mappings_*.json; do
        [ ! -f "$route_mapping" ] && continue
        
        iface=$(basename "$route_mapping" | sed 's/route_mappings_//; s/\.json//')
        
        jq -r 'to_entries[] | "\(.key) \(.value)"' "$route_mapping" | while read -r dip pub; do
            if ! iptables -t nat -C POSTROUTING -s "$dip" -j SNAT --to-source "$pub" 2>/dev/null; then
                log "恢复丢失的SNAT规则[$iface]: $dip => $pub"
                iptables -t nat -I POSTROUTING 1 -s "$dip" -j SNAT --to-source "$pub"
            fi
        done
    done
}

# 主执行函数（在后台运行）
main() {
    # 恢复SNAT规则
    restore_snat_rules
    
    # 确保所有WireGuard接口运行
    for iface_conf in /etc/wireguard/*.conf; do
        iface_name=$(basename "$iface_conf" .conf)
        if [[ "$iface_name" == "wg-snat-restore" ]]; then
            continue
        fi
        
        # 检查接口是否运行
        if ! ip link show "$iface_name" >/dev/null 2>&1; then
            log "启动WireGuard接口: $iface_name"
            systemctl start "wg-quick@$iface_name" 2>/dev/null || true
        fi
    done
    
    # 保存iptables规则
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

# 在后台运行主函数
main &
EOF

    chmod +x /usr/local/bin/restore-wg-snat.sh
    
    # 添加定时任务（每5分钟检查一次）
    if ! crontab -l 2>/dev/null | grep -q "restore-wg-snat.sh"; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/restore-wg-snat.sh") | crontab -
        log "添加SNAT规则监控定时任务"
    fi
    
    # 启动时恢复规则
    cat > /etc/systemd/system/wg-snat-restore.service <<EOF
[Unit]
Description=Restore WireGuard SNAT Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/restore-wg-snat.sh

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable wg-snat-restore.service >/dev/null 2>&1
    log "安装SNAT规则恢复服务"
}

# ========================
# 依赖安装（支持Debian和Ubuntu）
# ========================
install_dependencies() {
    echo "正在安装依赖..."
    log "开始安装依赖"
    export DEBIAN_FRONTEND=noninteractive

    # 检测操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        echo "错误: 无法确定操作系统类型"
        log "无法确定操作系统类型"
        exit 1
    fi

    # 更新包列表
    apt-get update >/dev/null 2>&1 || {
        echo "错误: 无法更新包列表"
        log "更新包列表失败"
        exit 1
    }

    # 安装通用依赖
    apt-get install -y --no-install-recommends \
        iptables iptables-persistent \
        sipcalc qrencode curl jq cron iftop >/dev/null 2>&1
        
    # 安装WireGuard
    if [[ "$OS" == "debian" ]]; then
        echo "检测到Debian系统 $VERSION"
        
        # 对于Debian 10 (Buster) 和 11 (Bullseye)
        if [[ "$VERSION" == "10" || "$VERSION" == "11" ]]; then
            # 添加backports源
            echo "deb http://deb.debian.org/debian ${VERSION_CODENAME}-backports main" > /etc/apt/sources.list.d/backports.list
            apt-get update >/dev/null 2>&1
            apt-get install -y -t ${VERSION_CODENAME}-backports wireguard-tools >/dev/null 2>&1
        else
            # 对于Debian 12+ 或其他版本
            apt-get install -y wireguard-tools >/dev/null 2>&1
        fi
    elif [[ "$OS" == "ubuntu" ]]; then
        echo "检测到Ubuntu系统 $VERSION"
        
        # 安装PPA支持
        apt-get install -y software-properties-common >/dev/null 2>&1
        add-apt-repository -y ppa:wireguard/wireguard >/dev/null 2>&1
        apt-get update >/dev/null 2>&1
        apt-get install -y wireguard-tools >/dev/null 2>&1
    else
        echo "错误: 不支持的操作系统: $OS"
        log "不支持的操作系统: $OS"
        exit 1
    fi

    # 检查所有包是否安装成功
    local missing=()
    for pkg in wireguard-tools iptables iptables-persistent sipcalc qrencode curl jq cron iftop; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "错误: 以下依赖安装失败: ${missing[*]}"
        log "依赖安装失败: ${missing[*]}"
        exit 1
    fi

    systemctl enable --now netfilter-persistent >/dev/null 2>&1
    systemctl enable --now cron >/dev/null 2>&1

    # 配置内核参数
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1

    # 安装持久化机制
    install_persistence
    
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

    read -p "请输入接口名称（例如wg0, wg1）: " iface
    [[ "$iface" =~ ^[a-zA-Z0-9]+$ ]] || {
        echo "错误: 接口名称只能包含字母和数字"
        return 1
    }

    [ -f "$CONFIG_DIR/$iface.conf" ] && {
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

    port=$(shuf -i 51620-52000 -n 1)
    server_private=$(wg genkey)

    # 创建接口配置
    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = $server_ip
PrivateKey = $server_private
ListenPort = $port
SaveConfig = false
EOF

    chmod 600 "$CONFIG_DIR/$iface.conf"
    
    # 先尝试直接启动接口
    echo "正在启动接口 $iface..."
    if wg-quick up "$iface" 2>/dev/null; then
        echo "接口 $iface 创建成功！"
        log "接口 $iface 创建成功"
        
        # 确保服务设置为开机自启动
        systemctl enable "wg-quick@$iface" >/dev/null 2>&1
        
        # 创建接口专属目录
        mkdir -p "$CLIENT_DIR/$iface"
        
        # 初始化路由映射文件
        local route_mapping=$(get_route_mapping "$iface")
        [ ! -f "$route_mapping" ] && echo "{}" > "$route_mapping"
        
        # 添加防火墙规则允许WireGuard端口
        if ! iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            iptables-save > /etc/iptables/rules.v4
            log "添加防火墙规则允许端口: $port"
        fi
    else
        echo "错误: 接口启动失败，尝试使用systemctl..."
        
        # 尝试使用systemctl启动
        if systemctl start "wg-quick@$iface"; then
            echo "接口 $iface 创建成功！"
            log "接口 $iface 创建成功"
            
            # 确保服务设置为开机自启动
            systemctl enable "wg-quick@$iface" >/dev/null 2>&1
            
            # 创建接口专属目录
            mkdir -p "$CLIENT_DIR/$iface"
            
            # 初始化路由映射文件
            local route_mapping=$(get_route_mapping "$iface")
            [ ! -f "$route_mapping" ] && echo "{}" > "$route_mapping"
            
            # 添加防火墙规则允许WireGuard端口
            if ! iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
                iptables -A INPUT -p udp --dport "$port" -j ACCEPT
                iptables-save > /etc/iptables/rules.v4
                log "添加防火墙规则允许端口: $port"
            fi
        else
            echo "错误: 服务启动失败"
            echo "请检查日志: journalctl -u wg-quick@$iface"
            rm -f "$CONFIG_DIR/$iface.conf"
            return 1
        fi
    fi
}

# ========================
# 添加客户端（路由器）
# ========================
add_client() {
    echo "正在添加路由型客户端..."
    log "添加路由型客户端开始"
    
    # 选择接口
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi
    
    [ -z "$iface" ] && {
        echo "错误: 未选择接口"
        return 1
    }
    
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && {
        echo "错误: 接口 $iface 不存在"
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
    server_public=$(wg show "$iface" public-key)

    server_subnet=$(grep 'Address' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | tr -d ' ')
    base_net=$(echo $server_subnet | cut -d'/' -f1 | sed 's/\.[0-9]*$//')
    
    # 获取所有已使用的隧道IP（包括服务器IP）
    used_ips=(
        $(grep 'Address' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | cut -d'/' -f1)
        $(grep 'AllowedIPs' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | tr ',' '\n' | awk '{print $1}' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
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

    # 在服务器配置中添加Peer
    {
        echo -e "\n[Peer]"
        echo "PublicKey = $client_public"
        echo "AllowedIPs = $client_subnet, $client_tunnel_ip/32"
    } >> "$CONFIG_DIR/$iface.conf"

    mkdir -p "$CLIENT_DIR/$iface"
    client_file="$CLIENT_DIR/$iface/$client_name.conf"
    
    server_port=$(grep 'ListenPort' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | tr -d ' ')
    server_public_ip=$(head -n 1 "$PUBLIC_IP_FILE")

    # 客户端配置使用正确的隧道IP
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_tunnel_ip/24
Dns = 8.8.8.8, 1.1.1.1
[Peer]
PublicKey = $server_public
Endpoint = ${server_public_ip}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    qrencode -t ansiutf8 < "$client_file"
    chmod 600 "$client_file"

    wg syncconf "$iface" <(wg-quick strip "$iface") >/dev/null
    echo "路由型客户端添加成功！"
    echo "接口: $iface"
    echo "客户端子网: $client_subnet"
    echo "隧道端点IP: $client_tunnel_ip（仅用于建立连接）"
    log "接口 $iface 添加路由型客户端 $client_name"
}

# ========================
# 下游设备管理（使用SNAT）
# ========================
add_downstream() {
    echo "正在添加下游设备（SNAT）..."
    log "添加下游设备开始"
    
    # 选择接口
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi
    
    [ -z "$iface" ] && {
        echo "错误: 未选择接口"
        return 1
    }
    
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && {
        echo "错误: 接口 $iface 不存在"
        return 1
    }

    read -p "输入客户端子网（例如192.168.1.0/24）: " client_subnet
    validate_subnet "$client_subnet" || return 1

    # 检查子网掩码必须为24
    mask=$(echo "$client_subnet" | cut -d'/' -f2)
    if [ "$mask" -ne 24 ]; then
        echo "错误: 下游设备只支持/24子网"
        return 1
    fi

    read -p "需要分配的公网IP数量: " ip_count
    [[ "$ip_count" =~ ^[0-9]+$ ]] || {
        echo "错误: 请输入有效数字"
        return 1
    }
    [ $ip_count -lt 1 ] && {
        echo "错误: 至少分配1个公网IP"
        return 1
    }

    public_ips=($(allocate_public_ips "$ip_count")) || {
        echo "$public_ips"
        return 1
    }

    base_ip=$(echo "$client_subnet" | awk -F'[./]' '{print $1"."$2"."$3"."}')
    mappings=()

    for i in $(seq 1 $ip_count); do
        downstream_ip="${base_ip}$((i+1))"  # 从.2开始分配
        public_ip="${public_ips[$((i-1))]}"

        # 删除可能存在的旧规则
        iptables -t nat -D POSTROUTING -s "$downstream_ip" -j SNAT --to-source "$public_ip" 2>/dev/null || true
        
        # 添加新规则（插入到链的顶部）
        iptables -t nat -I POSTROUTING 1 -s "$downstream_ip" -j SNAT --to-source "$public_ip"
        
        # 验证规则是否添加成功
        if ! iptables -t nat -C POSTROUTING -s "$downstream_ip" -j SNAT --to-source "$public_ip" 2>/dev/null; then
            echo "错误: 无法添加SNAT规则 $downstream_ip => $public_ip"
            log "SNAT规则添加失败: $downstream_ip => $public_ip"
            return 1
        fi
        
        mappings+=("$downstream_ip:$public_ip")
    done

    # 保存规则
    iptables-save > /etc/iptables/rules.v4
    if ! netfilter-persistent save >/dev/null; then
        echo "警告: 无法永久保存iptables规则"
        log "iptables规则永久保存失败"
    fi

    # 更新映射文件
    local route_mapping=$(get_route_mapping "$iface")
    for map in "${mappings[@]}"; do
        dip=$(echo "$map" | cut -d: -f1)
        pub=$(echo "$map" | cut -d: -f2)
        jq --arg dip "$dip" --arg pub "$pub" \
           '. + { ($dip): $pub }' "$route_mapping" > tmp.json && mv tmp.json "$route_mapping"
        
        # 验证映射文件是否更新成功
        if [ "$(jq -r ".\"$dip\"" "$route_mapping")" != "$pub" ]; then
            echo "错误: 无法更新路由映射文件"
            log "路由映射文件更新失败: $dip => $pub"
            return 1
        fi
    done

    # 确保持久化机制已安装
    if [ ! -f "/usr/local/bin/restore-wg-snat.sh" ]; then
        install_persistence
    fi

    # 不重启接口，而是重新加载配置
    echo "重新加载接口配置..."
    if wg syncconf "$iface" <(wg-quick strip "$iface") 2>/dev/null; then
        echo "接口配置已重新加载"
        log "接口 $iface 配置已重新加载"
    else
        echo "警告: 无法重新加载配置，但SNAT规则已添加"
        log "接口 $iface 配置重新加载失败，但SNAT规则已添加"
    fi

    # 最终验证
    echo -e "\n验证配置:"
    for map in "${mappings[@]}"; do
        dip=$(echo "$map" | cut -d: -f1)
        pub=$(echo "$map" | cut -d: -f2)
        
        # 检查iptables规则
        if iptables -t nat -C POSTROUTING -s "$dip" -j SNAT --to-source "$pub" 2>/dev/null; then
            echo "[✓] SNAT规则有效: $dip => $pub"
        else
            echo "[×] SNAT规则缺失: $dip => $pub"
        fi
        
        # 检查映射文件
        if [ "$(jq -r ".\"$dip\"" "$route_mapping")" == "$pub" ]; then
            echo "[✓] 映射文件记录有效: $dip => $pub"
        else
            echo "[×] 映射文件记录缺失: $dip => $pub"
        fi
    done

    echo -e "\n下游设备添加成功！"
    echo "接口: $iface"
    echo "子网: $client_subnet"
    echo "分配的公网IP: ${public_ips[@]}"
    show_remaining_public_ips
    log "接口 $iface 添加下游设备"
}

delete_downstream() {
    echo "正在删除下游设备（SNAT）..."
    log "删除下游设备开始"
    
    # 选择接口
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi
    
    [ -z "$iface" ] && {
        echo "错误: 未选择接口"
        return 1
    }
    
    local route_mapping=$(get_route_mapping "$iface")

    read -p "输入下游设备私有IP（或输入 all 删除所有）: " downstream_ip

    if [ "$downstream_ip" = "all" ]; then
        jq -r 'keys[]' "$route_mapping" | while read -r dip; do
            public_ip=$(jq -r ".\"$dip\"" "$route_mapping")
            # 删除SNAT规则
            iptables -t nat -D POSTROUTING -s "$dip" -j SNAT --to-source "$public_ip" 2>/dev/null || true
            sed -i "/^$public_ip$/d" "$USED_IP_FILE"
        done

        echo "{}" > "$route_mapping"
        echo "已删除所有下游设备"
        show_remaining_public_ips
        log "接口 $iface 所有下游设备已删除"
    else
        public_ip=$(jq -r ".\"$downstream_ip\"" "$route_mapping")
        [ -z "$public_ip" ] || [ "$public_ip" = "null" ] && {
            echo "错误: 未找到映射记录"
            return 1
        }

        # 删除SNAT规则
        iptables -t nat -D POSTROUTING -s "$downstream_ip" -j SNAT --to-source "$public_ip" 2>/dev/null || true
        sed -i "/^$public_ip$/d" "$USED_IP_FILE"
        jq "del(.\"$downstream_ip\")" "$route_mapping" > tmp.json && mv tmp.json "$route_mapping"
        
        echo "已删除下游设备 $downstream_ip"
        show_remaining_public_ips
        log "接口 $iface 下游设备 $downstream_ip 已删除"
    fi

    # 保存规则
    netfilter-persistent save >/dev/null
    iptables-save > /etc/iptables/rules.v4
}

# ========================
# 状态管理
# ========================
show_mappings() {
    echo "当前路由映射状态："
    local has_mappings=false
    
    for route_mapping in "$CONFIG_DIR"/route_mappings_*.json; do
        [ ! -f "$route_mapping" ] && continue
        
        iface=$(basename "$route_mapping" | sed 's/route_mappings_//; s/\.json//')
        count=$(jq 'length' "$route_mapping")
        
        if [ "$count" -gt 0 ]; then
            has_mappings=true
            echo "接口: $iface"
            jq -r 'to_entries[] | "  \(.key) => \(.value)"' "$route_mapping"
        fi
    done
    
    if ! $has_mappings; then
        echo "无映射记录"
    fi
}

restart_interface() {
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi
    
    [ -z "$iface" ] && {
        echo "错误: 未选择接口"
        return 1
    }
    
    # 检查接口配置文件是否存在
    if [ ! -f "$CONFIG_DIR/$iface.conf" ]; then
        echo "错误: 接口配置文件 $iface.conf 不存在"
        return 1
    fi
    
    # 完全停止接口
    echo "正在停止接口 $iface..."
    systemctl stop "wg-quick@$iface" 2>/dev/null
    sleep 2
    
    # 确保接口设备被删除
    ip link delete "$iface" 2>/dev/null || true
    sleep 1
    
    # 检查配置文件格式
    echo "检查配置文件格式..."
    if ! wg-quick strip "$iface" >/dev/null 2>&1; then
        echo "错误: 配置文件格式有问题，请检查 $CONFIG_DIR/$iface.conf"
        return 1
    fi
    
    # 启动接口
    echo "启动接口 $iface..."
    if systemctl start "wg-quick@$iface"; then
        echo "接口 $iface 已成功启动"
        log "接口 $iface 已成功重启"
    else
        echo "错误: 接口 $iface 启动失败"
        echo "请检查配置文件: $CONFIG_DIR/$iface.conf"
        log "接口 $iface 启动失败"
        return 1
    fi
    
    # 恢复SNAT规则
    if [ -f "/usr/local/bin/restore-wg-snat.sh" ]; then
        echo "恢复SNAT规则..."
        /usr/local/bin/restore-wg-snat.sh
    fi
    
    # 显示接口状态
    echo "接口状态:"
    wg show "$iface"
}

delete_interface() {
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi
    
    [ -z "$iface" ] && {
        echo "错误: 未选择接口"
        return 1
    }
    
    read -p "确认删除接口 $iface？(y/N) " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    
    # 清除该接口的所有下游设备映射
    local route_mapping=$(get_route_mapping "$iface")
    if [ -f "$route_mapping" ]; then
        count=$(jq 'length' "$route_mapping")
        if [ "$count" -gt 0 ]; then
            echo "正在清除接口 $iface 的下游设备映射..."
            jq -r 'keys[]' "$route_mapping" | while read -r dip; do
                public_ip=$(jq -r ".\"$dip\"" "$route_mapping")
                iptables -t nat -D POSTROUTING -s "$dip" -j SNAT --to-source "$public_ip" 2>/dev/null || true
                sed -i "/^$public_ip$/d" "$USED_IP_FILE"
            done
            echo "已删除 $count 个下游设备映射"
        fi
    fi
    
    systemctl stop "wg-quick@$iface"
    rm -f "$CONFIG_DIR/$iface.conf"
    rm -f "$route_mapping"
    
    # 删除客户端配置目录
    rm -rf "$CLIENT_DIR/$iface"
    
    echo "接口 $iface 已删除"
    log "接口 $iface 已删除"
}

uninstall_wireguard() {
    read -p "确认完全卸载？(y/N) " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    
    # 清除所有接口的下游设备映射
    for route_mapping in "$CONFIG_DIR"/route_mappings_*.json; do
        [ ! -f "$route_mapping" ] && continue
        
        iface=$(basename "$route_mapping" | sed 's/route_mappings_//; s/\.json//')
        count=$(jq 'length' "$route_mapping")
        if [ "$count" -gt 0 ]; then
            echo "正在清除接口 $iface 的下游设备映射..."
            jq -r 'keys[]' "$route_mapping" | while read -r dip; do
                public_ip=$(jq -r ".\"$dip\"" "$route_mapping")
                iptables -t nat -D POSTROUTING -s "$dip" -j SNAT --to-source "$public_ip" 2>/dev/null || true
                sed -i "/^$public_ip$/d" "$USED_IP_FILE"
            done
        fi
    done
    
    # 停止并禁用所有接口
    for iface in $(list_interfaces); do
        systemctl stop "wg-quick@$iface" 2>/dev/null
    done
    
    # 停止并禁用恢复服务
    systemctl stop wg-snat-restore.service 2>/dev/null
    systemctl disable wg-snat-restore.service 2>/dev/null
    
    # 删除定时任务
    crontab -l 2>/dev/null | grep -v "restore-wg-snat.sh" | crontab -
    
    # 卸载软件包
    apt-get purge -y wireguard-tools iptables-persistent qrencode jq cron
    
    # 删除配置文件和目录（强制删除，即使非空）
    rm -rf "$CONFIG_DIR"
    rm -f /etc/systemd/system/wg-snat-restore.service
    rm -f /usr/local/bin/restore-wg-snat.sh
    rm -f /etc/iptables/rules.v4
    
    systemctl daemon-reload
    
    echo "WireGuard已完全卸载"
    log "WireGuard卸载完成"
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
mkdir -p "$CONFIG_DIR"
mkdir -p "$CLIENT_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
init_resources
main_menu