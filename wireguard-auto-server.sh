#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
FIXED_IFACE="wg0"  # 固定接口名称
SUBNET_IPV4="10.252.252.0/24"  # 固定IPv4子网
SUBNET_IPV6="fd00:252:252::/64"  # 固定IPv6子网
LOG_FILE="/var/log/wireguard-lite.log"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# ========================
# 通用功能函数
# ========================
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

validate_ip() {
    local ip=$1
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "错误: IP格式无效"
        return 1
    fi
    return 0
}

backup_config() {
    cp "$CONFIG_DIR/$FIXED_IFACE.conf" "$CONFIG_DIR/$FIXED_IFACE.conf.bak" 2>/dev/null && \
    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf.bak"
}

# ========================
# 依赖安装函数
# ========================
install_dependencies() {
    echo "正在安装依赖和配置系统..."
    log "开始安装依赖"
    export DEBIAN_FRONTEND=noninteractive

    # 修复PPA检查逻辑：确保目录存在并处理空目录场景
    mkdir -p /etc/apt/sources.list.d  # 创建目录（如果不存在）
    
    # 检查是否已添加WireGuard PPA（兼容空目录场景）
    if [ -n "$(ls -A /etc/apt/sources.list.d 2>/dev/null)" ]; then
        if ! grep -q "wireguard/wireguard" /etc/apt/sources.list.d/* 2>/dev/null; then
            add-apt-repository -y ppa:wireguard/wireguard >/dev/null 2>&1
            apt-get update >/dev/null 2>&1
        fi
    else
        # 目录为空时直接添加PPA
        add-apt-repository -y ppa:wireguard/wireguard >/dev/null 2>&1
        apt-get update >/dev/null 2>&1
    fi

    # 安装核心依赖
    if ! apt-get install -y --install-recommends wireguard-tools iptables iptables-persistent sipcalc qrencode curl iftop; then
        echo "错误: 依赖安装失败"
        log "依赖安装失败"
        exit 1
    fi

    # 验证wg命令
    if ! command -v wg &>/dev/null; then
        echo "错误: wireguard-tools 未正确安装"
        log "wireguard-tools安装失败"
        exit 1
    fi
    
    # 自动保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    # 配置sysctl参数（避免引用未创建的接口）
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.ipv6.conf.all.forwarding=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.conf.all.rp_filter=0"
        "net.ipv4.conf.default.rp_filter=0"
    )
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    
    # 加载sysctl参数（忽略接口未创建的警告）
    if ! sysctl -p >/dev/null 2>&1; then
        echo "警告: sysctl加载部分参数失败（接口可能尚未创建）"
        log "sysctl部分参数加载失败"
    fi
    
    echo "系统配置完成！"
    log "依赖安装完成"
}

# ========================
# 核心功能
# ========================
generate_client_ip() {
    local subnet=$(echo "$SUBNET_IPV4" | cut -d',' -f1)
    local existing_ips=($(awk -F'[ ,/]' '/^\[Peer\]/ { flag=1 } flag && /AllowedIPs/ { print $3; flag=0 }' "$CONFIG_DIR/$FIXED_IFACE.conf" 2>/dev/null | sort -u))
    
    local network_info=$(sipcalc "$subnet" 2>/dev/null)
    local network=$(echo "$network_info" | grep "Network address" | awk '{print $4}')
    local broadcast=$(echo "$network_info" | grep "Broadcast address" | awk '{print $4}')
    
    for i in $(seq 2 254); do
        candidate_ip="${network%.*}.$i"
        [[ "$candidate_ip" == "$broadcast" ]] && continue
        if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
            echo "$candidate_ip"
            return 0
        fi
    done
    
    echo "错误: 子网IP已耗尽"
    log "子网IP耗尽"
    return 1
}

generate_client_ipv6() {
    local subnet=$(echo "$SUBNET_IPV6" | cut -d',' -f1)
    local existing_ips=($(awk -F'[ ,/]' '/^\[Peer\]/ { flag=1 } flag && /AllowedIPs/ { for(i=3;i<=NF;i++) if($i ~ /:/) print $i; flag=0 }' "$CONFIG_DIR/$FIXED_IFACE.conf" 2>/dev/null | sort -u))
    
    local network="${subnet%::*}"  # 获取网络部分
    for i in $(seq 2 254); do
        # 生成IPv6地址（使用网络部分和递增的数字）
        candidate_ip="${network}::${i}"
        if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
            echo "$candidate_ip"
            return 0
        fi
    done
    
    echo "错误: IPv6子网地址已耗尽"
    log "IPv6子网地址耗尽"
    return 1
}

get_available_port() {
    base_port=51628
    while [ $base_port -lt 52000 ]; do
        if ! ss -uln | grep -q ":$base_port "; then
            echo $base_port
            return 0
        fi
        ((base_port++))
    done
    echo "错误: 未找到可用端口"
    log "端口扫描失败"
    return 1
}

get_server_public_ipv4() {
    # 获取服务器的公网IPv4地址
    local ipv4_address
    # 尝试多个源获取公网IP
    sources=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me"
        "https://ident.me"
    )
    
    for source in "${sources[@]}"; do
        if ipv4_address=$(curl -4 -s --connect-timeout 5 "$source"); then
            if [[ $ipv4_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$ipv4_address"
                return 0
            fi
        fi
    done
    
    # 如果所有在线服务都失败，尝试从网络接口获取
    ipv4_address=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    if [ -n "$ipv4_address" ]; then
        echo "$ipv4_address"
        return 0
    fi
    
    echo "错误: 无法获取服务器的公网IPv4地址"
    log "无法获取服务器IPv4地址"
    return 1
}

create_interface() {
    echo "正在创建WireGuard接口..."
    log "开始创建接口"

    if [ -f "$CONFIG_DIR/$FIXED_IFACE.conf" ]; then
        echo "错误: 接口 $FIXED_IFACE 已存在"
        log "接口已存在"
        return 1
    fi

    # 获取动态端口
    port=$(get_available_port) || { 
        return 1 
    }

    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    # 获取服务器公网IPv4地址
    server_ipv4=$(get_server_public_ipv4) || {
        echo "$server_ipv4"
        return 1
    }

    # 保存服务器端口和IPv4地址供客户端使用
    echo "$port" > "$CONFIG_DIR/${FIXED_IFACE}_port"
    echo "$server_ipv4" > "$CONFIG_DIR/${FIXED_IFACE}_ipv4"

    # 获取外部接口用于NAT
    ext_if=$(ip route show default | awk '/default/ {print $5; exit}')
    [ -z "$ext_if" ] && { 
        echo "错误: 未找到默认出口接口"
        log "未找到出口接口"
        return 1 
    }

    # 创建WireGuard配置（使用MASQUERADE进行IPv4 NAT）
    cat > "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF
[Interface]
Address = ${SUBNET_IPV4%.*}.1/24, ${SUBNET_IPV6%:*}:1/64
PrivateKey = $server_private
ListenPort = $port

# IPv4 NAT规则
PreUp = iptables -t nat -A POSTROUTING -s $SUBNET_IPV4 -o $ext_if -j MASQUERADE
PreDown = iptables -t nat -D POSTROUTING -s $SUBNET_IPV4 -o $ext_if -j MASQUERADE

# IPv6路由通告配置（使客户端能够自动配置IPv6地址）
PostUp = sysctl -w net.ipv6.conf.$FIXED_IFACE.autoconf=1
PostUp = sysctl -w net.ipv6.conf.$FIXED_IFACE.accept_ra=1
PostUp = sysctl -w net.ipv6.conf.$FIXED_IFACE.forwarding=1
EOF

    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf"

    if systemctl enable --now "wg-quick@$FIXED_IFACE" &>/dev/null; then
        echo "接口 $FIXED_IFACE 创建成功！"
        echo "监听端口: $port"
        echo "IPv4子网: $SUBNET_IPV4"
        echo "IPv6子网: $SUBNET_IPV6"
        echo "服务器IPv4地址: $server_ipv4"
        log "接口创建成功"
        
        # 接口启动后配置wg0的rp_filter
        echo "正在配置wg0接口的反向路径过滤..."
        if ! grep -qxF "net.ipv4.conf.$FIXED_IFACE.rp_filter=0" /etc/sysctl.conf; then
            echo "net.ipv4.conf.$FIXED_IFACE.rp_filter=0" >> /etc/sysctl.conf
            sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || echo "警告: 无法加载wg0的rp_filter配置"
        fi
        log "wg0接口rp_filter已配置"
    else
        rm -f "$CONFIG_DIR/$FIXED_IFACE.conf" "$CONFIG_DIR/${FIXED_IFACE}_port" "$CONFIG_DIR/${FIXED_IFACE}_ipv4"
        echo "错误: 服务启动失败"
        log "接口启动失败"
        return 1
    fi
}

add_client() {
    echo "正在添加新客户端..."
    log "开始添加客户端"
    
    if [ ! -f "$CONFIG_DIR/$FIXED_IFACE.conf" ]; then
        echo "错误: 接口 $FIXED_IFACE 不存在"
        log "接口不存在"
        return 1
    fi

    # 自动生成客户端名称
    client_count=$(ls "$CLIENT_DIR/$FIXED_IFACE"/*.conf 2>/dev/null | wc -l)
    client_name="client$((client_count + 1))"
    
    # 获取客户端IPv4和IPv6地址
    client_ipv4=$(generate_client_ip "$SUBNET_IPV4" "$FIXED_IFACE") || { 
        echo "$client_ipv4"
        return 1 
    }
    
    client_ipv6=$(generate_client_ipv6 "$SUBNET_IPV6" "$FIXED_IFACE") || { 
        echo "$client_ipv6"
        return 1 
    }
    
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)

    # 备份当前配置
    backup_config

    # 添加Peer配置
    tmp_conf=$(mktemp /tmp/wg_conf.XXXXXX)
    chmod 600 "$tmp_conf"
    trap "rm -f '$tmp_conf'" EXIT

    grep -v '^$' "$CONFIG_DIR/$FIXED_IFACE.conf" > "$tmp_conf"
    cat >> "$tmp_conf" <<EOF

[Peer]
# $client_name
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ipv4/32, $client_ipv6/128
EOF

    # 保存配置
    chmod 600 "$tmp_conf"
    mv "$tmp_conf" "$CONFIG_DIR/$FIXED_IFACE.conf"

    # 生成客户端配置
    mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
    client_file="$CLIENT_DIR/$FIXED_IFACE/$client_name.conf"
    
    # 使用默认DNS
    client_dns="1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888"
    
    # 获取服务器端口和IPv4地址
    server_port=$(cat "$CONFIG_DIR/${FIXED_IFACE}_port" 2>/dev/null | tr -d '\r')
    server_ipv4=$(cat "$CONFIG_DIR/${FIXED_IFACE}_ipv4" 2>/dev/null | tr -d '\r')
    
    # 客户端配置同时支持IPv4和IPv6，但Endpoint使用IPv4
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ipv4/24, $client_ipv6/64
DNS = $client_dns

[Peer]
PublicKey = $(grep 'PrivateKey' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk '{print $3}' | wg pubkey)
PresharedKey = $client_preshared
Endpoint = $server_ipv4:$server_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 600 "$client_file"
    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"
    chmod 600 "${client_file}.png"

    # 动态加载配置
    if wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE") 2>/dev/null; then
        echo "配置已动态加载"
        log "配置动态加载成功"
    else
        echo "警告: 动态加载失败，尝试重启接口..."
        log "动态加载失败，尝试重启"
        if ! systemctl restart "wg-quick@$FIXED_IFACE"; then
            echo "错误: 接口重启失败"
            log "接口重启失败"
            return 1
        fi
    fi

    echo "客户端 $client_name 添加成功！"
    echo "IPv4地址: $client_ipv4"
    echo "IPv6地址: $client_ipv6"
    echo "配置文件: $client_file"
    echo "二维码: ${client_file}.png"
    log "客户端添加成功: $client_name"
}

# 删除客户端
delete_client() {
    echo "正在删除客户端..."
    log "开始删除客户端"
    
    if [ ! -f "$CONFIG_DIR/$FIXED_IFACE.conf" ]; then
        echo "错误: 接口 $FIXED_IFACE 不存在"
        log "接口不存在"
        return 1
    fi

    read -p "输入要删除的客户端名称: " client_name
    client_file="$CLIENT_DIR/$FIXED_IFACE/$client_name.conf"
    if [ ! -f "$client_file" ]; then
        echo "错误: 客户端不存在"
        log "客户端不存在: $client_name"
        return 1
    fi

    # 备份配置
    backup_config

    # 从服务器配置中移除Peer
    tmp_conf=$(mktemp /tmp/wg_conf.XXXXXX)
    awk -v client="$client_name" '
        BEGIN { skip = 0 }
        /^\[Peer\]/ { 
            if (skip) { skip = 0 }
            else { save = 1 }
        }
        /^# '${client_name}'$/ { skip = 1; next }
        skip { next }
        { if (save) print }
    ' "$CONFIG_DIR/$FIXED_IFACE.conf" > "$tmp_conf"

    # 保存配置
    mv "$tmp_conf" "$CONFIG_DIR/$FIXED_IFACE.conf"
    
    # 删除客户端文件
    rm -f "$client_file" "${client_file}.png"
    
    # 重新加载配置
    wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE") 2>/dev/null

    echo "客户端 $client_name 已删除"
    log "客户端删除成功: $client_name"
}

# 删除接口
delete_interface() {
    read -p "确定要删除接口 $FIXED_IFACE 吗？(y/N) " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    echo "正在删除接口..."
    log "开始删除接口"
    
    systemctl stop "wg-quick@$FIXED_IFACE" 2>/dev/null
    systemctl disable "wg-quick@$FIXED_IFACE" 2>/dev/null
    rm -f "$CONFIG_DIR/$FIXED_IFACE.conf" "$CONFIG_DIR/${FIXED_IFACE}_port" "$CONFIG_DIR/${FIXED_IFACE}_ipv4"
    
    # 清理iptables规则
    ext_if=$(ip route show default | awk '/default/ {print $5; exit}')
    iptables -t nat -D POSTROUTING -s "$SUBNET_IPV4" -o "$ext_if" -j MASQUERADE 2>/dev/null
    
    echo "接口 $FIXED_IFACE 已删除"
    log "接口删除成功"
}

# 重启接口
restart_interface() {
    echo "正在重启接口..."
    log "尝试重启接口"
    
    # 优先动态加载配置
    if wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE") 2>/dev/null; then
        echo "配置已动态加载"
        log "接口配置动态加载成功"
    else
        echo "警告: 动态加载失败，尝试完整重启接口..."
        log "动态加载失败，开始完整重启"
        systemctl restart "wg-quick@$FIXED_IFACE" && \
        echo "接口重启成功" || {
            echo "错误: 接口重启失败"
            log "接口重启失败"
            return 1
        }
    fi
}

# 完全卸载
uninstall_wireguard() {
    read -p "确定要完全卸载WireGuard吗？(y/N) " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    echo "正在卸载WireGuard..."
    log "开始卸载"
    
    systemctl stop "wg-quick@$FIXED_IFACE" 2>/dev/null
    rm -rf "$CONFIG_DIR" "$CLIENT_DIR"
    apt-get purge -y --auto-remove wireguard-tools iptables-persistent qrencode
    
    iptables -F
    iptables -t nat -F
    
    echo "WireGuard已完全卸载"
    log "卸载完成"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=("安装依赖" "创建接口" "添加客户端" "删除客户端" "重启接口" "删除接口" "完全卸载" "退出")
    select opt in "${options[@]}"; do
        case $opt in
            "安装依赖") install_dependencies ;;
            "创建接口") create_interface ;;
            "添加客户端") add_client ;;
            "删除客户端") delete_client ;;
            "重启接口") restart_interface ;;
            "删除接口") delete_interface ;;
            "完全卸载") uninstall_wireguard ;;
            "退出") 
                echo "配置已保存，再见！"
                log "脚本正常退出"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
    log "脚本正常退出"
}

# 初始化
mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

main_menu