#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
FIXED_IFACE="wg0"
SUBNET="10.20.0.0/24"
LOG_FILE="/var/log/wireguard-lite.log"
SERVER_PUBLIC_IP=""

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
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    return 0
}

backup_config() {
    cp "$CONFIG_DIR/$FIXED_IFACE.conf" "$CONFIG_DIR/$FIXED_IFACE.conf.bak" 2>/dev/null && \
    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf.bak"
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

    apt-get install -y --install-recommends wireguard-tools iptables iptables-persistent sipcalc qrencode || {
        echo "依赖安装失败"; log "依赖安装失败"; exit 1
    }

    # 配置系统参数
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.conf.all.rp_filter=0"
        "net.ipv4.conf.default.rp_filter=0"
    )
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1

    echo "系统配置完成"
    log "依赖安装完成"
}

# ========================
# IP池管理
# ========================
init_ip_pool() {
    [ -f "$PUBLIC_IP_FILE" ] || { 
        echo "错误: 公网IP池文件不存在: $PUBLIC_IP_FILE" 
        echo "文件格式要求：每行一个客户端公网IP"
        exit 1
    }
    
    [ $(wc -l < "$PUBLIC_IP_FILE") -lt 1 ] && {
        echo "错误: IP池文件至少需要1行"
        exit 1
    }
    touch "$USED_IP_FILE"
}

get_available_public_ip() {
    cat "$PUBLIC_IP_FILE" | \
    diff --unchanged-line-format= --old-line-format= --new-line-format='%L' "$USED_IP_FILE" - | \
    head -n1
}

mark_ip_used() {
    grep -qxF "$1" "$USED_IP_FILE" || echo "$1" >> "$USED_IP_FILE"
}

release_ip() {
    sed -i "/^$1$/d" "$USED_IP_FILE"
}

# ========================
# IP分配验证函数
# ========================
validate_client_ip_allocation() {
    local total_client_ips=$(wc -l < "$PUBLIC_IP_FILE")
    local used_client_ips=$(wc -l < "$USED_IP_FILE")
    
    [ "$total_client_ips" -le "$used_client_ips" ] && {
        echo "错误: 客户端公网IP已耗尽（总数：$total_client_ips，已用：$used_client_ips）"
        exit 1
    }
}

# ========================
# 核心功能
# ========================
generate_client_ip() {
    # 从服务器配置中精确提取已分配IP
    existing_ips=($(awk -F'[ /]' '/AllowedIPs/ && !/^#/ {print $3}' "$CONFIG_DIR/$FIXED_IFACE.conf" 2>/dev/null))
    
    # 获取子网信息
    network_info=$(sipcalc "$SUBNET")
    network=$(echo "$network_info" | grep "Network address" | awk '{print $4}')
    broadcast=$(echo "$network_info" | grep "Broadcast address" | awk '{print $4}')
    
    # 遍历2-254地址段
    for i in $(seq 2 254); do
        candidate_ip="${network%.*}.$i"
        [[ "$candidate_ip" == "$broadcast" ]] && continue
        if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
            echo "$candidate_ip"
            return 0
        fi
    done
    
    echo "错误: 子网IP已耗尽" >&2
    log "子网IP耗尽"
    return 1
}

create_interface() {
    init_ip_pool
    echo "正在创建WireGuard接口..."
    log "接口创建开始"

    # 获取服务器公网IP
    while true; do
        read -p "请输入服务器公网IP地址: " SERVER_PUBLIC_IP
        if validate_ip "$SERVER_PUBLIC_IP"; then
            break
        else
            echo "无效的IP地址，请重新输入"
        fi
    done

    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    cat > "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF
[Interface]
Address = ${SUBNET%.*}.1/24
PrivateKey = $server_private
ListenPort = 51820

PreUp = iptables -t nat -A POSTROUTING -s $SUBNET -o %i -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o %i -j MASQUERADE
EOF

    systemctl enable --now wg-quick@$FIXED_IFACE &>/dev/null || {
        echo "接口启动失败"; log "接口启动失败"; exit 1
    }

    echo "接口 $FIXED_IFACE 创建成功"
    echo "服务器公网IP: $SERVER_PUBLIC_IP"
    log "接口创建成功"
}

add_client() {
    validate_client_ip_allocation
    echo "正在添加新客户端..."
    log "开始添加客户端"

    # 分配客户端公网IP
    client_nat_ip=$(get_available_public_ip) || {
        echo "错误: 没有可用的公网IP"
        exit 1
    }
    mark_ip_used "$client_nat_ip" || {
        echo "IP标记失败: $client_nat_ip"
        exit 1
    }

    # 分配内网IP
    client_ip=$(generate_client_ip) || {
        release_ip "$client_nat_ip"
        exit 1
    }

    # 生成客户端密钥
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)

    # 更新服务器配置
    backup_config
    cat >> "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF

[Peer]
# $client_nat_ip
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ip/32
EOF

    # 配置SNAT规则
    ext_if=$(ip route show default | awk '{print $5; exit}')
    iptables -t nat -A POSTROUTING -s $client_ip/32 -o $ext_if -j SNAT --to-source $client_nat_ip

    # 生成客户端配置（使用服务器公网IP）
    mkdir -p "$CLIENT_DIR"
    client_file="$CLIENT_DIR/${client_nat_ip}.conf"
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip/32
DNS = 8.8.8.8

[Peer]
PublicKey = $server_public
Endpoint = ${SERVER_PUBLIC_IP}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
PresharedKey = $client_preshared
EOF

    # 生成二维码
    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"
    chmod 600 "$client_file" "${client_file}.png"

    # 应用配置
    if ! wg syncconf $FIXED_IFACE <(wg-quick strip $FIXED_IFACE); then
        systemctl restart wg-quick@$FIXED_IFACE
        log "配置动态加载失败，已执行完整重启"
    fi

    echo "客户端添加成功"
    echo "出口公网IP: $client_nat_ip"
    echo "内网IP: $client_ip"
    echo "配置文件: $client_file"
    log "客户端添加: $client_nat_ip"
}

delete_client() {
    [ -n "$1" ] || { echo "请提供公网IP地址"; exit 1; }
    
    client_file="$CLIENT_DIR/$1.conf"
    [ -f "$client_file" ] || { echo "客户端不存在"; exit 1; }

    release_ip "$1"

    client_ip=$(grep 'Address = ' "$client_file" | awk '{print $3}' | cut -d/ -f1)
    iptables-save -t nat | grep "SNAT --to-source $1" | while read -r rule; do
        iptables -t nat -D ${rule#-A}
    done

    sed -i "/# $1$/,+4d" "$CONFIG_DIR/$FIXED_IFACE.conf"
    rm -f "$client_file" "${client_file}.png"

    if ! wg syncconf $FIXED_IFACE <(wg-quick strip $FIXED_IFACE); then
        systemctl restart wg-quick@$FIXED_IFACE
    fi

    echo "客户端 $1 已删除"
    log "客户端删除: $1"
}

restart_wg() {
    systemctl restart wg-quick@$FIXED_IFACE
    echo "WireGuard接口已重启"
}

# ========================
# 完全卸载功能
# ========================
uninstall_wireguard() {
    echo "⚠️  即将执行完全卸载操作，此操作将："
    echo "1. 永久删除所有WireGuard配置"
    echo "2. 移除所有已安装的依赖包"
    echo "3. 清除iptables规则"
    echo "4. 恢复系统网络参数"
    
    read -p "❗ 确认要完全卸载吗？(输入YES确认): " confirm
    [[ "$confirm" != "YES" ]] && {
        echo "卸载已取消"
        return
    }

    echo "开始卸载..."
    log "启动完全卸载流程"

    systemctl stop wg-quick@$FIXED_IFACE 2>/dev/null
    systemctl disable wg-quick@$FIXED_IFACE 2>/dev/null

    rm -rf "$CONFIG_DIR"
    rm -f /etc/sysctl.d/wireguard.conf 2>/dev/null

    apt-get purge -y --auto-remove \
        wireguard-tools \
        iptables-persistent \
        qrencode \
        wireguard-dkms \
        wireguard-tools-dbgsym 2>/dev/null

    iptables-save | grep -v "WireGuard" | iptables-restore
    ip6tables-save | grep -v "WireGuard" | ip6tables-restore

    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    rm -f "$LOG_FILE" 2>/dev/null

    echo "✅ WireGuard已完全卸载"
    echo "建议手动执行以下命令："
    echo "reboot  # 重启确保所有配置清除"
    log "卸载完成"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=("安装依赖" "创建接口" "添加客户端" "删除客户端" "重启接口" "完全卸载" "退出")
    select opt in "${options[@]}"; do
        case $opt in
            "安装依赖") install_dependencies ;;
            "创建接口") create_interface ;;
            "添加客户端") add_client ;;
            "删除客户端") 
                read -p "输入要删除的公网IP: " ip
                delete_client "$ip" ;;
            "重启接口") restart_wg ;;
            "完全卸载") uninstall_wireguard ;;
            "退出") exit 0 ;;
            *) echo "无效选项" ;;
        esac
    done
}

# 初始化环境
mkdir -p "$CONFIG_DIR" "$CLIENT_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

main_menu
