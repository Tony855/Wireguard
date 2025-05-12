#!/bin/bash
# ========================
# WireGuard 全功能管理脚本
# 版本：2.2
# 更新：2023-12-26
# ========================

# 配置参数
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
FIXED_IFACE="wg0"
SUBNET="10.20.1.0/24"
LOG_FILE="/var/log/wireguard-manager.log"
SERVER_PUBLIC_IP=""
PHYSICAL_IFACE="eth0"
DEFAULT_MTU=1420

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本" | tee -a "$LOG_FILE"
    exit 1
fi

# ========================
# 增强日志系统
# ========================
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_msg="$timestamp - $1"
    echo "$log_msg" >> "$LOG_FILE"
    echo "$log_msg"
}

# ========================
# 依赖安装（多发行版支持）
# ========================
install_dependencies() {
    log "开始安装依赖"
    echo "正在安装系统依赖..."

    # 检测TUN模块
    if ! lsmod | grep -q tun; then
        log "加载TUN模块"
        if ! modprobe tun 2>> "$LOG_FILE"; then
            log "[错误] TUN模块加载失败"
            echo "错误: 无法加载TUN内核模块，请检查内核支持"
            exit 1
        fi
        echo "tun" > /etc/modules-load.d/wireguard-tun.conf
        chmod 644 /etc/modules-load.d/wireguard-tun.conf
    fi

    # 检测发行版
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log "[错误] 无法检测操作系统"
        echo "错误: 不支持的操作系统"
        exit 1
    fi

    export DEBIAN_FRONTEND=noninteractive

    # 安装依赖
    case "$OS" in
        ubuntu|debian)
            if [[ "$OS" == "ubuntu" && $(echo "$VERSION >= 20.04" | bc -l) -eq 1 ]] || 
               [[ "$OS" == "debian" && $(echo "$VERSION >= 11" | bc -l) -eq 1 ]]; then
                apt-get update >/dev/null 2>> "$LOG_FILE"
                apt-get install -y --no-install-recommends \
                    wireguard-tools \
                    iptables \
                    iptables-persistent \
                    qrencode \
                    bc \
                    ipcalc-ng 2>> "$LOG_FILE"
            else
                add-apt-repository -y ppa:wireguard/wireguard >/dev/null 2>> "$LOG_FILE"
                apt-get update >/dev/null 2>> "$LOG_FILE"
                apt-get install -y --no-install-recommends \
                    wireguard-tools \
                    wireguard-dkms \
                    iptables \
                    iptables-persistent \
                    qrencode \
                    bc \
                    ipcalc-ng 2>> "$LOG_FILE"
            fi
            systemctl enable netfilter-persistent >/dev/null 2>&1
            ;;
        centos|fedora|rhel)
            yum install -y epel-release >/dev/null 2>> "$LOG_FILE"
            yum install -y kmod-wireguard \
                wireguard-tools \
                iptables \
                iptables-services \
                qrencode \
                bc \
                ipcalc 2>> "$LOG_FILE"
            systemctl enable iptables >/dev/null 2>&1
            ;;
        *)
            log "[错误] 不支持的发行版: $OS"
            echo "错误: 不支持的操作系统"
            exit 1
            ;;
    esac

    # 配置内核参数
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.ipv6.conf.all.forwarding=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    for param in "${sysctl_conf[@]}"; do
        if ! grep -qxF "$param" /etc/sysctl.conf; then
            echo "$param" >> /etc/sysctl.conf
        fi
    done
    sysctl -p >/dev/null 2>> "$LOG_FILE"

    log "依赖安装完成"
    echo "系统依赖安装成功"
}

# ========================
# IP地址管理
# ========================
init_ip_pool() {
    [ -f "$PUBLIC_IP_FILE" ] || { 
        log "[错误] 公网IP池文件不存在"
        echo "错误: 请先创建公网IP池文件 $PUBLIC_IP_FILE"
        exit 1
    }
    
    [ $(wc -l < "$PUBLIC_IP_FILE") -lt 1 ] && {
        log "[错误] IP池文件为空"
        echo "错误: IP池文件至少需要1个公网IP"
        exit 1
    }
    touch "$USED_IP_FILE"
}

get_available_public_ip() {
    comm -23 <(sort "$PUBLIC_IP_FILE") <(sort "$USED_IP_FILE") | head -n1
}

mark_ip_used() {
    grep -qxF "$1" "$USED_IP_FILE" || echo "$1" >> "$USED_IP_FILE"
}

release_ip() {
    sed -i "/^$1$/d" "$USED_IP_FILE"
}

# ========================
# 核心功能
# ========================
generate_client_ip() {
    existing_ips=($(wg show "$FIXED_IFACE" allowed-ips | awk '{print $2}' | cut -d/ -f1))
    
    network_info=$(ipcalc -n "$SUBNET")
    network=$(echo "$network_info" | grep 'NETWORK=' | cut -d= -f2)
    
    for i in $(seq 2 254); do
        candidate_ip="${network%.*}.$i"
        [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]] || {
            echo "$candidate_ip"
            return 0
        }
    done
    
    log "[错误] 子网IP耗尽"
    echo "错误: 子网IP已耗尽" >&2
    return 1
}

create_interface() {
    init_ip_pool
    log "开始创建WireGuard接口"

    # TUN设备验证
    [ -c /dev/net/tun ] || {
        log "[错误] TUN设备不存在"
        echo "错误: 缺少TUN设备，请检查内核模块"
        exit 1
    }

    # 获取公网IP
    while :; do
        read -p "请输入服务器公网IP地址: " SERVER_PUBLIC_IP
        if [[ "$SERVER_PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            echo "无效的IP格式，请重新输入"
        fi
    done

    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    # 生成服务端配置
    cat > "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF
[Interface]
Address = ${SUBNET%.*}.1/24
PrivateKey = $server_private
ListenPort = 51620
MTU = $DEFAULT_MTU

# 网络转发配置
PreUp = sysctl -w net.ipv4.ip_forward=1
PreUp = sysctl -w net.ipv6.conf.all.forwarding=1
PreUp = iptables -t nat -A POSTROUTING -s $SUBNET -o $PHYSICAL_IFACE -j MASQUERADE
PreUp = iptables -A FORWARD -i $FIXED_IFACE -j ACCEPT
PreUp = iptables -A FORWARD -o $FIXED_IFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o $PHYSICAL_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i $FIXED_IFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $FIXED_IFACE -j ACCEPT
EOF

    # 启动服务
    if ! wg-quick up "$FIXED_IFACE" 2>> "$LOG_FILE"; then
        log "[错误] 接口启动失败"
        echo "错误: 接口启动失败，请检查日志"
        exit 1
    fi

    systemctl enable wg-quick@"$FIXED_IFACE" >/dev/null 2>&1
    log "接口创建成功"
    echo "✅ WireGuard接口已创建"
}

add_client() {
    init_ip_pool
    log "开始添加新客户端"

    # 分配公网IP
    client_nat_ip=$(get_available_public_ip)
    [ -z "$client_nat_ip" ] && {
        log "[错误] 公网IP耗尽"
        echo "错误: 没有可用的公网IP"
        exit 1
    }
    mark_ip_used "$client_nat_ip"

    # 分配内网IP
    client_ip=$(generate_client_ip) || {
        release_ip "$client_nat_ip"
        exit 1
    }

    # 生成密钥
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)

    # 更新服务端配置
    cat >> "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF

[Peer]
# $client_nat_ip
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ip/32
EOF

    # 配置SNAT
    iptables -t nat -I POSTROUTING 1 -s "$client_ip/32" -o "$PHYSICAL_IFACE" -j SNAT --to-source "$client_nat_ip"
    iptables-save > /etc/iptables/rules.v4

    # 生成客户端配置
    mkdir -p "$CLIENT_DIR"
    client_file="$CLIENT_DIR/${client_nat_ip}.conf"
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip/24
DNS = 8.8.8.8, 2001:4860:4860::8888
MTU = $DEFAULT_MTU

[Peer]
PublicKey = $server_public
Endpoint = ${SERVER_PUBLIC_IP}:51620
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
PresharedKey = $client_preshared
EOF

    # 生成二维码
    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"

    # 应用配置
    if ! wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE"); then
        systemctl restart wg-quick@"$FIXED_IFACE"
        log "[警告] 配置重载失败，已重启服务"
    fi

    log "客户端添加成功: $client_nat_ip"
    echo "✅ 客户端添加成功"
    echo "配置文件路径: $client_file"
}

delete_client() {
    [ -z "$1" ] && { echo "请提供公网IP地址"; exit 1; }
    log "开始删除客户端: $1"

    client_file="$CLIENT_DIR/$1.conf"
    [ -f "$client_file" ] || { 
        log "[错误] 客户端不存在: $1"
        echo "错误: 客户端不存在"
        exit 1
    }

    # 获取内网IP
    client_ip=$(awk -F'[ /]' '/Address/{print $3}' "$client_file")

    # 清理iptables规则
    iptables -t nat -D POSTROUTING -s "$client_ip/32" -o "$PHYSICAL_IFACE" -j SNAT --to-source "$1" 2>/dev/null
    iptables-save > /etc/iptables/rules.v4

    # 释放IP
    release_ip "$1"

    # 从服务端配置删除
    sed -i "/^# $1$/,/^$/d" "$CONFIG_DIR/$FIXED_IFACE.conf"

    # 删除客户端文件
    rm -f "$client_file" "${client_file}.png"

    # 重载配置
    if ! wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE"); then
        systemctl restart wg-quick@"$FIXED_IFACE"
        log "[警告] 配置重载失败，已重启服务"
    fi

    log "客户端已删除: $1"
    echo "✅ 客户端 $1 已删除"
}

# ========================
# 诊断功能
# ========================
check_forwarding() {
    echo "===== 网络转发状态检查 ====="
    echo "IPv4 转发状态: $(sysctl -n net.ipv4.ip_forward)"
    echo "IPv6 转发状态: $(sysctl -n net.ipv6.conf.all.forwarding)"
    echo "TUN 设备状态: $(ls /dev/net/tun 2>/dev/null || echo '未找到')"
    echo ""
    echo "当前 NAT 规则:"
    iptables -t nat -L POSTROUTING -nv --line-numbers
    echo ""
    echo "当前 FORWARD 规则:"
    iptables -L FORWARD -nv
}

# ========================
# 卸载功能
# ========================
uninstall_wireguard() {
    read -p "确认要完全卸载WireGuard吗？(输入YES确认): " confirm
    [[ "$confirm" != "YES" ]] && return

    log "开始卸载WireGuard"
    systemctl stop wg-quick@"$FIXED_IFACE" 2>/dev/null
    systemctl disable wg-quick@"$FIXED_IFACE" 2>/dev/null

    # 清理配置
    rm -rf "$CONFIG_DIR"
    rm -f /etc/modules-load.d/wireguard-tun.conf

    # 清理iptables规则
    iptables-save | grep -v "WireGuard" | iptables-restore
    ip6tables-save | grep -v "WireGuard" | ip6tables-restore
    rm -f /etc/iptables/rules.v4

    # 卸载软件包
    if [ -f /etc/redhat-release ]; then
        yum remove -y wireguard-tools kmod-wireguard 2>/dev/null
    else
        apt-get purge -y wireguard-tools wireguard-dkms 2>/dev/null
    fi

    # 恢复内核参数
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
    sysctl -p >/dev/null

    log "卸载完成"
    echo "✅ WireGuard已完全卸载"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=(
        "安装系统依赖"
        "创建WG接口" 
        "添加新客户端"
        "删除客户端"
        "检查网络状态"
        "查看系统日志"
        "完全卸载程序"
        "退出"
    )
    
    while true; do
        select opt in "${options[@]}"; do
            case $REPLY in
                1) install_dependencies; break ;;
                2) create_interface; break ;;
                3) add_client; break ;;
                4) 
                    read -p "输入要删除的公网IP: " ip
                    delete_client "$ip"
                    break
                    ;;
                5) check_forwarding; break ;;
                6) less +G "$LOG_FILE"; break ;;
                7) uninstall_wireguard; break ;;
                8) exit 0 ;;
                *) echo "无效选项"; break ;;
            esac
        done
        echo
    done
}

# 初始化环境
mkdir -p "$CONFIG_DIR" "$CLIENT_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

main_menu
