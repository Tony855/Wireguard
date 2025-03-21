#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
PUBLIC_IP6_FILE="$CONFIG_DIR/public_ip6s.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
USED_IP6_FILE="$CONFIG_DIR/used_ip6s.txt"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# ========================
# 依赖安装函数（优化版）
# ========================
install_dependencies() {
    echo "正在安装依赖和配置系统..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y --install-recommends \
        wireguard-tools wireguard-dkms \
        iptables nftables iptables-persistent \
        sipcalc qrencode curl linux-headers-$(uname -r)

    # 启用nftables后端（性能更优）
    update-alternatives --set iptables /usr/sbin/iptables-nft
    update-alternatives --set ip6tables /usr/sbin/ip6tables-nft

    # 硬件加速相关组件
    apt-get install -y cpu-checker
    if kvm-ok; then
        apt-get install -y virt-what
    fi

    # 自动保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # 优化系统参数
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.ipv6.conf.all.forwarding=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.core.rmem_max=67108864"
        "net.core.wmem_max=67108864"
        "net.ipv4.tcp_rmem=4096 87380 67108864"
        "net.ipv4.tcp_wmem=4096 65536 67108864"
        "net.ipv4.tcp_mtu_probing=1"
    )
    # 检测AES-NI支持
    if grep -q 'aes' /proc/cpuinfo; then
        echo "检测到CPU支持AES-NI指令集，启用加密加速"
        sysctl_conf+=("net.ipv4.tcp_congestion_control=bbr")
    fi

    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1

    # 网卡优化（仅对物理接口）
    ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)
    if [ -d "/sys/class/net/$ext_if/queues" ]; then
        ethtool -K $ext_if gro on gso on tso on 2>/dev/null
        ethtool -C $ext_if rx-usecs 50 2>/dev/null
    fi

    echo "系统配置完成！"
}

# ========================
# IP池管理功能
# ========================
init_ip_pool() {
    if [ ! -f "$PUBLIC_IP_FILE" ]; then
        echo "错误: 公网IPv4池文件不存在！"
        echo "请先创建 $PUBLIC_IP_FILE"
        exit 1
    fi
    touch "$USED_IP_FILE" 2>/dev/null || :

    if [[ $enable_ipv6 =~ ^[Yy]$ ]] && [ ! -f "$PUBLIC_IP6_FILE" ]; then
        echo "错误: 公网IPv6池文件不存在！"
        echo "请先创建 $PUBLIC_IP6_FILE"
        exit 1
    fi
    touch "$USED_IP6_FILE" 2>/dev/null || :
}

get_available_ip() {
    local pool_file=$1
    local used_file=$2
    while read -r ip; do
        if ! grep -qxF "$ip" "$used_file"; then
            echo "$ip"
            return 0
        fi
    done < "$pool_file"
    echo "错误: 所有公网IP已分配完毕（$pool_file）"
    return 1
}

mark_ip_used() {
    local ip=$1
    local used_file=$2
    echo "$ip" >> "$used_file"
}

rollback_ip_allocation() {
    local ip=$1
    local used_file=$2
    sed -i "/^$ip$/d" "$used_file" 2>/dev/null
}

# ========================
# 核心功能（优化接口配置）
# ========================
validate_subnet() {
    local subnet=$1
    if [[ -z "$subnet" || "$subnet" == -* ]]; then
        echo "错误: 子网格式不能为空或以 '-' 开头"
        return 1
    fi
    if [[ "$subnet" == *:* ]]; then
        sipcalc "$subnet" >/dev/null 2>&1 || { echo "错误: 无效的IPv6子网格式"; return 1; }
    else
        if ! [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "错误: IPv4子网格式应为 x.x.x.x/x"
            return 1
        fi
        sipcalc "$subnet" >/dev/null 2>&1 || { echo "错误: 无效的IPv4子网"; return 1; }
    fi
    return 0
}

generate_client_ip() {
    local subnet=$1
    local config_file=$2
    local existing_ips=($(grep -E '^AllowedIPs = .*' "$CONFIG_DIR/$config_file.conf" | awk -F'[ /]+' '{print $3}'))

    if [[ "$subnet" == *:* ]]; then
        network_info=$(sipcalc "$subnet")
        network_start=$(echo "$network_info" | grep "Expanded address" | awk '{print $4}')
        prefix_length=$(echo "$subnet" | cut -d'/' -f2)

        for _ in {1..10}; do
            suffix=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ' | sed 's/^0000//')
            candidate_ip="${network_start%::*}::${suffix:0:4}:${suffix:4:4}"
            candidate_ip=$(echo "$candidate_ip" | sed 's/:0*/:/g; s/::*/::/g')
            if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
                echo "$candidate_ip"
                return 0
            fi
        done
        echo "错误: IPv6子网中没有可用地址"
        return 1
    else
        network_info=$(sipcalc "$subnet")
        hostmin=$(echo "$network_info" | grep "Usable range" | awk '{print $4}')
        hostmax=$(echo "$network_info" | grep "Usable range" | awk '{print $6}')

        IFS='.' read -r a b c d_start <<< "$hostmin"
        IFS='.' read -r a b c d_end <<< "$hostmax"

        for ((i=d_start + 1; i<=d_end; i++)); do
            candidate_ip="$a.$b.$c.$i"
            if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
                echo "$candidate_ip"
                return 0
            fi
        done
        echo "错误: IPv4子网中没有可用地址"
        return 1
    fi
}

get_available_port() {
    base_port=51620
    while :; do
        if ! ss -uln | grep -q ":$base_port "; then
            echo $base_port
            break
        fi
        ((base_port++))
    done
}

create_interface() {
    echo "正在创建新WireGuard接口..."

    read -p "是否启用IPv6支持？(y/N) " enable_ipv6
    enable_ipv6=${enable_ipv6:-N}

    init_ip_pool

    public_ip4=$(get_available_ip "$PUBLIC_IP_FILE" "$USED_IP_FILE") || { echo "$public_ip4" >&2; return 1; }
    mark_ip_used "$public_ip4" "$USED_IP_FILE"
    if [[ $enable_ipv6 =~ ^[Yy]$ ]]; then
        public_ip6=$(get_available_ip "$PUBLIC_IP6_FILE" "$USED_IP6_FILE") || { echo "$public_ip6" >&2; return 1; }
        mark_ip_used "$public_ip6" "$USED_IP6_FILE"
    else
        public_ip6=""
    fi

    while true; do
        read -p "输入IPv4子网（格式如 10.10.0.0/24）: " subnet4
        validate_subnet "$subnet4" && break
    done
    if [[ $enable_ipv6 =~ ^[Yy]$ ]]; then
        while true; do
            read -p "输入IPv6子网（如 fd00:1234::/64）: " subnet6
            validate_subnet "$subnet6" && break
        done
        gateway_ip6=$(sipcalc "$subnet6" | grep "Address (compressed)" | awk '{print $NF}' | cut -d'/' -f1)
    else
        subnet6=""; gateway_ip6=""
    fi

    network_info=$(sipcalc "$subnet4")
    hostmin=$(echo "$network_info" | grep "Usable range" | awk '{print $4}')
    gateway_ip4="$hostmin"

    existing_interfaces=($(ls "$CONFIG_DIR"/wg*.conf 2>/dev/null | sed 's/.*wg\([0-9]\+\).conf/\1/' | sort -n))
    max_interface=$(printf "%d\n" "${existing_interfaces[@]}" | sort -n | tail -1)
    new_interface=$((max_interface + 1))
    default_iface="wg${new_interface}"

    read -p "输入接口名称（默认 $default_iface）: " iface
    iface=${iface:-$default_iface}

    [[ "$iface" =~ [^a-zA-Z0-9] ]] && { echo "错误: 接口名称非法"; return 1; }
    [ -f "$CONFIG_DIR/$iface.conf" ] && { echo "错误: 接口已存在"; return 1; }
    ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)

    port=$(get_available_port)
    server_private=$(wg genkey)
    config_content="[Interface]\n"
    config_content+="Address = $gateway_ip4/$(cut -d'/' -f2 <<< "$subnet4")"
    [[ -n "$gateway_ip6" ]] && config_content+=", $gateway_ip6/$(cut -d'/' -f2 <<< "$subnet6")"
    config_content+="\nPrivateKey = $server_private\nListenPort = $port\nMTU = 1420\n"
    config_content+="PostUp = sysctl -w net.core.rmem_max=67108864; sysctl -w net.core.wmem_max=67108864\n"

    if [ -d "/sys/class/net/$ext_if/queues" ]; then
        queues=$(ethtool -l $ext_if 2>/dev/null | grep "Combined:" | head -1 | awk '{print $2}')
        if [ "$queues" -gt 0 ]; then
            config_content+="PostUp = ethtool -L $ext_if combined $queues || true\n"
        fi
    fi

    config_content+="\n# IPv4 NAT规则\n"
    config_content+="PostUp = iptables -t nat -A POSTROUTING -s $subnet4 -o $ext_if -j SNAT --to-source $public_ip4\n"
    config_content+="PostDown = iptables -t nat -D POSTROUTING -s $subnet4 -o $ext_if -j SNAT --to-source $public_ip4\n"
    if [[ $enable_ipv6 =~ ^[Yy]$ ]]; then
        config_content+="\n# IPv6 NAT规则\n"
        config_content+="PostUp = ip6tables -t nat -A POSTROUTING -s $subnet6 -o $ext_if -j SNAT --to-source $public_ip6\n"
        config_content+="PostDown = ip6tables -t nat -D POSTROUTING -s $subnet6 -o $ext_if -j SNAT --to-source $public_ip6\n"
    fi

    if dmesg | grep -q 'DMA accelerated'; then
        config_content+="PostUp = ethtool -G $ext_if rx 2047 tx 2047\n"
    fi

    echo -e "$config_content" > "$CONFIG_DIR/$iface.conf"
    chmod 600 "$CONFIG_DIR/$iface.conf"

    if systemctl enable --now "wg-quick@$iface" &>/dev/null; then
        echo "接口 $iface 创建成功！"
        echo "公网IPv4: $public_ip4 | 内网子网: $subnet4"
        [[ -n "$public_ip6" ]] && echo "公网IPv6: $public_ip6 | 内网子网: $subnet6"
    else
        rollback_ip_allocation "$public_ip4" "$USED_IP_FILE"
        [[ -n "$public_ip6" ]] && rollback_ip_allocation "$public_ip6" "$USED_IP6_FILE"
        echo "错误: 服务启动失败"
        return 1
    fi
}

# ========================
# 客户端管理功能
# ========================
add_client() {
    echo "正在添加新客户端..."
    latest_iface=$(ls -t "$CONFIG_DIR"/*.conf | xargs -n1 basename | cut -d. -f1 | head -1)
    [ -z "$latest_iface" ] && { echo "错误: 没有可用接口"; return 1; }

    read -p "选择接口（默认 $latest_iface）: " iface
    iface=${iface:-$latest_iface}
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && { echo "错误: 接口不存在"; return 1; }

    public_ip4=$(grep '^PostUp.*--to-source' "$CONFIG_DIR/$iface.conf" | sed -n 's/.*--to-source \([0-9.]\+\).*/\1/p' | xargs)
    if [[ ! "$public_ip4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "错误: 无效的公网IPv4地址: $public_ip4" >&2
        return 1
    fi
    subnet4=$(grep '^PostUp.*iptables -t nat -A POSTROUTING' "$CONFIG_DIR/$iface.conf" | grep -oP '\-s \K[0-9./]+')
    enable_ipv6=$(grep -q "^PostUp.*ip6tables" "$CONFIG_DIR/$iface.conf" && echo "Y" || echo "N")
    if [[ $enable_ipv6 == "Y" ]]; then
        public_ip6=$(grep '^PostUp.*ip6tables -t nat -A POSTROUTING.*--to-source' "$CONFIG_DIR/$iface.conf" | awk '{print $NF}' | xargs)
        subnet6=$(grep '^PostUp.*ip6tables -t nat -A POSTROUTING' "$CONFIG_DIR/$iface.conf" | awk '{print $8}')
    else
        public_ip6=""; subnet6=""
    fi

    port=$(grep '^ListenPort' "$CONFIG_DIR/$iface.conf" | awk '{print $3}' | xargs)

    if [ -z "$public_ip4" ] && [ -z "$public_ip6" ]; then
        echo "错误: 未找到公网IP地址" >&2
        return 1
    fi
    if [ -z "$port" ]; then
        echo "错误: 未找到监听端口" >&2
        return 1
    fi

    client_ip4=$(generate_client_ip "$subnet4" "$iface") || { echo "$client_ip4"; return 1; }
    if [[ $enable_ipv6 == "Y" ]]; then
        client_ip6=$(generate_client_ip "$subnet6" "$iface") || { echo "$client_ip6"; return 1; }
    fi

    client_name_default="${iface}_${client_ip4}"
    read -p "输入客户端名称（默认 $client_name_default）: " client_name
    client_name=${client_name:-"$client_name_default"}
    [[ "$client_name" =~ [/\\] ]] && { echo "错误: 名称含非法字符"; return 1; }

    client_private=$(wg genkey)
    client_preshared=$(wg genpsk)
    peer_config="\n[Peer]\n# $client_name\nPublicKey = $(echo "$client_private" | wg pubkey)\nPresharedKey = $client_preshared\nAllowedIPs = $client_ip4/32"
    [[ -n "$client_ip6" ]] && peer_config+=", $client_ip6/128"
    echo -e "$peer_config" >> "$CONFIG_DIR/$iface.conf"

    mkdir -p "$CLIENT_DIR/$iface"
    client_file="$CLIENT_DIR/$iface/$client_name.conf"
    cat > "$client_file" << EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip4/24
$( [[ -n "$client_ip6" ]] && echo "Address = $client_ip6/64" )
DNS = 8.8.8.8, 2001:4860:4860::8888

[Peer]
PublicKey = $(grep 'PrivateKey' "$CONFIG_DIR/$iface.conf" | awk '{print $3}' | wg pubkey)
PresharedKey = $client_preshared
Endpoint = $public_ip4:$port
AllowedIPs = 0.0.0.0/0${client_ip6:+, ::/0}
PersistentKeepalive = 15
EOF

    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"
    systemctl restart "wg-quick@$iface" &>/dev/null || wg syncconf "$iface" <(wg-quick strip "$iface")
    echo "客户端 $client_name 添加成功！配置文件: $client_file"
}

# ========================
# 完全卸载功能
# ========================
uninstall_wireguard() {
    read -p "确定要完全卸载WireGuard吗？(y/N) " confirm
    [[ $confirm =~ ^[Yy]$ ]] || return

    echo "正在卸载WireGuard..."
    find "$CONFIG_DIR" -name '*.conf' -exec basename {} .conf \; | while read -r iface; do
        systemctl stop "wg-quick@$iface"
    done

    rm -rf "$CONFIG_DIR"
    apt-get purge -y wireguard-tools iptables-persistent qrencode

    iptables -F; iptables -t nat -F
    ip6tables -F; ip6tables -t nat -F

    echo "WireGuard已完全卸载"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=("安装依赖" "创建接口" "添加客户端" "完全卸载" "退出")
    select opt in "${options[@]}"; do
        case $opt in
            "安装依赖") install_dependencies ;;
            "创建接口") create_interface ;;
            "添加客户端") add_client ;;
            "完全卸载") uninstall_wireguard ;;
            "退出")
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4
                ip6tables-save > /etc/iptables/rules.v6
                echo "配置已保存，再见！"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
}

mkdir -p "$CLIENT_DIR"
main_menu
