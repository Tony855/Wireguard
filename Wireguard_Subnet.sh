#!/bin/bash
#
# https://github.com/hwdsl2/wireguard-install
#
# Modified version with custom subnet support
# Original credits: Lin Song, Nyr and contributors

# 错误处理函数
exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

# 新增：子网变量声明
subnet_ipv4=""
subnet_ipv6=""

# 新增：CIDR格式验证函数
check_ipv4_cidr() {
    echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
}

check_ipv6_cidr() {
    echo "$1" | grep -Eq '^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$'
}

# 新增：自定义子网输入函数
enter_custom_subnet() {
    while true; do
        echo
        read -rp "请输入自定义IPv4子网（格式：x.x.x.x/xx，示例：10.17.0.1/24）: " subnet_ipv4
        if check_ipv4_cidr "$subnet_ipv4"; then
            break
        else
            echo "错误：无效的IPv4子网格式，请重新输入"
        fi
    done

    echo
    read -rp "是否配置IPv6子网？[y/N]: " use_ipv6
    if [[ "$use_ipv6" =~ [yY] ]]; then
        while true; do
            read -rp "请输入IPv6子网（格式：xxxx::x/xx，示例：fddd:2c4:2c4:2c4::1/64）: " subnet_ipv6
            if check_ipv6_cidr "$subnet_ipv6"; then
                break
            else
                echo "错误：无效的IPv6子网格式，请重新输入"
            fi
        done
    fi
}

# 自动生成客户端名称函数
generate_client_name() {
    while true; do
        timestamp=$(date +%y%m%d%M%S)
        random_str=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 5)
        pid=$(echo $$ | cut -c 1-3)
        base_unsanitized="clt-${timestamp}-${random_str}-${pid}"
        unsanitized_client="$base_unsanitized"
        set_client_name
        if [ -z "$client" ]; then
            continue
        fi
        if ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
            echo "$unsanitized_client"
            return
        fi
        counter=1
        while [ $counter -le 99 ]; do
            unsanitized_client="${base_unsanitized}-$(printf "%03d" $counter)"
            set_client_name
            if [ -z "$client" ]; then
                continue
            fi
            if ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
                echo "$unsanitized_client"
                return
            fi
            ((counter++))
        done
        exiterr "无法生成唯一名称（尝试了99次），请手动指定或清理旧配置。"
    done
}

set_client_name() {
    client=$(sed 's/[^A-Za-z0-9_-]/_/g' <<< "$unsanitized_client" | cut -c-20)
    if [ -z "$client" ]; then
        client="client-$(date +%s | sha256sum | base64 | head -c 4)"
    fi
}

# IP验证函数
check_ip() {
    IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_pvt_ip() {
    IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

check_dns_name() {
    FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

# 系统检查函数
check_root() {
    if [ "$(id -u)" != 0 ]; then
        exiterr "This installer must be run as root. Try 'sudo bash $0'"
    fi
}

check_shell() {
    if readlink /proc/$$/exe | grep -q "dash"; then
        exiterr 'This installer needs to be run with "bash", not "sh".'
    fi
}

check_kernel() {
    if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        exiterr "The system is running an old kernel, which is incompatible with this installer."
    fi
}

check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
        os="openSUSE"
        os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        exiterr "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora and openSUSE."
    fi
}

check_os_ver() {
    if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
        exiterr "Ubuntu 20.04 or higher is required to use this installer."
    fi
    if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
        exiterr "Debian 11 or higher is required to use this installer."
    fi
    if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
        exiterr "CentOS 8 or higher is required to use this installer."
    fi
}

check_container() {
    if systemd-detect-virt -cq 2>/dev/null; then
        exiterr "This system is running inside a container, which is not supported by this installer."
    fi
}

# 参数解析函数
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --auto)
                auto=1
                if [[ "$2" != --* && -n "$2" ]]; then
                    first_client_name="$2"
                    shift
                fi
                shift
                ;;
            --addclient)
                add_client=1
                if [[ "$2" != --* && -n "$2" ]]; then
                    unsanitized_client="$2"
                    shift
                else
                    unsanitized_client=$(generate_client_name)
                fi
                shift
                ;;
            --listclients)
                list_clients=1
                shift
                ;;
            --removeclient)
                remove_client=1
                unsanitized_client="$2"
                shift
                shift
                ;;
            --showclientqr)
                show_client_qr=1
                unsanitized_client="$2"
                shift
                shift
                ;;
            --uninstall)
                remove_wg=1
                shift
                ;;
            --serveraddr)
                server_addr="$2"
                shift
                shift
                ;;
            --port)
                server_port="$2"
                shift
                shift
                ;;
            --clientname)
                first_client_name="$2"
                shift
                shift
                ;;
            --dns1)
                dns1="$2"
                shift
                shift
                ;;
            --dns2)
                dns2="$2"
                shift
                shift
                ;;
            -y|--yes)
                assume_yes=1
                shift
                ;;
            -h|--help)
                show_usage
                ;;
            *)
                show_usage "Unknown parameter: $1"
                ;;
        esac
    done
}

# 修改：服务器配置生成
create_server_config() {
    ipv4_address=$(echo "$subnet_ipv4" | cut -d '/' -f 1)
    ipv4_cidr=$(echo "$subnet_ipv4" | cut -d '/' -f 2)
    ipv6_part=""
    [ -n "$subnet_ipv6" ] && ipv6_part=", $subnet_ipv6"

    cat << EOF > "$WG_CONF"
# Do not alter the commented lines
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = ${ipv4_address}/${ipv4_cidr}${ipv6_part}
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
    chmod 600 "$WG_CONF"
}

# 修改：客户端IP分配逻辑
select_client_ip() {
    base_network=$(echo "$subnet_ipv4" | cut -d '.' -f 1-3)
    octet=2
    while grep AllowedIPs "$WG_CONF" | grep -Eq "${base_network}\.${octet}/32"; do
        (( octet++ ))
    done
    if [[ "$octet" -eq 255 ]]; then
        exiterr "子网 ${subnet_ipv4} 已分配满253个客户端！"
    fi
    client_ip="${base_network}.${octet}"
}

# 修改：防火墙规则生成
create_firewall_rules() {
    ipv4_network=$(echo "$subnet_ipv4" | cut -d '/' -f 1)
    ipv4_cidr=$(echo "$subnet_ipv4" | cut -d '/' -f 2)

    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd -q --zone=trusted --add-source=${ipv4_network}/${ipv4_cidr}
        firewall-cmd -q --permanent --zone=trusted --add-source=${ipv4_network}/${ipv4_cidr}
        firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s ${ipv4_network}/${ipv4_cidr} ! -d ${ipv4_network}/${ipv4_cidr} -j MASQUERADE
        firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s ${ipv4_network}/${ipv4_cidr} ! -d ${ipv4_network}/${ipv4_cidr} -j MASQUERADE

        if [ -n "$subnet_ipv6" ]; then
            firewall-cmd -q --zone=trusted --add-source=${subnet_ipv6}
            firewall-cmd -q --permanent --zone=trusted --add-source=${subnet_ipv6}
            firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s ${subnet_ipv6} ! -d ${subnet_ipv6} -j MASQUERADE
            firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s ${subnet_ipv6} ! -d ${subnet_ipv6} -j MASQUERADE
        fi
    else
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s ${ipv4_network}/${ipv4_cidr} ! -d ${ipv4_network}/${ipv4_cidr} -j MASQUERADE
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s ${ipv4_network}/${ipv4_cidr} -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s ${ipv4_network}/${ipv4_cidr} ! -d ${ipv4_network}/${ipv4_cidr} -j MASQUERADE
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s ${ipv4_network}/${ipv4_cidr} -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
        if [[ -n "$subnet_ipv6" ]]; then
            echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s ${subnet_ipv6} ! -d ${subnet_ipv6} -j MASQUERADE
ExecStart=$ip6tables_path -I FORWARD -s ${subnet_ipv6} -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s ${subnet_ipv6} ! -d ${subnet_ipv6} -j MASQUERADE
ExecStop=$ip6tables_path -D FORWARD -s ${subnet_ipv6} -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
        fi
        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
        (
            set -x
            systemctl enable --now wg-iptables.service >/dev/null 2>&1
        )
    fi
}

# 修改：客户端配置文件生成
new_client() {
    select_client_ip
    base_network=$(echo "$subnet_ipv4" | cut -d '.' -f 1-3)
    client_ip="${base_network}.${octet}"

    key=$(wg genkey)
    psk=$(wg genpsk)
    cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = ${client_ip}/32$(grep -q "$subnet_ipv6" "$WG_CONF" && echo ", ${subnet_ipv6%/*}$octet/128")
# END_PEER $client
EOF
    get_export_dir
    cat << EOF > "$export_dir$client".conf
[Interface]
Address = ${client_ip}/$(echo "$subnet_ipv4" | cut -d '/' -f 2)$([ -n "$subnet_ipv6" ] && echo ", ${subnet_ipv6%/*}$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0
Endpoint = $(grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3):$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
PersistentKeepalive = 15
EOF
    if [ "$export_to_home_dir" = 1 ]; then
        chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
    fi
    chmod 600 "$export_dir$client".conf
}

# 主安装流程
wgsetup() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    check_root
    check_shell
    check_kernel
    check_os
    check_os_ver
    check_container

    WG_CONF="/etc/wireguard/wg0.conf"

    auto=0
    assume_yes=0
    add_client=0
    list_clients=0
    remove_client=0
    show_client_qr=0
    remove_wg=0
    public_ip=""
    server_addr=""
    server_port=""
    first_client_name=""
    unsanitized_client=""
    client=""
    dns=""
    dns1=""
    dns2=""

    parse_args "$@"
    check_args

    if [ "$add_client" = 1 ]; then
        show_header
        new_client add_client
        update_wg_conf
        echo
        show_client_qr_code
        print_client_added
        exit 0
    fi

    if [ "$list_clients" = 1 ]; then
        show_header
        print_check_clients
        check_clients
        echo
        show_clients
        print_client_total
        exit 0
    fi

    if [ "$remove_client" = 1 ]; then
        show_header
        confirm_remove_client
        if [[ "$remove" =~ ^[yY]$ ]]; then
            print_remove_client
            remove_client_wg
            print_client_removed
            exit 0
        else
            print_client_removal_aborted
            exit 1
        fi
    fi

    if [ "$show_client_qr" = 1 ]; then
        show_header
        echo
        get_export_dir
        check_client_conf
        show_client_qr_code
        print_client_conf
        exit 0
    fi

    if [ "$remove_wg" = 1 ]; then
        show_header
        confirm_remove_wg
        if [[ "$remove" =~ ^[yY]$ ]]; then
            print_remove_wg
            remove_firewall_rules
            disable_wg_service
            remove_sysctl_rules
            remove_rclocal_rules
            remove_pkgs
            print_wg_removed
            exit 0
        else
            print_wg_removal_aborted
            exit 1
        fi
    fi

    if [[ ! -e "$WG_CONF" ]]; then
        check_nftables
        install_wget
        install_iproute
        show_welcome
        enter_custom_subnet
        if [ "$auto" = 0 ]; then
            enter_server_address
        else
            if [ -n "$server_addr" ]; then
                ip="$server_addr"
            else
                detect_ip
                check_nat_ip
            fi
        fi
        show_config
        detect_ipv6
        select_port
        enter_first_client_name
        if [ "$auto" = 0 ]; then
            select_dns
        fi
        show_setup_ready
        check_firewall
        confirm_setup
        show_start_setup
        install_pkgs
        create_server_config
        update_sysctl
        create_firewall_rules
        if [ "$os" != "openSUSE" ]; then
            update_rclocal
        fi
        new_client
        start_wg_service
        echo
        show_client_qr_code
        if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
            show_dns_name_note "$server_addr"
        fi
        finish_setup
    else
        show_header
        select_menu_option
        case "$option" in
            1)
                enter_client_name
                select_dns
                new_client add_client
                update_wg_conf
                echo
                show_client_qr_code
                print_client_added
                exit 0
                ;;
            2)
                print_check_clients
                check_clients
                echo
                show_clients
                print_client_total
                exit 0
                ;;
            3)
                check_clients
                select_client_to remove
                confirm_remove_client
                if [[ "$remove" =~ ^[yY]$ ]]; then
                    print_remove_client
                    remove_client_wg
                    print_client_removed
                    exit 0
                else
                    print_client_removal_aborted
                    exit 1
                fi
                ;;
            4)
                check_clients
                select_client_to "show QR code for"
                echo
                get_export_dir
                check_client_conf
                show_client_qr_code
                print_client_conf
                exit 0
                ;;
            5)
                confirm_remove_wg
                if [[ "$remove" =~ ^[yY]$ ]]; then
                    print_remove_wg
                    remove_firewall_rules
                    disable_wg_service
                    remove_sysctl_rules
                    remove_rclocal_rules
                    remove_pkgs
                    print_wg_removed
                    exit 0
                else
                    print_wg_removal_aborted
                    exit 1
                fi
                ;;
        esac
    fi
}

# 脚本入口
wgsetup "$@"
exit 0
