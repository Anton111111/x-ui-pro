#!/bin/bash
source <(curl -s https://raw.githubusercontent.com/anton111111/x-ui-pro/master/functions.sh)
#################### x-ui-pro v2.4.3 @ github.com/GFW4Fun ##############################################
[[ $EUID -ne 0 ]] && echo "not root!" && sudo su -
##############################INFO######################################################################
echo
msg_inf '           ___    _   _   _  '
msg_inf ' \/ __ | |  | __ |_) |_) / \ '
msg_inf ' /\    |_| _|_   |   | \ \_/ '
echo
##################################Variables#############################################################
XUIDB="/etc/x-ui/x-ui.db"
domain=""
UNINSTALL="x"
INSTALL="n"
PNLNUM=1
CFALLOW="n"
CLASH=0
CUSTOMWEBSUB=0
Pak=$(type apt &>/dev/null && echo "apt" || echo "yum")
systemctl stop x-ui
rm -rf /etc/systemd/system/x-ui.service
rm -rf /usr/local/x-ui
rm -rf /etc/x-ui
rm -rf /etc/nginx/sites-enabled/*
rm -rf /etc/nginx/sites-available/*
rm -rf /etc/nginx/stream-enabled/*

##################################generate ports and paths#############################################################

sub_port=$(make_port)
panel_port=$(make_port)
web_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
sub2singbox_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
sub_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
json_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
panel_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
awg_panel_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
ws_port=$(make_port)
ws_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")web_path
xhttp_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
config_username=$(gen_random_string 10)
config_password=$(gen_random_string 10)

################################Get arguments###########################################################
while [ "$#" -gt 0 ]; do
  case "$1" in
  -install)
    INSTALL="$2"
    shift 2
    ;;
  -panel)
    PNLNUM="$2"
    shift 2
    ;;
  -subdomain)
    domain="$2"
    shift 2
    ;;
  -reality_domain)
    reality_domain="$2"
    shift 2
    ;;
  -awg_password)
    awg_password="$2"
    shift 2
    ;;
  -ONLY_CF_IP_ALLOW)
    CFALLOW="$2"
    shift 2
    ;;
  -websub)
    CUSTOMWEBSUB="$2"
    shift 2
    ;;
  -clash)
    CLASH="$2"
    shift 2
    ;;
  -uninstall)
    UNINSTALL="$2"
    shift 2
    ;;
  *) shift 1 ;;
  esac
done

##############################Uninstall#################################################################
uninstall_xui() {
  printf 'y\n' | x-ui uninstall
  rm -rf "/etc/x-ui/" "/usr/local/x-ui/" "/usr/bin/x-ui/"
  $Pak -y remove nginx nginx-common nginx-core nginx-full python3-certbot-nginx
  $Pak -y purge nginx nginx-common nginx-core nginx-full python3-certbot-nginx
  $Pak -y autoremove
  $Pak -y autoclean
  rm -rf "/var/www/html/" "/etc/nginx/" "/usr/share/nginx/"
  crontab -l | grep -v "certbot\|x-ui\|cloudflareips" | crontab -
  docker rm -f amnezia-wg-easy >/dev/null 2>&1
  rm -rf "/etc/amnezia-wg-easy/"
}
if [[ ${UNINSTALL} == *"y"* ]]; then
  uninstall_xui
  clear && msg_ok "Completely Uninstalled!" && exit 1
fi
##############################Input Validations########################################################
while true; do
  if [[ -n "$domain" ]]; then
    break
  fi
  echo -en "Enter available subdomain for panels (sub.domain.tld): " && read domain
done

domain=$(echo "$domain" 2>&1 | tr -d '[:space:]')

while true; do
  if [[ -n "$reality_domain" ]]; then
    break
  fi
  echo -en "Enter available subdomain for REALITY (sub.domain.tld): " && read reality_domain
done

reality_domain=$(echo "$reality_domain" 2>&1 | tr -d '[:space:]')

while true; do
  if [[ -n "$awg_password" ]]; then
    break
  fi
  echo -en "Enter Password for AWG: " && read awg_password
done

awg_password=$(echo "$awg_password" 2>&1 | tr -d '[:space:]')

###############################Install Packages#########################################################
ufw disable
if [[ ${INSTALL} == *"y"* ]]; then

  version=$(grep -oP '(?<=VERSION_ID=")[0-9]+' /etc/os-release)

  # Проверяем, является ли версия 20 или 22
  if [[ "$version" == "20" || "$version" == "22" ]]; then
    echo "Версия системы: Ubuntu $version"
  fi

  $Pak -y update

  $Pak -y install curl wget jq bash sudo nginx-full certbot python3-certbot-nginx sqlite3 ufw

  systemctl daemon-reload && systemctl enable --now nginx
fi
systemctl stop nginx
fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
##################################GET SERVER IPv4-6#####################################################
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*')
IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*')
[[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com)
[[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com)
##############################Install SSL###############################################################
install_cert "$domain"
install_cert "$reality_domain"
################################# Access to configs only with cloudflare#################################
rm -f "/etc/nginx/cloudflareips.sh"
cat <<'EOF' >>/etc/nginx/cloudflareips.sh
#!/bin/bash
rm -f "/etc/nginx/conf.d/cloudflare_real_ips.conf" "/etc/nginx/conf.d/cloudflare_whitelist.conf"
CLOUDFLARE_REAL_IPS_PATH=/etc/nginx/conf.d/cloudflare_real_ips.conf
CLOUDFLARE_WHITELIST_PATH=/etc/nginx/conf.d/cloudflare_whitelist.conf
echo "geo \$realip_remote_addr \$cloudflare_ip {
	default 0;" >> $CLOUDFLARE_WHITELIST_PATH
for type in v4 v6; do
	echo "# IP$type"
	for ip in `curl https://www.cloudflare.com/ips-$type`; do
		echo "set_real_ip_from $ip;" >> $CLOUDFLARE_REAL_IPS_PATH;
		echo "	$ip 1;" >> $CLOUDFLARE_WHITELIST_PATH;
	done
done
echo "real_ip_header X-Forwarded-For;" >> $CLOUDFLARE_REAL_IPS_PATH
echo "}" >> $CLOUDFLARE_WHITELIST_PATH
EOF
sudo bash "/etc/nginx/cloudflareips.sh" >/dev/null 2>&1
if [[ ${CFALLOW} == *"y"* ]]; then
  CF_IP=""
else
  CF_IP="#"
fi
###################################Get Installed XUI Port/Path##########################################
if [[ -f $XUIDB ]]; then
  XUIPORT=$(sqlite3 -list $XUIDB 'SELECT "value" FROM settings WHERE "key"="webPort" LIMIT 1;' 2>&1)
  XUIPATH=$(sqlite3 -list $XUIDB 'SELECT "value" FROM settings WHERE "key"="webBasePath" LIMIT 1;' 2>&1)
  if [[ $XUIPORT -gt 0 && $XUIPORT != "54321" && $XUIPORT != "2053" ]] && [[ ${#XUIPORT} -gt 4 ]]; then
    RNDSTR=$(echo "$XUIPATH" 2>&1 | tr -d '/')
    PORT=$XUIPORT
    sqlite3 $XUIDB <<EOF
	DELETE FROM "settings" WHERE ( "key"="webCertFile" ) OR ( "key"="webKeyFile" ); 
	INSERT INTO "settings" ("key", "value") VALUES ("webCertFile",  "");
	INSERT INTO "settings" ("key", "value") VALUES ("webKeyFile", "");
EOF
  fi
fi
#################################Nginx Config###########################################################
mkdir -p /etc/nginx/stream-enabled
cat >"/etc/nginx/stream-enabled/stream.conf" <<EOF
map \$ssl_preread_server_name \$sni_name {
    hostnames;
    ${reality_domain}      xray;
    ${domain}           www;
    default              xray;
}

upstream xray {
    server 127.0.0.1:8443;
}

upstream www {
    server 127.0.0.1:7443;
}

server {
    proxy_protocol on;
    set_real_ip_from unix:;
    listen          443;
    proxy_pass      \$sni_name;
    ssl_preread     on;
}

EOF

grep -xqFR "stream { include /etc/nginx/stream-enabled/*.conf; }" /etc/nginx/* || echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >>/etc/nginx/nginx.conf
grep -xqFR "load_module modules/ngx_stream_module.so;" /etc/nginx/* || sed -i '1s/^/load_module \/usr\/lib\/nginx\/modules\/ngx_stream_module.so; /' /etc/nginx/nginx.conf
grep -xqFR "load_module modules/ngx_stream_geoip2_module.so;" /etc/nginx* || sed -i '2s/^/load_module \/usr\/lib\/nginx\/modules\/ngx_stream_geoip2_module.so; /' /etc/nginx/nginx.conf
grep -xqFR "worker_rlimit_nofile 16384;" /etc/nginx/* || echo "worker_rlimit_nofile 16384;" >>/etc/nginx/nginx.conf
sed -i "/worker_connections/c\worker_connections 4096;" /etc/nginx/nginx.conf
cat >"/etc/nginx/sites-available/80.conf" <<EOF
server {
    listen 80;
    server_name ${domain} ${reality_domain};
    return 301 https://\$host\$request_uri;
}
EOF

cat >"/etc/nginx/sites-available/${domain}" <<EOF
server {
	server_tokens off;
	server_name ${domain};
	listen 7443 ssl http2 proxy_protocol;
	listen [::]:7443 ssl http2 proxy_protocol;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
	if (\$host !~* ^(.+\.)?$domain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$domain\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel
	location /${panel_path}/ {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:${panel_port};
		break;
	}
  #AmneziaWG Easy Panel
	location /${awg_panel_path}/ {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:51821;
    rewrite ^/${awg_panel_path}/(.*)$ /\$1 break;
		break;
	}
        
 	#Subscription Path (simple/encode)
	location /${sub_path}/ {
    if (\$hack = 1) {return 404;}
    proxy_redirect off;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:${sub_port};
    break;
  }
	#Subscription Path (json/fragment)
	location /${json_path}/ {
    if (\$hack = 1) {return 404;}
    proxy_redirect off;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:${sub_port};
    break;
  }
  #XHTTP
  location /${xhttp_path} {
    grpc_pass grpc://unix:/dev/shm/uds2023.sock;
    grpc_buffer_size         16k;
    grpc_socket_keepalive    on;
    grpc_read_timeout        1h;
    grpc_send_timeout        1h;
    grpc_set_header Connection         "";
    grpc_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
    grpc_set_header X-Forwarded-Proto  \$scheme;
    grpc_set_header X-Forwarded-Port   \$server_port;
    grpc_set_header Host               \$host;
    grpc_set_header X-Forwarded-Host   \$host;
  }
 	#Xray Config Path
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
	$CF_IP	if (\$cloudflare_ip != 1) {return 404;}
		if (\$hack = 1) {return 404;}
		client_max_body_size 0;
		client_body_timeout 1d;
		grpc_read_timeout 1d;
		grpc_socket_keepalive on;
		proxy_read_timeout 1d;
		proxy_http_version 1.1;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_socket_keepalive on;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		#proxy_set_header CF-IPCountry \$http_cf_ipcountry;
		#proxy_set_header CF-IP \$realip_remote_addr;
		if (\$content_type ~* "GRPC") {
			grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
		if (\$http_upgrade ~* "(WEBSOCKET|WS)") {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
	        }
		if (\$request_method ~* ^(PUT|POST|GET)\$) {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
	}
	location / { try_files \$uri \$uri/ =404; }
}
EOF

cat >"/etc/nginx/sites-available/${reality_domain}" <<EOF
server {
	server_tokens off;
	server_name ${reality_domain};
	listen 9443 ssl http2;
	listen [::]:9443 ssl http2;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$reality_domain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$reality_domain/privkey.pem;
	if (\$host !~* ^(.+\.)?${reality_domain}\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?${reality_domain}\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	
  #XHTTP
  location /${xhttp_path} {
    grpc_pass grpc://unix:/dev/shm/uds2023.sock;
    grpc_buffer_size         16k;
    grpc_socket_keepalive    on;
    grpc_read_timeout        1h;
    grpc_send_timeout        1h;
    grpc_set_header Connection         "";
    grpc_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
    grpc_set_header X-Forwarded-Proto  \$scheme;
    grpc_set_header X-Forwarded-Port   \$server_port;
    grpc_set_header Host               \$host;
    grpc_set_header X-Forwarded-Host   \$host;
  }
 	#Xray Config Path
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
	$CF_IP	if (\$cloudflare_ip != 1) {return 404;}
		if (\$hack = 1) {return 404;}
		client_max_body_size 0;
		client_body_timeout 1d;
		grpc_read_timeout 1d;
		grpc_socket_keepalive on;
		proxy_read_timeout 1d;
		proxy_http_version 1.1;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_socket_keepalive on;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		#proxy_set_header CF-IPCountry \$http_cf_ipcountry;
		#proxy_set_header CF-IP \$realip_remote_addr;
		if (\$content_type ~* "GRPC") {
			grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
		if (\$http_upgrade ~* "(WEBSOCKET|WS)") {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
	        }
		if (\$request_method ~* ^(PUT|POST|GET)\$) {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
	}
	location / { try_files \$uri \$uri/ =404; }
}
EOF

##################################Check Nginx status####################################################
if [[ -f "/etc/nginx/sites-available/${domain}" ]]; then
  unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
  rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
  ln -s "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/" 2>/dev/null
  ln -s "/etc/nginx/sites-available/${reality_domain}" "/etc/nginx/sites-enabled/" 2>/dev/null
  ln -s "/etc/nginx/sites-available/80.conf" "/etc/nginx/sites-enabled/" 2>/dev/null
else
  msg_err "${domain} nginx config not exist!" && exit 1
fi

if [[ $(nginx -t 2>&1 | grep -o 'successful') != "successful" ]]; then
  msg_err "nginx config is not ok!" && exit 1
else
  systemctl start nginx
fi

##############################generate keys###########################################################
shor=($(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8))
###################################Install X-UI#########################################################
if systemctl is-active --quiet x-ui; then
  x-ui restart
else
  PANEL=("https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh"
    "https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh"
    "https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install_en.sh"
  )

  printf 'n\n' | bash <(wget -qO- "${PANEL[$PNLNUM]}")
  update_xuidb
  if ! systemctl is-enabled --quiet x-ui; then
    systemctl daemon-reload && systemctl enable x-ui.service
  fi
  x-ui restart
fi

###################################Install AmneziaWG Easy#########################################################
awg_password_raw=$(docker run -it ghcr.io/w0rng/amnezia-wg-easy wgpw "$awg_password")
awg_password_clean=$(printf "%s" "$awg_password_raw" | cut -d= -f2- | tr -d '\r\n')
awg_password_clean=${awg_password_clean:1:${#awg_password_clean}-2}
docker rm -f amnezia-wg-easy >/dev/null 2>&1
docker run -d \
  --name=amnezia-wg-easy \
  -e LANG=en \
  -e WG_HOST=$IP4 \
  -e PASSWORD_HASH=$awg_password_clean \
  -e PORT=51821 \
  -e WG_PORT=51820 \
  -v /etc/amnezia-wg-easy:/etc/wireguard \
  -p 51820:51820/udp \
  -p 127.0.0.1:51821:51821/tcp \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --sysctl="net.ipv4.conf.all.src_valid_mark=1" \
  --sysctl="net.ipv4.ip_forward=1" \
  --device=/dev/net/tun:/dev/net/tun \
  --restart unless-stopped \
  ghcr.io/w0rng/amnezia-wg-easy

######################enable bbr and tune system########################################################
apt-get install -yqq --no-install-recommends ca-certificates
echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf
echo "fs.file-max=2097152" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 1" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_sack = 1" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling = 1" | tee -a /etc/sysctl.conf
echo "net.core.rmem_max = 16777216" | tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 16777216" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 87380 16777216" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" | tee -a /etc/sysctl.conf

sysctl -p

######################install_fake_site#################################################################

sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/mozaroc/x-ui-pro/refs/heads/master/randomfakehtml.sh)"

######################cronjob for ssl/reload service/cloudflareips######################################
crontab -l | grep -v "certbot\|x-ui\|cloudflareips" | crontab -
(
  crontab -l 2>/dev/null
  echo '@daily x-ui restart > /dev/null 2>&1 && nginx -s reload;'
) | crontab -
(
  crontab -l 2>/dev/null
  echo '@weekly bash /etc/nginx/cloudflareips.sh > /dev/null 2>&1;'
) | crontab -
(
  crontab -l 2>/dev/null
  echo '@monthly certbot renew --nginx --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1;'
) | crontab -
##################################ufw###################################################################
ufw disable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
##################################Show Details##########################################################

if systemctl is-active --quiet x-ui; then
  clear
  printf '0\n' | x-ui | grep --color=never -i ':'
  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  nginx -T | grep -i 'ssl_certificate\|ssl_certificate_key'
  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  certbot certificates | grep -i 'Path:\|Domains:\|Expiry Date:'

  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  msg_inf "X-UI Secure Panel: https://${domain}/${panel_path}/\n"
  echo -e "Username:  ${config_username} \n"
  echo -e "Password:  ${config_password} \n"
  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  msg_inf "AmneziaWG Easy Secure Panel: https://${domain}/${awg_panel_path}/\n"
  echo -e "Password:  ${awg_password} \n"
  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  msg_inf "XKeen Subsciption: https://${domain}/${sub_path}/xkeen\n"
  msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  msg_inf "Please Save this Screen!!"
else
  nginx -t && printf '0\n' | x-ui | grep --color=never -i ':'
  msg_err "sqlite and x-ui to be checked, try on a new clean linux! "
fi
#################################################N-joy##################################################
