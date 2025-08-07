#!/bin/bash
##############################INFO######################################################################
msg_ok() { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }

##################################generate ports and paths#############################################################
get_port() {
    echo $((((RANDOM << 15) | RANDOM) % 49152 + 10000))
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}
check_free() {
    local port=$1
    nc -z 127.0.0.1 $port &>/dev/null
    return $?
}

make_port() {
    while true; do
        PORT=$(get_port)
        if ! check_free $PORT; then
            echo $PORT
            break
        fi
    done
}

##############################Install SSL###############################################################
install_cert() {
    domain="$1"
    certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$domain"
    if [[ ! -d "/etc/letsencrypt/live/${domain}/" ]]; then
        systemctl start nginx >/dev/null 2>&1
        msg_err "$domain SSL could not be generated! Check Domain/IP Or Enter new domain!" && exit 1
    fi
}

#################################Nginx Config###########################################################
create_service_nginx() {
    domain="$1"
    port="$2"
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
 	location / {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:$port;
		break;
	}
}
EOF
}

########################################Update X-UI Port/Path for first INSTALL#########################
update_xuidb() {
    if [[ -f $XUIDB ]]; then
        x-ui stop
        var1=$(/usr/local/x-ui/bin/xray-linux-amd64 x25519)
        var2=($var1)
        private_key=${var2[2]}
        public_key=${var2[5]}
        client_id=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
        client_id2=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
        client_id3=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
        emoji_flag=$(LC_ALL=en_US.UTF-8 curl -s https://ipwho.is/ | jq -r '.flag.emoji')
        sqlite3 $XUIDB <<EOF
INSERT INTO "settings" ("key", "value") VALUES ("subPort",  '${sub_port}');
INSERT INTO "settings" ("key", "value") VALUES ("subPath",  '${sub_path}');
INSERT INTO "settings" ("key", "value") VALUES ("subURI",  '${sub_uri}');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonPath",  '${json_path}');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonURI",  '${json_uri}');
INSERT INTO "settings" ("key", "value") VALUES ("subEnable",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("webListen",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webDomain",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webCertFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webKeyFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("sessionMaxAge",  '60');
INSERT INTO "settings" ("key", "value") VALUES ("pageSize",  '50');
INSERT INTO "settings" ("key", "value") VALUES ("expireDiff",  '0');
INSERT INTO "settings" ("key", "value") VALUES ("trafficDiff",  '0');
INSERT INTO "settings" ("key", "value") VALUES ("remarkModel",  '-ieo');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotEnable",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotToken",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotProxy",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotAPIServer",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotChatId",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgRunTime",  '@daily');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotBackup",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotLoginNotify",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("tgCpu",  '80');
INSERT INTO "settings" ("key", "value") VALUES ("tgLang",  'en-US');
INSERT INTO "settings" ("key", "value") VALUES ("timeLocation",  'Europe/Moscow');
INSERT INTO "settings" ("key", "value") VALUES ("secretEnable",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("subDomain",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subCertFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subKeyFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subUpdates",  '12');
INSERT INTO "settings" ("key", "value") VALUES ("subEncrypt",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("subShowInfo",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonFragment",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonNoises",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonMux",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonRules",  '');
INSERT INTO "settings" ("key", "value") VALUES ("datepicker",  'gregorian');
INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('1','1','first','0','0','0','0','0');
INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('2','1','first_1','0','0','0','0','0');
INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing","allocate") 
VALUES
  (
    '1',
    '0',
    '0',
    '0',
    '',
    '1',
    '0',
    '',
    '8443',
    'vless',
    '{
	     "clients": [
    {
      "id": "${client_id}",
      "flow": "xtls-rprx-vision",
      "email": "${emoji_flag}-reality-xkeen",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "xkeen",
      "reset": 0
    }
  ],
  "decryption": "none",
  "fallbacks": []
}',
    '{
  "network": "tcp",
  "security": "reality",
  "externalProxy": [
    {
      "forceTls": "same",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "realitySettings": {
    "show": false,
    "xver": 0,
    "dest": "${reality_domain}:9443",
    "serverNames": [
      "$reality_domain"
    ],
    "privateKey": "${private_key}",
    "minClient": "",
    "maxClient": "",
    "maxTimediff": 0,
    "shortIds": [
      "${shor[0]}",
      "${shor[1]}",
      "${shor[2]}",
      "${shor[3]}",
      "${shor[4]}",
      "${shor[5]}",
      "${shor[6]}",
      "${shor[7]}"
    ],
    "settings": {
      "publicKey": "${public_key}",
      "fingerprint": "random",
      "serverName": "",
      "spiderX": "/"
    }
  },
  "tcpSettings": {
    "acceptProxyProtocol": true,
    "header": {
      "type": "none"
    }
  }
}',
    'inbound-8443',
    '{
  "enabled": true,
  "destOverride": [
    "http",
    "tls",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}',
    '{
  "strategy": "always",
  "refresh": 5,
  "concurrency": 3
}'
  );
      

INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing","allocate") 
VALUES
  (
    '1',
    '0',
    '0',
    '0',
    '',
    '1',
    '0',
    '/dev/shm/uds2023.sock,0666',
    '0',
    'vless',
    '{
  "clients": [
    {
      "id": "${client_id3}",
      "flow": "",
      "email": "${emoji_flag}-xhttp-xkeen",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "xkeen",
      "reset": 0
    }
  ],
  "decryption": "none",
  "fallbacks": []
}',
    '{
  "network": "xhttp",
  "security": "none",
  "externalProxy": [
    {
      "forceTls": "tls",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "xhttpSettings": {
    "path": "/${xhttp_path}",
    "host": "",
    "headers": {},
    "scMaxBufferedPosts": 30,
    "scMaxEachPostBytes": "1000000",
    "noSSEHeader": false,
    "xPaddingBytes": "100-1000",
    "mode": "packet-up"
  },
  "sockopt": {
    "acceptProxyProtocol": false,
    "tcpFastOpen": true,
    "mark": 0,
    "tproxy": "off",
    "tcpMptcp": true,
    "tcpNoDelay": true,
    "domainStrategy": "UseIP",
    "tcpMaxSeg": 1440,
    "dialerProxy": "",
    "tcpKeepAliveInterval": 0,
    "tcpKeepAliveIdle": 300,
    "tcpUserTimeout": 10000,
    "tcpcongestion": "bbr",
    "V6Only": false,
    "tcpWindowClamp": 600,
    "interface": ""
  }
}',
    'inbound-/dev/shm/uds2023.sock,0666:0|',
    '{
  "enabled": true,
  "destOverride": [
    "http",
    "tls",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}',
    '{
  "strategy": "always",
  "refresh": 5,
  "concurrency": 3
}'
  );
EOF
        /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${panel_port}" -webBasePath "${panel_path}"
        x-ui start
    else
        msg_err "x-ui.db file not exist! Maybe x-ui isn't installed." && exit 1
    fi
}
