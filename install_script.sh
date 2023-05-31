#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# System Required: CentOS 7+/Ubuntu 18+/Debian 10+
# Version: v2.1.3
# Description: One click Install Trojan Panel server
# Author: jonssonyan <https://jonssonyan.com>
# Github: https://github.com/Ptechgithub/install-script

init_var() {
  ECHO_TYPE="echo -e"

  package_manager=""
  release=""
  get_arch=""
  can_google=0

  # Docker
  DOCKER_MIRROR='"https://hub-mirror.c.163.com","https://ccr.ccs.tencentyun.com","https://mirror.baidubce.com","https://dockerproxy.com"'

  # project directory
  TP_DATA="/tpdata/"

  STATIC_HTML="https://github.com/Ptechgithub/install-script/releases/download/v1.0.0/html.tar.gz"

  # web
  WEB_PATH="/tpdata/web/"

  # cert
  CERT_PATH="/tpdata/cert/"
  DOMAIN_FILE="/tpdata/domain.lock"
  domain=""
  crt_path=""
  key_path=""

  # Caddy
  CADDY_DATA="/tpdata/caddy/"
  CADDY_CONFIG="${CADDY_DATA}config.json"
  CADDY_LOG="${CADDY_DATA}logs/"
  CADDY_CERT_DIR="${CERT_PATH}certificates/acme-v02.api.letsencrypt.org-directory/"
  caddy_port=80
  caddy_remote_port=8863
  your_email=""
  ssl_option=1
  ssl_module_type=1
  ssl_module="acme"

  # Nginx
  NGINX_DATA="/tpdata/nginx/"
  NGINX_CONFIG="${NGINX_DATA}default.conf"
  nginx_port=80
  nginx_remote_port=8863
  nginx_https=1

  # MariaDB
  MARIA_DATA="/tpdata/mariadb/"
  mariadb_ip="127.0.0.1"
  mariadb_port=9507
  mariadb_user="root"
  mariadb_pas=""

  #Redis
  REDIS_DATA="/tpdata/redis/"
  redis_host="127.0.0.1"
  redis_port=6378
  redis_pass=""

  # Trojan Panel
  TROJAN_PANEL_DATA="/tpdata/trojan-panel/"
  TROJAN_PANEL_WEBFILE="${TROJAN_PANEL_DATA}webfile/"
  TROJAN_PANEL_LOGS="${TROJAN_PANEL_DATA}logs/"
  TROJAN_PANEL_EXPORT="${TROJAN_PANEL_DATA}config/export/"
  TROJAN_PANEL_TEMPLATE="${TROJAN_PANEL_DATA}config/template/"

  # Trojan Panel UI
  TROJAN_PANEL_UI_DATA="/tpdata/trojan-panel-ui/"
  # Nginx
  UI_NGINX_DATA="${TROJAN_PANEL_UI_DATA}nginx/"
  UI_NGINX_CONFIG="${UI_NGINX_DATA}default.conf"
  trojan_panel_ui_port=2083
  ui_https=1

  # Trojan Panel Core
  TROJAN_PANEL_CORE_DATA="/tpdata/trojan-panel-core/"
  TROJAN_PANEL_CORE_LOGS="${TROJAN_PANEL_CORE_DATA}logs/"
  TROJAN_PANEL_CORE_SQLITE="${TROJAN_PANEL_CORE_DATA}config/sqlite/"
  database="trojan_panel_db"
  account_table="account"
  grpc_port=8100

  # Update
  trojan_panel_current_version=""
  trojan_panel_latest_version="v2.1.3"
  trojan_panel_core_current_version=""
  trojan_panel_core_latest_version="v2.1.0"

  # SQL
  sql_200="alter table \`system\` add template_config varchar(512) default '' not null comment 'template configuration' after email_config;update \`system\` set template_config = \"{\\\"systemName\\\":\\\"Trojan Panel\\\"}\" where name = \"trojan-panel\";insert into \`casbin_rule\` values ('p','sysadmin','/api/nodeServer/nodeServerState','GET','','','');insert into \`casbin_rule\` values ('p','user','/api/node/selectNodeInfo','GET','','','');insert into \`casbin_rule\` values ('p','sysadmin','/api/node/selectNodeInfo','GET','','','');"
  sql_203="alter table node add node_server_grpc_port int(10) unsigned default 8100 not null comment 'gRPC port' after node_server_ip;alter table node_server add grpc_port int(10) unsigned default 8100 not null comment 'gRPC port' after name;alter table node_xray add xray_flow varchar(32) default 'xtls-rprx-vision' not null comment 'Xray flow control' after protocol;alter table node_xray add xray_ss_method varchar(32) default 'aes-256-gcm' not null comment 'Xray Shadowsocks encryption method' after xray_flow;"
  sql_205="DROP TABLE IF EXISTS \`file_task\`;CREATE TABLE \`file_task\` ( \`id\` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'primary key', \`name\` varchar(64) NOT NULL DEFAULT '' COMMENT 'file name', \`path\` varchar(128) NOT NULL DEFAULT '' COMMENT 'file path', \`type\` tinyint(2) unsigned NOT NULL DEFAULT '1' COMMENT 'type 1/user import 2/server import 3/user export 4/server export', \`status\` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'status -1/failed 0/waiting 1/executing 2/successful', \`err_msg\` varchar(128) NOT NULL DEFAULT '' COMMENT 'error message', \`account_id\` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT 'account id', \`account_username\` varchar(64) NOT NULL DEFAULT '' COMMENT 'account login username', \`create_time\` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'creation time', \`update_time\` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'update time', PRIMARY KEY (\`id\`) ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='file task';INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/account/exportAccount', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/account/importAccount', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/system/uploadLogo', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/nodeServer/exportNodeServer', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/nodeServer/importNodeServer', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/fileTask/selectFileTaskPage', 'GET', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/fileTask/deleteFileTaskById', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/fileTask/downloadFileTask', 'POST', '', '', '');INSERT INTO trojan_panel_db.casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/fileTask/downloadTemplate', 'POST', '', '', '');"
  sql_210="UPDATE casbin_rule SET v1 = '/api/fileTask/downloadTemplate' WHERE v1 = '/api/fileTask/downloadCsvTemplate';UPDATE casbin_rule SET v1 = '/api/account/updateAccountPass' WHERE v1 = '/api/account/updateAccountProfile';INSERT INTO casbin_rule (p_type, v0, v1, v2) VALUES ('p', 'sysadmin', '/api/account/updateAccountProperty', 'POST');INSERT INTO casbin_rule (p_type, v0, v1, v2) VALUES ('p', 'user', '/api/account/updateAccountProperty', 'POST');alter table node_xray modify settings varchar(1024) default '' not null comment 'settings';alter table node_xray modify stream_settings varchar(1024) default '' not null comment 'streamSettings';alter table node_xray add reality_pbk varchar(64) default '' not null comment 'reality public key' after xray_ss_method;alter table node_hysteria add obfs varchar(64) default '' not null comment 'obfuscation password' after protocol;"
  sql_211="UPDATE \`system\` SET account_config = '{\"registerEnable\":1,\"registerQuota\":0,\"registerExpireDays\":0,\"resetDownloadAndUploadMonth\":0,\"trafficRankEnable\":1,\"captchaEnable\":0}' WHERE name = 'trojan-panel';INSERT INTO casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/node/nodeDefault', 'GET', '', '', '');INSERT INTO casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'user', '/api/node/nodeDefault', 'GET', '', '', '');"
  sql_212="alter table account add validity_period int unsigned default 0 not null comment 'account validity period' after email;alter table account add last_login_time bigint unsigned default 0 not null comment 'last login time' after validity_period;INSERT INTO casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/account/createAccountBatch', 'POST', '', '', '');INSERT INTO casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/account/exportAccountUnused', 'POST', '', '', '');"
}

echo_content() {
  case $1 in
  "red")
    ${ECHO_TYPE} "\033[31m$2\033[0m"
    ;;
  "green")
    ${ECHO_TYPE} "\033[32m$2\033[0m"
    ;;
  "yellow")
    ${ECHO_TYPE} "\033[33m$2\033[0m"
    ;;
  "blue")
    ${ECHO_TYPE} "\033[34m$2\033[0m"
    ;;
  "purple")
    ${ECHO_TYPE} "\033[35m$2\033[0m"
    ;;
  "skyBlue")
    ${ECHO_TYPE} "\033[36m$2\033[0m"
    ;;
  "white")
    ${ECHO_TYPE} "\033[37m$2\033[0m"
    ;;
  esac
}

mkdir_tools() {
  # Project Directory
  mkdir -p ${TP_DATA}

  # web
  mkdir -p ${WEB_PATH}

  # cert
  mkdir -p ${CERT_PATH}
  touch ${DOMAIN_FILE}

  # Caddy
  mkdir -p ${CADDY_DATA}
  touch ${CADDY_CONFIG}
  mkdir -p ${CADDY_LOG}

  # Nginx
  mkdir -p ${NGINX_DATA}
  touch ${NGINX_CONFIG}

  # MariaDB
  mkdir -p ${MARIA_DATA}

  # Redis
  mkdir -p ${REDIS_DATA}

  # Trojan Panel
  mkdir -p ${TROJAN_PANEL_DATA}
  mkdir -p ${TROJAN_PANEL_LOGS}

  # Trojan Panel UI
  mkdir -p ${TROJAN_PANEL_UI_DATA}
  # # Nginx
  mkdir -p ${UI_NGINX_DATA}
  touch ${UI_NGINX_CONFIG}

  # Trojan Panel Core
  mkdir -p ${TROJAN_PANEL_CORE_DATA}
  mkdir -p ${TROJAN_PANEL_CORE_LOGS}
  mkdir -p ${TROJAN_PANEL_CORE_SQLITE}
}

can_connect() {
  ping -c2 -i0.3 -W1 "$1" &>/dev/null
  if [[ "$?" == "0" ]]; then
    return 0
  else
    return 1
  fi
}

check_sys() {
  if [[ $(command -v yum) ]]; then
    package_manager='yum'
  elif [[ $(command -v dnf) ]]; then
    package_manager='dnf'
  elif [[ $(command -v apt) ]]; then
    package_manager='apt'
  elif [[ $(command -v apt-get) ]]; then
    package_manager='apt-get'
  fi

  if [[ -z "${package_manager}" ]]; then
    echo_content red "This system is currently not supported."
    exit 0
  fi

  if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
    release="centos"
  elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
    release="debian"
  elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
    release="ubuntu"
  fi

  if [[ -z "${release}" ]]; then
    echo_content red "Only CentOS 7+/Ubuntu 18+/Debian 10+ systems are supported."
    exit 0
  fi

  if [[ $(arch) =~ ("x86_64"|"amd64"|"arm64"|"aarch64"|"arm"|"s390x") ]]; then
    get_arch=$(arch)
  fi

  if [[ -z "${get_arch}" ]]; then
    echo_content red "Only amd64/arm64/arm/s390x processor architectures are supported."
    exit 0
  fi

  can_connect www.google.com
  [[ "$?" == "0" ]] && can_google=1
}

depend_install() {
  if [[ "${package_manager}" != 'yum' && "${package_manager}" != 'dnf' ]]; then
    ${package_manager} update -y
  fi
  ${package_manager} install -y \
    curl \
    wget \
    tar \
    lsof \
    systemd
}

# Install Docker
install_docker() {
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content green "---> Install Docker"

    # disable firewall
    if [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]]; then
      systemctl stop firewalld.service && systemctl disable firewalld.service
    fi

    # timezone
    timedatectl set-timezone Asia/Tehran

    if [[ ${can_google} == 0 ]]; then
      sh <(curl -sL https://get.docker.com) --mirror Aliyun
      # Set up Docker domestic source
      mkdir -p /etc/docker &&
        cat >/etc/docker/daemon.json <<EOF
{
  "registry-mirrors":[${DOCKER_MIRROR}],
  "log-driver":"json-file",
  "log-opts":{
      "max-size":"50m",
      "max-file":"3"
  }
}
EOF
    else
      sh <(curl -sL https://get.docker.com)
      mkdir -p /etc/docker &&
        cat >/etc/docker/daemon.json <<EOF
{
  "log-driver":"json-file",
  "log-opts":{
      "max-size":"50m",
      "max-file":"3"
  }
}
EOF
    fi

    systemctl enable docker &&
      systemctl restart docker

    if [[ $(docker -v 2>/dev/null) ]]; then
      echo_content skyBlue "---> Docker installation complete"
    else
      echo_content red "---> Docker installation failed"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed Docker"
  fi
}

# Install Caddy TLS
install_caddy_tls() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> Install Caddy TLS"

    wget --no-check-certificate -O ${WEB_PATH}html.tar.gz -N ${STATIC_HTML} &&
      tar -zxvf ${WEB_PATH}html.tar.gz -k -C ${WEB_PATH}

    read -r -p "Please enter the Caddy port (default: 80): " caddy_port
    [[ -z "${caddy_port}" ]] && caddy_port=80
    read -r -p "Please enter the Caddy remote port (default: 8863): " caddy_remote_port
    [[ -z "${caddy_remote_port}" ]] && caddy_remote_port=8863

    echo_content yellow "Note: please make sure that your domain name has been resolved to this machine, otherwise the installation may fail."
    while read -r -p "Please enter your domain name (required): " domain; do
      if [[ -z "${domain}" ]]; then
        echo_content red "Domain name cannot be empty."
      else
        break
      fi
    done

    read -r -p "Please enter your email (optional): " your_email

    while read -r -p "Please choose how to set up SSL certificates (1/automatic certificate request and renewal, 2/manual certificate path setup, default: 1/automatic ... ): " ssl_option; do
      if [[ -z ${ssl_option} || ${ssl_option} == 1 ]]; then
        while read -r -p "Please choose how to request a certificate (1/acme, 2/zerossl, default: 1/acme): " ssl_module_type; do
          if [[ -z "${ssl_module_type}" || ${ssl_module_type} == 1 ]]; then
            ssl_module="acme"
            CADDY_CERT_DIR="${CERT_PATH}certificates/acme-v02.api.letsencrypt.org-directory/"
            break
          elif [[ ${ssl_module_type} == 2 ]]; then
            ssl_module="zerossl"
            CADDY_CERT_DIR="${CERT_PATH}certificates/acme.zerossl.com-v2-dv90/"
            break
          else
            echo_content red "please only choose: 1 or 2."
          fi
        done

        cat >${CADDY_CONFIG} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CERT_PATH}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${WEB_PATH}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
        break
      elif [[ ${ssl_option} == 2 ]]; then
        install_custom_cert "${domain}"
        cat >${CADDY_CONFIG} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CERT_PATH}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${WEB_PATH}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ],
                "load_files":[
                    {
                        "certificate":"${CADDY_CERT_DIR}${domain}/${domain}.crt",
                        "key":"${CADDY_CERT_DIR}${domain}/${domain}.key"
                    }
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
        break
      else
        echo_content red "please only choose: 1 or 2."
      fi
    done

    if [[ -n $(lsof -i:${caddy_port},443 -t) ]]; then
      kill -9 "$(lsof -i:${caddy_port},443 -t)"
    fi

    docker pull caddy:2.6.2 &&
      docker run -d --name trojan-panel-caddy --restart always \
        --network=host \
        -v "${CADDY_CONFIG}":"${CADDY_CONFIG}" \
        -v ${CERT_PATH}:"${CADDY_CERT_DIR}${domain}/" \
        -v ${WEB_PATH}:${WEB_PATH} \
        -v ${CADDY_LOG}:${CADDY_LOG} \
        caddy:2.6.2 caddy run --config ${CADDY_CONFIG}

    if [[ -n $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
      cat >${DOMAIN_FILE} <<EOF
${domain}
EOF
      echo_content skyBlue "---> Caddy installation complete."
    else
      echo_content red "---> Caddy installation failed or is not running properly. Please try to fix it or uninstall and reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed Caddy."
  fi
}

# Install Nginx
install_nginx() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-nginx$") ]]; then
    echo_content green "---> Installing Nginx."

    wget --no-check-certificate -O ${WEB_PATH}html.tar.gz -N ${STATIC_HTML} &&
      tar -zxvf ${WEB_PATH}html.tar.gz -k -C ${WEB_PATH}

    read -r -p "Please enter the Nginx port (default:80): " nginx_port
    [[ -z "${nginx_port}" ]] && nginx_port=80
    read -r -p "Please enter the Nginx remote port (default:8863): " nginx_remote_port
    [[ -z "${nginx_remote_port}" ]] && nginx_remote_port=8863

    while read -r -p "Please select whether to enable https for Nginx?( 0/Off   1/On   default:1/On): " nginx_https; do
      if [[ -z ${nginx_https} || ${nginx_https} == 1 ]]; then
        install_custom_cert "custom_cert"
        domain=$(cat "${DOMAIN_FILE}")
        cat >${NGINX_CONFIG} <<-EOF
server {
    listen ${nginx_port};
    server_name localhost;

    return 301 http://\$host:${nginx_remote_port}\$request_uri;
}

server {
    listen       ${nginx_remote_port} ssl;
    server_name  localhost;

    # Force SSL
    ssl on;
    ssl_certificate      ${CERT_PATH}${domain}.crt;
    ssl_certificate_key  ${CERT_PATH}${domain}.key;
    # Cache valid period
    ssl_session_timeout  5m;
    # Optional encryption protocols for secure links
    ssl_protocols  TLSv1.3;
    # Encryption algorithm
    ssl_ciphers  ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    # Use server-side preferred algorithm
    ssl_prefer_server_ciphers  on;

    #access_log  /var/log/nginx/host.access.log  main;

    location / {
        root   ${WEB_PATH};
        index  index.html index.htm;
    }

    #error_page  404              /404.html;
    #497 http->https
    error_page  497               https://\$host:${nginx_remote_port}\$request_uri;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
        break
      else
        if [[ ${nginx_https} != 0 ]]; then
          echo_content red "please only choose: 0 or 1"          
        else
          cat >${NGINX_CONFIG} <<-EOF
server {
    listen       ${nginx_port};
    server_name  localhost;

    location / {
        root   ${WEB_PATH};
        index  index.html index.htm;
    }

    error_page  497               http://\$host:${nginx_port}\$request_uri;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
          break
        fi
      fi
    done

    docker pull nginx:1.20-alpine &&
      docker run -d --name trojan-panel-nginx --restart always \
        --network=host \
        -v "${NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CERT_PATH}:${CERT_PATH} \
        -v ${WEB_PATH}:${WEB_PATH} \
        nginx:1.20-alpine

    if [[ -n $(docker ps -q -f "name=^trojan-panel-nginx$" -f "status=running") ]]; then
      echo_content skyBlue "---> Nginx installation complete."
    else
      echo_content red "---> Nginx installation failed or is not running properly. Please try to fix it or uninstall and reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed Nginx."
  fi
}

# Set up reverse proxy
install_reverse_proxy() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-caddy$|^trojan-panel-nginx$") ]]; then
    echo_content green "---> Set up reverse proxy"

    while :; do
      echo_content yellow "1. Install Caddy 2 (recommended)"
      echo_content yellow "2. Install Nginx"
      echo_content yellow "3. Do not set up reverse proxy"
      read -r -p "Please choose an option (default: 1): " whether_install_reverse_proxy
      [[ -z "${whether_install_reverse_proxy}" ]] && whether_install_reverse_proxy=1

      case ${whether_install_reverse_proxy} in
      1)
        install_caddy_tls
        break
        ;;
      2)
        install_nginx
        break
        ;;
      3)
        break
        ;;
      *)
        echo_content red "This option does not exist."
        continue
        ;;
      esac
    done

    echo_content skyBlue "---> Web camouflage settings completed."    
  fi
}

install_custom_cert() {
  while read -r -p "Please enter the path to the .crt file for the certificate (required): " crt_path; do
    if [[ -z "${crt_path}" ]]; then
      echo_content red "Path cannot be empty."
    else
      if [[ ! -f "${crt_path}" ]]; then
        echo_content red "The specified .crt file path does not exist."
      else
        cp "${crt_path}" "${CERT_PATH}$1.crt"
        break
      fi
    fi
  done
  while read -r -p "Please enter the path to the .key file for the certificate (required): " key_path; do
    if [[ -z "${key_path}" ]]; then
      echo_content red "Path cannot be empty."
    else
      if [[ ! -f "${key_path}" ]]; then
        echo_content red "The specified .key file path does not exist."
      else
        cp "${key_path}" "${CERT_PATH}$1.key"
        break
      fi
    fi
  done
  cat >${DOMAIN_FILE} <<EOF
$1
EOF
}

# 设置证书
install_cert() {
  domain=$(cat "${DOMAIN_FILE}")
  if [[ -z "${domain}" ]]; then
    echo_content green "---> Set up certificate."

    while :; do
      echo_content yellow "1. Install Caddy 2 (automatically request/renew certificates)."
      echo_content yellow "2. Manually set certificate paths."
      read -r -p "Please select an option (default: 1): " whether_install_cert
      [[ -z "${whether_install_cert}" ]] && whether_install_cert=1

      case ${whether_install_cert} in
      1)
        install_caddy_tls
        break
        ;;
      2)
        install_custom_cert "custom_cert"
        break
        ;;
      *)
        echo_content red "This option does not exist."
        continue
        ;;
      esac
    done

    echo_content green "---> Certificate setup completed."
  fi
}

# Install MariaDB
install_mariadb() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> Install MariaDB"

    read -r -p "Please enter the database port (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done

    if [[ "${mariadb_user}" == "root" ]]; then
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Tehran \
          mariadb:10.7.3 \
          --port ${mariadb_port} \
          --character-set-server=utf8mb4 \
          --collation-server=utf8mb4_unicode_ci
    else
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e MYSQL_USER="${mariadb_user}" \
          -e MYSQL_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Tehran \
          mariadb:10.7.3 \
          --port ${mariadb_port} \
          --character-set-server=utf8mb4 \
          --collation-server=utf8mb4_unicode_ci
    fi

    if [[ -n $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content skyBlue "---> MariaDB installation completed."
      echo_content yellow "---> Database password for MariaDB root (please keep it safe): ${mariadb_pas}"
      if [[ "${mariadb_user}" != "root" ]]; then
        echo_content yellow "---> Database password for MariaDB user ${mariadb_user} (please keep it safe): ${mariadb_pas}"
      fi
    else
      echo_content red "---> MariaDB installation failed or encountered errors. Please try to fix or reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed MariaDB."
  fi
}

# Install Redis
install_redis() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> Install Redis"

    read -r -p "Please enter the Redis port number (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the Redis password (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done

    docker pull redis:6.2.7 &&
      docker run -d --name trojan-panel-redis --restart always \
        --network=host \
        redis:6.2.7 \
        redis-server --requirepass "${redis_pass}" --port ${redis_port}

    if [[ -n $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content skyBlue "---> Redis installation completed."
      echo_content yellow "---> Database password for Redis (please keep it safe): ${redis_pass}"
    else
      echo_content red "---> Redis installation failed or encountered errors. Please try to fix or reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed Redis."
  fi
}

# Install Trojan Panel
install_trojan_panel() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> Install Trojan Panel"

    read -r -p "Please enter the database IP address (default: local database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the database port number (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done

    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -e "create database if not exists trojan_panel_db;" &>/dev/null

    read -r -p "Please enter the Redis IP address (default: local Redis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the Redis port number (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the Redis password (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker pull jonssonyan/trojan-panel &&
      docker run -d --name trojan-panel --restart always \
        --network=host \
        -v ${WEB_PATH}:${TROJAN_PANEL_WEBFILE} \
        -v ${TROJAN_PANEL_LOGS}:${TROJAN_PANEL_LOGS} \
        -v ${TROJAN_PANEL_EXPORT}:${TROJAN_PANEL_EXPORT} \
        -v ${TROJAN_PANEL_TEMPLATE}:${TROJAN_PANEL_TEMPLATE} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        jonssonyan/trojan-panel

   if [[ -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel backend installation completed."
    else
      echo_content red "---> Trojan Panel backend installation failed or encountered errors. Please try to fix or reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed the Trojan Panel backend."
  fi

  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-ui$") ]]; then
    read -r -p "Please enter the port number for Trojan Panel frontend (default: 2083): " trojan_panel_ui_port
    [[ -z "${trojan_panel_ui_port}" ]] && trojan_panel_ui_port="2083"

    while read -r -p "Would you like to enable HTTPS for Trojan Panel frontend? ( 0/disable,   1/enable,    default: 1/enable): " ui_https; do
      if [[ -z ${ui_https} || ${ui_https} == 1 ]]; then
        domain=$(cat "${DOMAIN_FILE}")
        # Configure Nginx
        cat >${UI_NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port} ssl;
    server_name  localhost;

    # Force SSL
    ssl on;
    ssl_certificate      ${CERT_PATH}${domain}.crt;
    ssl_certificate_key  ${CERT_PATH}${domain}.key;
    # Cache expiration time
    ssl_session_timeout  5m;
    # Optional encryption protocols for secure links
    ssl_protocols  TLSv1.3;
    # Encryption algorithms
    ssl_ciphers  ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    # Use the server's preferred algorithm
    ssl_prefer_server_ciphers  on;

    #access_log  /var/log/nginx/host.access.log  main;

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_pass http://127.0.0.1:8081;
    }

    #error_page  404              /404.html;
    #497 http->https
    error_page  497               https://\$host:${trojan_panel_ui_port}\$request_uri;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
        break
      else
        if [[ ${ui_https} != 0 ]]; then
          echo_content red "please only choose: 0 or 1"
        else
          cat >${UI_NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port};
    server_name  localhost;

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_pass http://127.0.0.1:8081;
    }

    error_page  497               http://\$host:${trojan_panel_ui_port}\$request_uri;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
          break
        fi
      fi
    done

    docker pull jonssonyan/trojan-panel-ui &&
      docker run -d --name trojan-panel-ui --restart always \
        --network=host \
        -v "${UI_NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CERT_PATH}:${CERT_PATH} \
        jonssonyan/trojan-panel-ui

    if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel front-end installation completed"
    else
      echo_content red "---> Trojan Panel frontend installation failed or encountered an error. Please try to fix or reinstall it."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed the Trojan Panel front-end."
  fi

  https_flag=$([[ -z ${ui_https} || ${ui_https} == 1 ]] && echo "https" || echo "http")
  domain_or_ip=$([[ -z ${domain} || "${domain}" == "custom_cert" ]] && echo "ip" || echo "${domain}")

  echo_content red "\n=============================================================="
  echo_content skyBlue "Trojan Panel installation successful"
  echo_content yellow "Password for MariaDB ${mariadb_user} (please keep it safe): ${mariadb_pas}"
  echo_content yellow "Password for Redis (please keep it safe): ${redis_pass}"
  echo_content yellow "Administration panel address: ${https_flag}://${domain_or_ip}:${trojan_panel_ui_port}"
  echo_content white "Default system administrator username: ■ sysadmin ■  default password: ■ 123456 ■ Please log in to the administration panel promptly and change the password."
  echo_content yellow "Trojan Panel private key and certificate directory: ${CERT_PATH}"
  echo_content red "\n=============================================================="
}

# installation Trojan Panel Core
install_trojan_panel_core() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> Install Trojan Panel Core"

    read -r -p "Please enter the IP address of the database (default: local database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of the database (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the username of the database (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the password of the database (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done
    read -r -p "Please enter the database name (default: trojan_panel_db): " database
    [[ -z "${database}" ]] && database="trojan_panel_db"
    read -r -p "Please enter the user table name of the database (default: account): " account_table
    [[ -z "${account_table}" ]] && account_table="account"

    read -r -p "Please enter the IP address of Redis (default: local Redis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the port of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the password of Redis (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done
    read -r -p "Please enter the API port (default: 8100): " grpc_port
    [[ -z "${grpc_port}" ]] && grpc_port=8100

    domain=$(cat "${DOMAIN_FILE}")

    docker pull jonssonyan/trojan-panel-core &&
      docker run -d --name trojan-panel-core --restart always \
        --network=host \
        -v ${TROJAN_PANEL_CORE_DATA}bin/xray/config:${TROJAN_PANEL_CORE_DATA}bin/xray/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/trojango/config:${TROJAN_PANEL_CORE_DATA}bin/trojango/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria/config:${TROJAN_PANEL_CORE_DATA}bin/hysteria/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config:${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config \
        -v ${TROJAN_PANEL_CORE_LOGS}:${TROJAN_PANEL_CORE_LOGS} \
        -v ${TROJAN_PANEL_CORE_SQLITE}:${TROJAN_PANEL_CORE_SQLITE} \
        -v ${CERT_PATH}:${CERT_PATH} \
        -v ${WEB_PATH}:${WEB_PATH} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "database=${database}" \
        -e "account-table=${account_table}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "crt_path=${CERT_PATH}${domain}.crt" \
        -e "key_path=${CERT_PATH}${domain}.key" \
        -e "grpc_port=${grpc_port}" \
        jonssonyan/trojan-panel-core
    if [[ -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel Core installation complete"
    else
      echo_content red "---> Trojan Panel Core backend installation failed or is running abnormally, please try to fix it or uninstall and reinstall."
      exit 0
    fi
  else
    echo_content skyBlue "---> You have already installed Trojan Panel Core"
  fi
}

# Update the Trojan Panel database structure
update__trojan_panel_database() {
  echo_content skyBlue "---> Updating the Trojan Panel database structure"

  if [[ "${trojan_panel_current_version}" == "v1.3.1" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_200}" &>/dev/null &&
      trojan_panel_current_version="v2.0.0"
  fi
  version_200_203=("v2.0.0" "v2.0.1" "v2.0.2")
  if [[ "${version_200_203[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_203}" &>/dev/null &&
      trojan_panel_current_version="v2.0.3"
  fi
  version_203_205=("v2.0.3" "v2.0.4")
  if [[ "${version_203_205[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_205}" &>/dev/null &&
      trojan_panel_current_version="v2.0.5"
  fi
  version_205_210=("v2.0.5")
  if [[ "${version_205_210[*]}" =~ "${trojan_panel_current_version}" ]]; then
    domain=$(cat "${DOMAIN_FILE}")
    if [[ -z "${domain}" ]]; then
      docker rm -f trojan-panel-caddy
      rm -rf /tpdata/caddy/srv/
      rm -rf /tpdata/caddy/cert/
      rm -f /tpdata/caddy/domain.lock
      install_reverse_proxy
      cp /tpdata/nginx/default.conf ${UI_NGINX_CONFIG} &&
        sed -i "s#/tpdata/caddy/cert/#${CERT_PATH}#g" ${UI_NGINX_CONFIG}
    fi
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_210}" &>/dev/null &&
      trojan_panel_current_version="v2.1.0"
  fi
  version_210_211=("v2.1.0")
  if [[ "${version_210_211[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_211}" &>/dev/null &&
      trojan_panel_current_version="v2.1.1"
  fi
  version_211_212=("v2.1.1")
  if [[ "${version_211_212[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_212}" &>/dev/null &&
      trojan_panel_current_version="v2.1.2"
  fi

  echo_content skyBlue "---> Trojan Panel database structure update complete"
}

# Update the Trojan Panel Core database structure
update__trojan_panel_core_database() {
  echo_content skyBlue "---> Updating the Trojan Panel Core database structure"

  version_204_210=("v2.0.4")
  if [[ "${version_204_210[*]}" =~ "${trojan_panel_core_current_version}" ]]; then
    domain=$(cat "${DOMAIN_FILE}")
    if [[ -z "${domain}" ]]; then
      docker rm -f trojan-panel-caddy
      rm -rf /tpdata/caddy/srv/
      rm -rf /tpdata/caddy/cert/
      rm -f /tpdata/caddy/domain.lock
      install_reverse_proxy
      cp /tpdata/nginx/default.conf ${UI_NGINX_CONFIG} &&
        sed -i "s#/tpdata/caddy/cert/#${CERT_PATH}#g" ${UI_NGINX_CONFIG}
    fi
    trojan_panel_core_current_version="v2.1.0"
  fi

  echo_content skyBlue "---> Trojan Panel Core database structure update complete"
}

# Update Trojan Panel
update_trojan_panel() {
  # Check if Trojan Panel is installed
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content red "---> Please install Trojan Panel first"
    exit 0
  fi

  trojan_panel_current_version=$(docker exec trojan-panel ./trojan-panel -version)
  if [[ -z "${trojan_panel_current_version}" || ! "${trojan_panel_current_version}" =~ ^v.* ]]; then
    echo_content red "---> Current version does not support automatic updates"
    exit 0
  fi

  echo_content yellow "Note: The current version of Trojan Panel backend (trojan-panel) is ${trojan_panel_current_version}. The latest version is ${trojan_panel_latest_version}."

  if [[ "${trojan_panel_current_version}" != "${trojan_panel_latest_version}" ]]; then
    echo_content green "---> Updating Trojan Panel"    

    read -r -p "Please enter the database IP address (default: local database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the database port (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done

    read -r -p "Please enter the IP address of Redis (default: localhost): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the port number of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the password for Redis (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
       echo "Password cannot be empty."
      else
        break
      fi
    done
    
    update__trojan_panel_database

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker rm -f trojan-panel &&
      docker rmi -f jonssonyan/trojan-panel

    docker pull jonssonyan/trojan-panel &&
      docker run -d --name trojan-panel --restart always \
        --network=host \
        -v ${WEB_PATH}:${TROJAN_PANEL_WEBFILE} \
        -v ${TROJAN_PANEL_LOGS}:${TROJAN_PANEL_LOGS} \
        -v ${TROJAN_PANEL_EXPORT}:${TROJAN_PANEL_EXPORT} \
        -v ${TROJAN_PANEL_TEMPLATE}:${TROJAN_PANEL_TEMPLATE} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        jonssonyan/trojan-panel

    if [[ -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel backend update completed"
    else
      echo_content red "---> Trojan Panel backend update failed or is running abnormally. Please try to fix it or uninstall and reinstall."
    fi

    docker rm -f trojan-panel-ui &&
      docker rmi -f jonssonyan/trojan-panel-ui

    docker pull jonssonyan/trojan-panel-ui &&
      docker run -d --name trojan-panel-ui --restart always \
        --network=host \
        -v "${UI_NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CERT_PATH}:${CERT_PATH} \
        jonssonyan/trojan-panel-ui

    if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel frontend update completed"
   else
      echo_content red "---> Trojan Panel frontend update failed or is running abnormally. Please try to fix it or uninstall and reinstall."
    fi
 else
    echo_content skyBlue "---> The Trojan Panel installed on your system is already up-to-date."
  fi
}

# Update the Trojan Panel Core
update_trojan_panel_core() {
  # Check if Trojan Panel Core is installed
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content red "---> Please install Trojan Panel Core first."
    exit 0
  fi

  trojan_panel_core_current_version=$(docker exec trojan-panel-core ./trojan-panel-core -version)
  if [[ -z "${trojan_panel_core_current_version}" || ! "${trojan_panel_core_current_version}" =~ ^v.* ]]; then
    echo_content red "---> The current version does not support automated updates."
    exit 0
  fi

  echo_content yellow "Note: The current version of Trojan Panel Core (trojan-panel-core) is ${trojan_panel_core_current_version}, and the latest version is ${trojan_panel_core_latest_version}."

  if [[ "${trojan_panel_core_current_version}" != "${trojan_panel_core_latest_version}" ]]; then
    echo_content green "---> Update Trojan Panel Core"
    
    read -r -p "Please enter the IP address of the database (default: localhost): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port number of the database (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the username for the database (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the password for the database (required): " mariadb_pass; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done
    read -r -p "Please enter the name of the database (default: trojan_panel_db): " database
    [[ -z "${database}" ]] && database="trojan_panel_db"
    read -r -p "Please enter the name of the user table in the database (default: account): " account_table
    [[ -z "${account_table}" ]] && account_table="account"

    read -r -p "Please enter the IP address of Redis (default: localhost): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the port number of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the password for Redis (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password cannot be empty."
      else
        break
      fi
    done
    read -r -p "Please enter the API port number (default: 8100): " grpc_port
    [[ -z "${grpc_port}" ]] && grpc_port=8100

    update__trojan_panel_core_database

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker rm -f trojan-panel-core &&
      docker rmi -f jonssonyan/trojan-panel-core

    domain=$(cat "${DOMAIN_FILE}")

    docker pull jonssonyan/trojan-panel-core &&
      docker run -d --name trojan-panel-core --restart always \
        --network=host \
        -v ${TROJAN_PANEL_CORE_DATA}bin/xray/config:${TROJAN_PANEL_CORE_DATA}bin/xray/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/trojango/config:${TROJAN_PANEL_CORE_DATA}bin/trojango/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria/config:${TROJAN_PANEL_CORE_DATA}bin/hysteria/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config:${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config \
        -v ${TROJAN_PANEL_CORE_LOGS}:${TROJAN_PANEL_CORE_LOGS} \
        -v ${TROJAN_PANEL_CORE_SQLITE}:${TROJAN_PANEL_CORE_SQLITE} \
        -v ${CERT_PATH}:${CERT_PATH} \
        -v ${WEB_PATH}:${WEB_PATH} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "database=${database}" \
        -e "account-table=${account_table}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "crt_path=${CERT_PATH}${domain}.crt" \
        -e "key_path=${CERT_PATH}${domain}.key" \
        -e "grpc_port=${grpc_port}" \
        jonssonyan/trojan-panel-core

    if [[ -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel Core update completed."
    else
      echo_content red "---> Trojan Panel Core update failed or is running abnormally. Please try to troubleshoot and fix the issue, or uninstall and reinstall."
    fi
  else
    echo_content skyBlue "---> The Trojan Panel Core installed on your system is already up-to-date."
  fi
}

# Uninstall Caddy TLS
uninstall_caddy_tls() {
  # Check if Caddy TLS is installed
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> Uninstalling Caddy TLS."

    docker rm -f trojan-panel-caddy &&
      rm -rf ${CADDY_DATA}

    echo_content skyBlue "---> Caddy TLS uninstallation completed."
  else
    echo_content red "---> Please install Caddy TLS first."
  fi
}

# Uninstall Nginx
uninstall_nginx() {
  # Check if Caddy TLS is
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-nginx") ]]; then
    echo_content green "---> Uninstalling Nginx."

    docker rm -f trojan-panel-nginx &&
      rm -rf ${NGINX_DATA}

    echo_content skyBlue "---> Nginx uninstallation completed."
  else
    echo_content red "---> Please install Nginx first."
  fi
}

# Uninstall MariaDB
uninstall_mariadb() {
  # Check if MariaDB is installed
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> Uninstalling MariaDB."

    docker rm -f trojan-panel-mariadb &&
      rm -rf ${MARIA_DATA}

    echo_content skyBlue "---> MariaDB uninstallation completed."
  else
    echo_content red "---> Please install MariaDB first."
  fi
}

# Uninstall Redis
uninstall_redis() {
  # Check if Redis is installed
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> Uninstalling Redis."

    docker rm -f trojan-panel-redis &&
      rm -rf ${REDIS_DATA}

    echo_content skyBlue "---> Redis uninstallation completed."
  else
    echo_content red "---> Please install Redis first."
  fi
}

# Uninstall Trojan Panel
uninstall_trojan_panel() {
  # Check if Trojan Panel is installed
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> Uninstalling Trojan Panel."

    docker rm -f trojan-panel &&
      docker rmi -f jonssonyan/trojan-panel &&
      rm -rf ${TROJAN_PANEL_DATA}

    docker rm -f trojan-panel-ui &&
      docker rmi -f jonssonyan/trojan-panel-ui &&
      rm -rf ${TROJAN_PANEL_UI_DATA}

    echo_content skyBlue "---> Trojan Panel uninstallation completed."
  else
    echo_content red "---> Please install Trojan Panel first."
  fi
}

# Uninstall Trojan Panel Core
uninstall_trojan_panel_core() {
  # Check if Trojan Panel Core is installed
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> Uninstalling Trojan Panel Core."

    docker rm -f trojan-panel-core &&
      docker rmi -f jonssonyan/trojan-panel-core &&
      rm -rf ${TROJAN_PANEL_CORE_DATA}

    echo_content skyBlue "---> Trojan Panel Core uninstallation completed."
  else
    echo_content red "---> Please install Trojan Panel Core first."
  fi
}

# Uninstall all Trojan Panel-related containers
uninstall_all() {
  echo_content green "---> Uninstalling all Trojan Panel-related containers."

  docker rm -f $(docker ps -a -q -f "name=^trojan-panel")
  docker rmi -f $(docker images | grep "^jonssonyan/trojan-panel" | awk '{print $3}')
  rm -rf ${TP_DATA}

  echo_content skyBlue "---> Uninstallation of all Trojan Panel-related containers completed."
}

# Update Trojan Panel frontend port
update_trojan_panel_ui_port() {
  if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
    echo_content green "---> Updating Trojan Panel frontend port"

    trojan_panel_ui_port=$(grep 'listen.*ssl' ${UI_NGINX_CONFIG} | awk '{print $2}')    
    echo_content yellow "Note: Current port for Trojan Panel frontend (trojan-panel-ui) is --> ${trojan_panel_ui_port}"

    read -r -p "Please enter the new port for Trojan Panel frontend (default: 2083): " trojan_panel_ui_port
    [[ -z "${trojan_panel_ui_port}" ]] && trojan_panel_ui_port="2083"
    sed -i "s/listen.*ssl;/listen       ${trojan_panel_ui_port} ssl;/g" ${UI_NGINX_CONFIG} &&
      sed -i "s/https:\/\/\$host:.*\$request_uri/https:\/\/\$host:${trojan_panel_ui_port}\$request_uri/g" ${UI_NGINX_CONFIG} &&
      docker restart trojan-panel-ui

    if [[ "$?" == "0" ]]; then
      echo_content skyBlue "---> Trojan Panel frontend port has been updated."
    else
      echo_content red "---> Failed to update Trojan Panel frontend port."
    fi
  else
    echo_content red "---> Trojan Panel frontend is not installed or not running properly. Please fix or reinstall and try again."
  fi
}

# Refresh Redis cache
redis_flush_all() {
  # Determine whether Redis is installed
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content red "-Please install Redis firstirst"
    exit 0
  fi

  if [[ -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
    echo_content red "---> Redis is running abnormally'"
    exit 0
  fi

  echo_content green "---> Refreshing Redis cache"

  read -r -p "Please enter the IP address of Redis (default: local Redis): " redis_host
  [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
  read -r -p "Please enter the port number of Redis (default: 6378): " redis_port
  [[ -z "${redis_port}" ]] && redis_port=6378
  while read -r -p "Please enter the password for Redis (required): " redis_pass; do
    if [[ -z "${redis_pass}" ]]; then
      echo_content red "Password cannot be empty"
    else
      break
    fi
  done

  docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

  echo_content skyBlue "---> Redis cache refresh complete"
}

# Failure testing
failure_testing() {
  echo_content green "---> Beginning failure testing."
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content red "---> Docker is not running properly."
  else
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
      if [[ -z $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
        echo_content red "---> Caddy TLS is not running properly. Error log is shown below:"
        docker logs trojan-panel-caddy
      fi
      domain=$(cat "${DOMAIN_FILE}")
      if [[ -z ${domain} || ! -d "${CERT_PATH}" || ! -f "${CERT_PATH}${domain}.crt" ]]; then
        echo_content red "---> There was an error with certificate request. Please try 1. setting up a new subdomain 2. restarting the server to renew certificates 3. selecting custom certificate option during setup. Log is shown below:"
        if [[ -f ${CADDY_LOG}error.log ]]; then
          tail -n 20 ${CADDY_LOG}error.log | grep error
        else
          docker logs trojan-panel-caddy
        fi
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") && -z $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content red "---> MariaDB is not running properly. The log is shown below:"
      docker logs trojan-panel-mariadb
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") && -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content red "---> Redis is not running properly. The log is shown below:"
      docker logs trojan-panel-redis
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -z $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content red "---> Trojan Panel backend is not running properly. The log is shown below:"
      if [[ -f ${TROJAN_PANEL_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_LOGS}trojan-panel.log | grep error
      else
        docker logs trojan-panel
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") && -z $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content red "---> Trojan Panel frontend is not running properly. The log is shown below:"
      docker logs trojan-panel-ui
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -z $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content red "---> Trojan Panel Core is not running properly. The log is shown below:"
      if [[ -f ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log | grep error
      else
        docker logs trojan-panel-core
      fi
    fi
  fi
  echo_content green "---> End of troubleshooting."
}

log_query() {
  while :; do
    echo_content skyBlue "The following applications can be queried for logs:"
    echo_content yellow "1. Trojan Panel"
    echo_content yellow "2. Trojan Panel Core"
    echo_content yellow "3. Quit"
    read -r -p "Please select an application (default:1): " select_log_query_type
    [[ -z "${select_log_query_type}" ]] && select_log_query_type=1

    case ${select_log_query_type} in
    1)
      log_file_path=${TROJAN_PANEL_LOGS}trojan-panel.log
      ;;
    2)
      log_file_path=${TROJAN_PANEL_CORE_LOGS}trojan-panel-core.log
      ;;
    3)
      break
      ;;
    *)
      echo_content red "This option does not exist."
      continue
      ;;
    esac

    read -r -p "Please enter the number of lines to query (default:20): " select_log_query_line_type
    [[ -z "${select_log_query_line_type}" ]] && select_log_query_line_type=20

    if [[ -f ${log_file_path} ]]; then
      echo_content skyBlue "The logs are as follows:"
      tail -n ${select_log_query_line_type} ${log_file_path}
    else
      echo_content red "Log file does not exist."
    fi
  done
}

version_query() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
    trojan_panel_current_version=$(docker exec trojan-panel ./trojan-panel -version)
    echo_content yellow "The current version of Trojan Panel backend (trojan-panel) is ${trojan_panel_current_version} and the latest version is ${trojan_panel_latest_version}."
  fi
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
    trojan_panel_core_current_version=$(docker exec trojan-panel-core ./trojan-panel-core -version)
    echo_content yellow "The current version of Trojan Panel core (trojan-panel-core) is ${trojan_panel_core_current_version} and the latest version is ${trojan_panel_core_latest_version}."
  fi
}

main() {
  cd "$HOME" || exit 0
  init_var
  mkdir_tools
  check_sys
  depend_install
  clear
  echo_content yellow "\n *                 WELCOME  TO   TROJAN                        *"
  echo_content skyBlue "System Required: CentOS 7+/Ubuntu 18+/Debian 10+"
  echo_content skyBlue "Version: v2.1.3"
  echo_content skyBlue "Description: One click Install Trojan Panel server"
  echo_content skyBlue "Author: jonssonyan <https://jonssonyan.com>"
  echo_content skyBlue "Github: https://github.com/Ptechgithub"
  echo_content skyBlue "Docs: https://trojanpanel.github.io"
  echo_content white "\n=============================================================="
  echo_content green "1. Install Trojan Panel"
  echo_content green "2. Install Trojan Panel Core"
  echo_content yellow "3. Install Caddy TLS"
  echo_content yellow "4. Install Nginx"
  echo_content yellow "5. Install MariaDB"
  echo_content yellow "6. Install Redis"
  echo_content white "\n=============================================================="
  echo_content yellow "7. Update Trojan Panel"
  echo_content yellow "8. Update Trojan Panel Core"
  echo_content white "\n=============================================================="
  echo_content yellow "9. Uninstall Trojan Panel"
  echo_content yellow "10. Uninstall Trojan Panel Core"
  echo_content yellow "11. Uninstall Caddy TLS"
  echo_content yellow "12. Uninstall Nginx"
  echo_content yellow "13. Uninstall MariaDB"
  echo_content yellow "14. Uninstall Redis"
  echo_content yellow "15. Uninstall all Trojan Panel-related applications"
  echo_content white "\n=============================================================="
  echo_content yellow "16. Modify Trojan Panel front-end port"
  echo_content yellow "17. Refresh Redis cache"
  echo_content purple "\n==============https://t.me/P_tech2024============================="
  echo_content yellow "18. Fault detection"
  echo_content yellow "19. Log query"
  echo_content yellow "20. Version query"
  read -r -p "Please select: " selectInstall_type
  case ${selectInstall_type} in
  1)
    install_docker
    install_reverse_proxy
    install_cert
    install_mariadb
    install_redis
    install_trojan_panel
    ;;
  2)
    install_docker
    install_reverse_proxy
    install_cert
    install_trojan_panel_core
    ;;
  3)
    install_docker
    install_caddy_tls
    ;;
  4)
    install_docker
    install_nginx
    ;;
  5)
    install_docker
    install_mariadb
    ;;
  6)
    install_docker
    install_redis
    ;;
  7)
    update_trojan_panel
    ;;
  8)
    update_trojan_panel_core
    ;;
  9)
    uninstall_trojan_panel
    ;;
  10)
    uninstall_trojan_panel_core
    ;;
  11)
    uninstall_caddy_tls
    ;;
  12)
    uninstall_nginx
    ;;
  13)
    uninstall_mariadb
    ;;
  14)
    uninstall_redis
    ;;
  15)
    uninstall_all
    ;;
  16)
    update_trojan_panel_ui_port
    ;;
  17)
    redis_flush_all
    ;;
  18)
    failure_testing
    ;;
  19)
    log_query
    ;;
  20)
    version_query
    ;;
  *)
    echo_content red "No Such Option"
    ;;
  esac
}

main
