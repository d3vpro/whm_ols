<?php
echo "\n CHECKING LSHTTPD SERVICE \n";
$service = shell_exec("systemctl status lshttpd -l");
if (strpos($service, 'active (running)') !== false) {
    echo "\n SERVICE IS OKAY! \n";
} else {
    echo "\n Attempting to Fix LSHTTPD Service \n";
    shell_exec("systemctl stop lshttpd");
    shell_exec("systemctl start lshttpd");
}

echo "\n GENERATING LSWS CONFIG \n";
if (file_exists("/usr/local/lsws/.changesDetect") && file_get_contents("/usr/local/lsws/.changesDetect") == changesDetector()) {
    echo "\n No changes detected! \n";
    exit();
}
file_put_contents("/usr/local/lsws/.changesDetect", changesDetector());

shell_exec("rm -rf /usr/local/lsws/conf/vhosts && mkdir /usr/local/lsws/conf/vhosts");
shell_exec("rm -rf /usr/local/lsws/conf/sslcerts && mkdir /usr/local/lsws/conf/sslcerts");
$domains = callWhmApi("--output=json get_domain_info");
$domains = $domains["data"]["domains"];
// Add hostname
$domains[] = [
    'ipv4' => callWhmApi('--output=json get_shared_ip')['data']['ip'],
    'php_version' => callWhmApi('--output=jsonpretty php_get_system_default_version')['data']['version'],
    'user' => "root",
    'port' => "80",
    'port_ssl' => "443",
    'domain' => callWhmApi('--output=json gethostname')['data']['hostname'],
    'docroot' => "/var/www/html",
    'ipv4_ssl' => callWhmApi('--output=json get_shared_ip')['data']['ip'],
    'is_hostname' => true,
];
// Fix strange bug
if (empty($domains[count($domains) - 1]['domain'])) {
    array_pop($domains);
}
$premade_pre = file_get_contents("/usr/local/lsws/conf/httpd_config.conf");
$premade_pre = explode("## DO NOT MODIFY BELOW", $premade_pre);
$premade_pre[0] = rtrim($premade_pre[0]);
$premade = '';
$listeners = [];
$listeners_ssl = [];
$sslInfo = callWhmApi("--output=json fetch_vhost_ssl_components");
foreach ($domains as $domain) {
    // Hostname ssl is not present in fetch_vhost_ssl_components api so use a hardcoded one
    if (!empty($domain['is_hostname'])) {
        file_put_contents("/usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".crt", file_get_contents("/var/cpanel/ssl/dovecot/mydovecot.crt"));
        file_put_contents("/usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".key", file_get_contents("/var/cpanel/ssl/dovecot/mydovecot.key"));
    } else {
        foreach ($sslInfo["data"]["components"] as $v) {
		if ($v["servername"] == $domain["domain"]) {
                $fullchain = rtrim($v["certificate"]) . "\n" . rtrim($v["cabundle"]) . "\n";
                file_put_contents("/usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".crt", $fullchain);
                file_put_contents("/usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".key", $v["key"]);
            }
        }
    }
    $w = file_get_contents("/usr/local/lsws/configparse/vhost.conf");
    $w = str_replace("[RANDOMSTRING]",$domain["user"] . '-' . bin2hex(random_bytes(2)), $w);
    $w = str_replace("[DOCROOT]",$domain["docroot"], $w);
    $w = str_replace("[USER]",$domain["user"], $w);
    $w = str_replace("[GROUP]",$domain["user"], $w);
    $w = str_replace("[PHPVERSION]", convertPHP($domain["php_version"]), $w);
    $map = "keyFile /usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".key\ncertFile /usr/local/lsws/conf/sslcerts/" . $domain["domain"] . ".crt";
    $w = str_replace("[SSL]", $map, $w);
    file_put_contents("/usr/local/lsws/conf/vhosts/" . $domain["domain"] . ".conf", $w);

    $x = file_get_contents("/usr/local/lsws/configparse/vhost_pre.conf");
    $vhostid = $domain['domain'];
    $x = str_replace("[RANDOMSTRING]", $vhostid, $x);
    $x = str_replace("[DOCROOT]", $domain["docroot"], $x);
    $x = str_replace("[DOMAIN]", $domain["domain"], $x);
    $premade .= "\n" . $x;
    // For tld domains other than hostname, add mail. as well in order for autossl to work
    if (empty($domain['is_hostname']) && substr_count($domain["domain"], '.') == 1) {
        $domain["domain"] .= ', mail.' . $domain["domain"];
    }
    if (isset($listeners[$domain["ipv4"] . ":" . $domain["port"]])) {
        $listeners[$domain["ipv4"] . ":" . $domain["port"]][$vhostid] = $domain["domain"];
    } else {
        $listeners[$domain["ipv4"] . ":" . $domain["port"]] = [];
        $listeners[$domain["ipv4"] . ":" . $domain["port"]][$vhostid] = $domain["domain"];
    }
    if (isset($listeners_ssl[$domain["ipv4_ssl"] . ":" . $domain["port_ssl"]])) {
        $listeners_ssl[$domain["ipv4_ssl"] . ":" . $domain["port_ssl"]][$vhostid] = $domain["domain"];
    } else {
        $listeners_ssl[$domain["ipv4_ssl"] . ":" . $domain["port_ssl"]] = [];
        $listeners_ssl[$domain["ipv4_ssl"] . ":" . $domain["port_ssl"]][$vhostid] = $domain["domain"];
    }
}
foreach ($listeners as $c => $l) {
    $px = file_get_contents("/usr/local/lsws/configparse/vhost_listeners.conf");
    $px = str_replace("[IPADD]", $c, $px);
    $px = str_replace("[SECURE]", "0", $px);
    $px = str_replace("[RANDOMSTRING]", $c, $px);
    $map = "";
    foreach ($l as $n => $t) {
        $map = $map . "\n    " . "map " . $n . " " . $t;
    }
    $px = str_replace("[MAPS]", $map, $px);
    $premade .= "\n" . $px;
}
foreach ($listeners_ssl as $c => $l) {
    $px = file_get_contents("/usr/local/lsws/configparse/vhost_listeners.conf");
    $px = str_replace("[IPADD]", $c, $px);
    $px = str_replace("[SECURE]", "1", $px);
    $px = str_replace("[RANDOMSTRING]", $c, $px);
    $map = "keyFile /usr/local/lsws/admin/conf/webadmin.key\ncertFile /usr/local/lsws/admin/conf/webadmin.crt";
    foreach ($l as $n => $t) {
        $map = $map . "\n    " . "map " . $n . " " . $t;
    }
    $px = str_replace("[MAPS]", $map, $px);
    $premade .= "\n" . $px;
}
unlink("/usr/local/lsws/conf/httpd_config.conf");
file_put_contents("/usr/local/lsws/conf/httpd_config.conf", $premade_pre[0] . "\n## DO NOT MODIFY BELOW\n$premade");
echo "\n PROCESS COMPLETE \n";

echo "\n RESTARTING LSHTTPD \n";
shell_exec("systemctl restart lshttpd");

function changesDetector() {
    $domains = callWhmApi("--output=json get_domain_info");
    $domains = $domains["data"]["domains"];
    $sslInfo = callWhmApi("--output=json fetch_vhost_ssl_components");
    $sslInfo = $sslInfo["data"]["components"];  
    $c = "";
    foreach ($domains as $domain) {
        $c .= $domain["domain"];
        $c .= $domain["docroot"];
        $c .= $domain["ipv4"];
        $c .= $domain["ipv4_ssl"];
        $c .= $domain["port"];
        $c .= $domain["port_ssl"];
        $c .= $domain["user"];
        $c .= $domain["php_version"];
    }
    foreach ($sslInfo as $v) {
        $c .= $v["certificate"];
        $c .= $v["key"];
    }
    return md5($c);
}

function callWhmApi($params) {
    $result = shell_exec("whmapi1 $params");
    $json = json_decode($result, true);
    if (empty($json) || (isset($json['status']) && $json['status'] == 0)) {
        echo "\n whmapi1 error: $result \n";
        exit();
    }
    return $json;
}

function convertPHP($phpId) {
    if (substr($phpId, 0, 6) == 'ea-php') {
        return "/opt/cpanel/$phpId/root/usr/bin/lsphp";
    } else if (substr($phpId, 0, 7) == 'alt-php') {
        return '/opt/' . str_replace('-', '/', $phpId) . '/usr/bin/lsphp';
    }
    return '/usr/local/bin/lsphp';
}
