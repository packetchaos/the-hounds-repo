#!/usr/bin/env python3
"""Build a sample navi.db (assets, certs, vulns) so the app runs out of the box.

This is the SAME 33-cert lab dataset the agent was validated against. In a real
deployment you point NAVI_DB_PATH at navi's own navi.db instead — no sample needed.

    python make_sample_db.py            # writes ./navi.db
"""
import os
import sqlite3

OUT = os.environ.get("NAVI_DB_PATH", os.path.join(os.path.dirname(__file__), "sample_navi.db"))

CERTS = [
 ("17b20844-9c41-48ba-a0c2-242c685c9702","tenable.io","192.168.128.22","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Dec 12 20:57:22 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("5c422c07-9c09-438e-a422-9fdee65216d9","ubuntutwo","192.168.128.66","10.152.183.1","Canonical","Canonical","Apr 03 16:07:23 2027 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("74afa793-3c23-4b20-8681-ad83261a09ad"," ","192.168.128.175","Chromecast ICA 21 (ATV)","Google Inc","Cast","May 18 17:18:38 2042 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("ebe40c61-97a6-4fca-9dc6-973943d98da8"," ","192.168.128.56","Buffalo Inc.","Buffalo Inc.","TeraStation","Jun 06 09:15:16 2039 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("9232d2f4-674b-42ce-ac73-24fd851d1424","tenablesc","192.168.128.63","TenableCA (4e)","Tenable, Inc.","INSECURE Certificate Authority for Tenable, Inc.","Jun 02 05:05:45 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("248356f1-bf6e-458c-b74a-e09dd26c92a8"," ","192.168.128.250","VMware-CE-UB","SomeOrganization","SomeOrganizationalUnit","Dec 18 13:10:40 2025 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("56a71fb6-d55c-413a-afd2-8c7d2e334d52"," ","192.168.128.97","localhost","Apache Friends","SomeOrganizationalUnit","Sep 30 09:10:30 2010 GMT","MD5 With RSA Encryption","1024 bits"),
 ("74afa793-3c23-4b20-8681-ad83261a09ad"," ","192.168.128.175","Chromecast ICA 21 (ATV)","Google Inc","Cast","May 18 17:18:38 2042 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933"," ","192.168.113.1","pfSense-6098a9f39e136","pfSense webConfigurator Self-Signed Certificate","Cast","Sep 10 23:19:06 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("16d18078-d259-4b20-a403-bc250ec334bc"," ","192.168.113.126","localhost.localdomain","VMware Installer","VMware ESX Server Default Certificate","Sep 10 15:17:42 2030 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("e05c3885-bbde-49e2-b916-2466a681c8cb"," ","192.168.128.126","localhost.localdomain","VMware Installer","VMware ESX Server Default Certificate","Sep 10 15:17:42 2030 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("17b20844-9c41-48ba-a0c2-242c685c9702","tenable.io","192.168.128.22","TenableCA (08)","Tenable Network Security, Inc.","Certificate Authority for Tenable Network Security, Inc.","Apr 18 16:12:59 2021 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("2f2cc2df-b288-4d25-b4af-a38537135cf1"," ","192.168.113.20","WIN-BLN41CCOKU3.hacker_lab.local","Tenable Network Security, Inc.","Certificate Authority for Tenable Network Security, Inc.","Oct 02 14:38:08 2026 GMT","SHA-1 With RSA Encryption","2048 bits"),
 ("bb65f605-fe09-4979-9d16-6f58dc7475b9","figet.hyrule","192.168.113.150","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Sep 04 20:36:29 2024 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("9e9cda00-d8a0-49a3-9103-6ac854c2ac13","jabba_the_hut.starwars","192.168.128.22","TenableCA (08)","Tenable Network Security, Inc.","Certificate Authority for Tenable Network Security, Inc.","Apr 18 16:12:59 2021 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("59fb535b-3806-4c9f-9519-9d6a896fdc4b","kylo_ren.starwars","192.168.113.126","localhost.localdomain","VMware Installer","VMware ESX Server Default Certificate","Sep 10 15:17:42 2030 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("47052165-3be6-4388-80f1-65fcb2879857"," ","192.168.128.97","localhost","Apache Friends","VMware ESX Server Default Certificate","Sep 30 09:10:30 2010 GMT","MD5 With RSA Encryption","1024 bits"),
 ("9e9cda00-d8a0-49a3-9103-6ac854c2ac13","jabba_the_hut.starwars","192.168.128.22","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Dec 12 20:57:22 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("11b803c1-0000-447b-b582-cde6e5b9fdda","win-bln41ccoku3","192.168.113.20","WIN-BLN41CCOKU3.hacker_lab.local","Nessus Users United","Nessus Certification Authority","Dec 23 01:54:07 2025 GMT","SHA-1 With RSA Encryption","2048 bits"),
 ("e71828b9-ecaf-4768-9dfa-9a3e5b05ede5","darth_maul.starwars","192.168.128.200","TenableCA (96)","Tenable, Inc.","INSECURE Certificate Authority for Tenable, Inc.","Aug 15 04:07:48 2025 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("093be672-7236-4678-9ac8-119b87993d8b"," ","192.168.128.176","SmartViewSDK Root CA G2","Samsung Electronics","Visual Display Business","Mar 25 01:30:51 2072 GMT","SHA-512 With RSA Encryption","2048 bits"),
 ("6dac9581-7280-44e9-9451-0baa81c2c5b0"," ","192.168.113.150","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Sep 04 20:36:29 2024 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("a2c1c1c1-c553-4d80-89d0-5974af1eaf57"," ","192.168.128.66","10.152.183.1","Canonical","Canonical","Jun 24 03:12:42 2026 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("41891acc-963a-487e-9b28-40f1df624afa","anakin_skywalker.starwars","192.168.128.250","VMware-CE-UB","SomeOrganization","SomeOrganizationalUnit","Dec 18 13:10:40 2025 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("0e75b29c-2749-4c58-bafa-52d7ac0fd708","ts3410de68","192.168.128.56","Buffalo Inc.","Buffalo Inc.","TeraStation","Jun 06 09:15:16 2039 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("59fb535b-3806-4c9f-9519-9d6a896fdc4b","kylo_ren.starwars","192.168.113.126","localhost.localdomain","VMware Installer","VMware ESX Server Default Certificate","Sep 10 15:17:42 2030 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("2d7e30f6-9dee-4052-b33d-f2a8111723d7","c-3po.starwars","192.168.128.8","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Apr 02 09:34:21 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("a7a7e4eb-9f9f-45ad-8231-c550967ea6cb"," ","192.168.128.73","camera.ubnt.dev","Ubiquiti Networks Inc.","devint","Dec 07 00:00:10 2099 GMT","ECDSA With SHA-256","256 bits"),
 ("cc83dd53-9ed1-4bb6-9763-1e6fcc92230b","yoda.starwars","192.168.128.63","TenableCA (4e)","Tenable, Inc.","INSECURE Certificate Authority for Tenable, Inc.","Jun 02 05:05:45 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("997d8e86-8b4a-4bf5-b6d2-b50103fcfdf5"," ","192.168.128.175","Chromecast ICA 21 (ATV)","Google Inc","Cast","May 18 17:18:38 2042 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("a4f53f62-135e-4498-92cb-42c549955034","r2-d2.starwars","192.168.128.1","pfSense-6098a9f39e136","pfSense webConfigurator Self-Signed Certificate","Cast","Sep 10 23:19:06 2023 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("997d8e86-8b4a-4bf5-b6d2-b50103fcfdf5"," ","192.168.128.175","Chromecast ICA 21 (ATV)","Google Inc","Cast","May 18 17:18:38 2042 GMT","SHA-256 With RSA Encryption","2048 bits"),
 ("cefc55af-75df-4b1f-8198-532e0387287c","boba_fett.starwars","192.168.128.86","Nessus Certification Authority","Nessus Users United","Nessus Certification Authority","Nov 16 23:09:57 2024 GMT","SHA-256 With RSA Encryption","2048 bits"),
]

# cert-issue plugins -> how many DISTINCT assets to fabricate for each
MATRIX = [
 ("51192","SSL Certificate Cannot Be Trusted",29),
 ("10863","SSL Certificate Information",28),
 ("57582","SSL Self-Signed Certificate",18),
 ("15901","SSL Certificate Expiry",14),
 ("94761","SSL Root Certification Authority Certificate Information",13),
 ("45410","SSL Certificate 'commonName' Mismatch",10),
 ("35291","SSL Certificate Signed Using Weak Hashing Algorithm",4),
 ("45411","SSL Certificate with Wrong Hostname",3),
 ("35297","SSL Service Requests Client Certificate",1),
 ("42981","SSL Certificate Expiry - Future Expiry",1),
 ("83298","SSL Certificate Chain Contains Certificates Expiring Soon",1),
]


def build():
    if os.path.exists(OUT):
        os.remove(OUT)
    con = sqlite3.connect(OUT)
    c = con.cursor()
    c.execute("CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT);")
    c.execute("""CREATE TABLE certs (asset_uuid TEXT, subject_name TEXT, country TEXT,
        state_province TEXT, locality TEXT, organization TEXT, common_name TEXT,
        issuer_name TEXT, organization_unit TEXT, serial_number TEXT, version TEXT,
        signature_algorithm TEXT, not_valid_before TEXT, not_valid_after TEXT,
        algorithm TEXT, key_length TEXT, signature_length TEXT);""")
    c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, last_found TEXT);")

    # assets (unique uuid -> host/ip)
    seen = {}
    for uuid, host, ip, *_ in CERTS:
        seen.setdefault(uuid, (host, ip))
    # pad to 80 assets total like the real tenant
    for i in range(len(seen), 80):
        seen[f"pad-{i:04d}"] = (f"host{i}", f"10.0.0.{i}")
    for uuid, (host, ip) in seen.items():
        c.execute("INSERT INTO assets VALUES (?,?,?)", (uuid, host, ip))

    # certs
    for uuid, host, ip, cn, org, ou, nva, sig, kl in CERTS:
        c.execute("INSERT INTO certs (asset_uuid,common_name,organization,organization_unit,"
                  "not_valid_after,signature_algorithm,key_length) VALUES (?,?,?,?,?,?,?)",
                  (uuid, cn, org, ou, nva, sig, kl))

    # vulns: fabricate DISTINCT-asset rows per cert-issue plugin (+ a few non-cert rows)
    pad_uuids = [f"av-{i:04d}" for i in range(40)]
    for uuid in pad_uuids:
        c.execute("INSERT INTO assets VALUES (?,?,?)", (uuid, "scan-host", "10.1.1.1"))
    for pid, name, count in MATRIX:
        for j in range(count):
            c.execute("INSERT INTO vulns VALUES (?,?,?,?,?)",
                      (pad_uuids[j % len(pad_uuids)], pid, name, "", "2026-06-15T00:00:00Z"))
    c.execute("INSERT INTO vulns VALUES ('av-0000','19506','Nessus Scan Information','','2026-06-15T00:00:00Z')")

    # ---- IoT squad signatures (so the 4-agent pipeline has real work) ----
    # An extra asset NOT in the cert set, used to demonstrate Agent-3 cross-ref:
    c.execute("INSERT INTO assets VALUES ('xref-pf-01','edge-fw-02','192.168.130.50')")
    iot_vulns = [
        # Chromecast — mDNS local-network (seed plugin 66717)
        ("74afa793-3c23-4b20-8681-ad83261a09ad","66717","mDNS Detection (Local Network)","Chromecast-Ultra _googlecast._tcp.local."),
        ("997d8e86-8b4a-4bf5-b6d2-b50103fcfdf5","66717","mDNS Detection (Local Network)","Chromecast _googlecast._tcp.local."),
        # pfSense — a name-matched detector (55786) AND an output-only detector (10107)
        ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933","55786","pfSense Detection","pfSense-6098a9f39e136 / pfSense webConfigurator"),
        ("a4f53f62-135e-4498-92cb-42c549955034","55786","pfSense Detection","pfSense webConfigurator self-signed"),
        ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933","10107","HTTP Server Type and Version","Server: nginx (pfSense webConfigurator)"),
        ("a4f53f62-135e-4498-92cb-42c549955034","10107","HTTP Server Type and Version","Server: nginx (pfSense webConfigurator)"),
        # cross-ref target: shares plugin 10107 but its OWN output does NOT say pfSense,
        # so Agent 1 won't catch it — Agent 3 should surface it as a candidate.
        ("xref-pf-01","10107","HTTP Server Type and Version","Server: nginx"),
        # Ubiquiti — name-matched detector (new proposal, since seed has no plugins)
        ("a7a7e4eb-9f9f-45ad-8231-c550967ea6cb","131732","Ubiquiti Device Detection","ubnt camera.ubnt.dev firmware"),
        # Buffalo TeraStation — NAS detection plugin
        ("ebe40c61-97a6-4fca-9dc6-973943d98da8","76423","Buffalo TeraStation NAS Detection","TeraStation series NAS"),
        ("0e75b29c-2749-4c58-bafa-52d7ac0fd708","76423","Buffalo TeraStation NAS Detection","TeraStation series NAS"),
        # Samsung SmartTV — discovered the way live navi sees it: cert text in the
        # SSL Certificate Information (10863) output. 10863 is on the generic
        # denylist, so Agent 2 will NOT promote it — exercises the guardrail.
        ("093be672-7236-4678-9ac8-119b87993d8b","10863","SSL Certificate Information","Subject: CN=SmartViewSDK Root CA G2, O=Samsung Electronics"),
    ]
    for uuid, pid, name, out in iot_vulns:
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?)", (uuid, pid, name, out, "2026-06-15T00:00:00Z"))

    # ---- Custom App agent: routes, paths, software inventory ----
    c.execute("CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);")
    c.execute("CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);")
    c.execute("CREATE TABLE software (asset_uuid TEXT, software_string TEXT);")
    routes = [
        ("CENTOS", "Operating System", 316), ("NGINX WEB SERVER", "Application", 54),
        ("JENKINS", "Application", 50), ("DOCKER ENGINE", "Application", 1),
        ("APACHE", "Application", 5), ("NAVI", "Application", 3),
    ]
    for i, (n, vt, tv) in enumerate(routes, 1):
        c.execute("INSERT INTO vuln_route VALUES (?,?,?,?,?)", (i, n, "", tv, vt))
    # software inventory (package-level) — note docker-ce & urllib3 ARE here, so
    # docker/urllib3 should be FILTERED OUT; jenkins/nessus/navi/spring are NOT.
    sw = ["adduser-3.118ubuntu5", "apt-2.4.9", "bash-5.1-6ubuntu1", "openssl-3.0.2",
          "python3-3.10.6", "docker-ce-24.0.7", "urllib3-1.26.12", "curl-7.81.0"]
    for s in sw:
        c.execute("INSERT INTO software VALUES (?,?)", ("5c422c07-9c09-438e-a422-9fdee65216d9", s))
    T = "17b20844-9c41-48ba-a0c2-242c685c9702"   # tenable.io
    U = "5c422c07-9c09-438e-a422-9fdee65216d9"   # ubuntutwo
    A = "a2c1c1c1-c553-4d80-89d0-5974af1eaf57"
    # version-sprawl demo for the Software Analyzer: same product at several versions
    sprawl = [
        ("openssl-1.0.2k-19.el7", T), ("openssl-1.1.1k-7.el7", A), ("openssl-3.0.2-0ubuntu1", U),
        ("python3-3.6.8-18.el7", T), ("python3-3.6.8-18.el7", A), ("python3-3.10.6-1", U),
        ("curl-7.29.0-59.el7", T), ("curl-7.81.0-1", U),
        ("log4j-2.14.1-1", T), ("log4j-2.17.1-1", A),
        ("openssh-7.4p1-21.el7", T), ("openssh-8.0p1-5.el7", A), ("openssh-8.9p1-3", U),
        # a standardized product — one version everywhere
        ("zlib-1.2.11-1", T), ("zlib-1.2.11-1", A), ("zlib-1.2.11-1", U),
    ]
    for s, a in sprawl:
        c.execute("INSERT INTO software VALUES (?,?)", (a, s))
    # business-critical software for the Crown-jewel + Risk-leaderboard views (Mimir).
    # Placed on high-ACR / CVE-bearing assets so the risk leaderboard has KEV/critical hits.
    crown_sw = [
        ("nginx-1.18.0-6ubuntu14", U), ("nginx-1.20.1-1.el8", A), ("nginx-1.24.0-1", T),
        ("mysql-server-8.0.34-1", T), ("mysql-server-5.7.42-1", A),
        ("postgresql-server-13.11-1", U), ("mariadb-server-10.6.12-1", A),
        ("openldap-2.4.57-2", T), ("samba-4.15.13-0", A),
        ("tomcat-9.0.71-1", U), ("openvpn-2.5.9-1", T),
        ("splunk-9.0.4-1", A), ("veeam-12.0.0-1", T),
        ("redis-6.2.7-1", U), ("mongodb-6.0.5-1", A),
    ]
    for s, a in crown_sw:
        c.execute("INSERT INTO software VALUES (?,?)", (a, s))
    paths = [
        ("145533", "/usr/lib/jenkins/jenkins.war", T),
        ("180006", "/var/lib/jenkins/plugins/git", T),
        ("161440", "/var/lib/jenkins/plugins/credentials", T),
        ("19506", "/opt/nessus", T),
        ("19506", "/opt/nessus_agent", "9e9cda00-d8a0-49a3-9103-6ac854c2ac13"),
        ("99001", "/opt/navi", U),                 # the user's example app
        ("99001", "/home/analyst/navi/navi.db", A),
        ("99002", "/snap/bin/docker", U),          # docker-ce IS in inventory → filtered
        ("99003", "/var/lib/docker/overlay2/8e0a381695d1/diff/app/spring-boot-application.jar", U),
        ("99004", "/usr/local/lib/python3.6/site-packages/urllib3-1.26.12-py3.6.egg/PKG-INFO", U),
    ]
    for i, (pid, p, uuid) in enumerate(paths, 1):
        c.execute("INSERT INTO vuln_paths VALUES (?,?,?,?,?)", (i, pid, p, uuid, f"f{i}"))

    # ---- plugin-mediated route<->path linkage + reduction funnel demo data ----
    # Populate plugin_list per route so a route's plugins tie to the paths where they were
    # found (the accurate CVE→plugin→app→path chain). CENTOS intentionally has NO path (its
    # plugins aren't in vuln_paths) → "app with no path detail"; plugin 99004 is in a path
    # but no route → an ORPHAN path.
    route_plugins = {
        "JENKINS":        ["145533", "180006", "161440"],
        "NGINX WEB SERVER": ["19506"],
        "NAVI":           ["99001"],
        "DOCKER ENGINE":  ["99002"],
        "APACHE":         ["99003"],
        "CENTOS":         ["51192", "35291", "57582"],
    }
    for app, pl in route_plugins.items():
        c.execute("UPDATE vuln_route SET plugin_list=? WHERE app_name=?", (str(pl), app))
    # a Chrome-style champion: one plugin bundling many CVEs (biggest workload collapse)
    c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) VALUES (?,?,?,?,?)",
              (U, "319296", "Google Chrome < 149.0.7827.53 Multiple Vulnerabilities", "", "2026-06-15T00:00:00Z"))
    # NOTE: the plugins table (per-plugin CVE lists for the reduction funnel + champion)
    # is populated at the END of build() so it covers EVERY plugin present in vulns.

    # ---- discovery signals (device-type / OUI / mDNS / users / banners) ----
    # so IoT + identity discovery render against the sample DB too.
    discovery_vulns = [
        # 54615 Device Type
        ("74afa793-3c23-4b20-8681-ad83261a09ad", "54615", "Device Type", "Remote device type : embedded\nConfidence level : 95"),
        ("ebe40c61-97a6-4fca-9dc6-973943d98da8", "54615", "Device Type", "Remote device type : embedded\nConfidence level : 90"),
        ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933", "54615", "Device Type", "Remote device type : firewall\nConfidence level : 86"),
        ("16d18078-d259-4b20-a403-bc250ec334bc", "54615", "Device Type", "Remote device type : hypervisor\nConfidence level : 99"),
        ("a7a7e4eb-9f9f-45ad-8231-c550967ea6cb", "54615", "Device Type", "Remote device type : switch\nConfidence level : 80"),
        ("5c422c07-9c09-438e-a422-9fdee65216d9", "54615", "Device Type", "Remote device type : general-purpose\nConfidence level : 95"),
        # 35716 Ethernet Card Manufacturer (OUI)
        ("74afa793-3c23-4b20-8681-ad83261a09ad", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\n00:1A:11:xx:xx:xx : Google, Inc."),
        ("ebe40c61-97a6-4fca-9dc6-973943d98da8", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\n00:24:A5:xx:xx:xx : BUFFALO.INC"),
        ("a7a7e4eb-9f9f-45ad-8231-c550967ea6cb", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\n44:D9:E7:xx:xx:xx : Ubiquiti Inc"),
        ("093be672-7236-4678-9ac8-119b87993d8b", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\nAC:5F:3E:xx:xx:xx : Samsung Electronics Co.,Ltd"),
        ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\n00:08:A2:xx:xx:xx : eac AUTOMATION-CONSULTING GmbH"),
        ("16d18078-d259-4b20-a403-bc250ec334bc", "35716", "Ethernet Card Manufacturer Detection", "The following card manufacturers were identified :\n00:50:56:xx:xx:xx : VMware, Inc."),
        # 86420 Ethernet MAC
        ("74afa793-3c23-4b20-8681-ad83261a09ad", "86420", "Ethernet MAC Addresses", "00:1A:11:00:00:01"),
        ("ebe40c61-97a6-4fca-9dc6-973943d98da8", "86420", "Ethernet MAC Addresses", "00:24:A5:00:00:02"),
        # 95928 Linux user list enumeration — STRUCTURED (UID + Home + Start script) so the
        # identity agent can classify by the login.defs UID convention (UID 0 = root superuser,
        # UID < 1000 = system account) and by interactive-shell evidence for real people.
        ("5c422c07-9c09-438e-a422-9fdee65216d9", "95928", "Linux User List Enumeration",
         "[ System Accounts ]\n"
         "User : root\n  UID : 0\n  Home folder : /root\n  Start script : /bin/bash\n"
         "User : www-data\n  UID : 33\n  Home folder : /var/www\n  Start script : /usr/sbin/nologin\n"
         "User : postfix\n  UID : 105\n  Home folder : /var/spool/postfix\n  Start script : /usr/sbin/nologin\n"
         "User : jenkins\n  UID : 110\n  Home folder : /var/lib/jenkins\n  Start script : /bin/false\n"
         "User : pihole\n  UID : 999\n  Home folder : /home/pihole\n  Start script : /usr/sbin/nologin\n"
         "[ User Accounts ]\n"
         "User : itninja\n  UID : 1000\n  Home folder : /home/itninja\n  Start script : /bin/bash\n"),
        ("17b20844-9c41-48ba-a0c2-242c685c9702", "95928", "Linux User List Enumeration",
         "[ System Accounts ]\n"
         "User : root\n  UID : 0\n  Home folder : /root\n  Start script : /bin/bash\n"
         "User : tns\n  UID : 54321\n  Home folder : /opt/oracle\n  Start script : /bin/false\n"
         "User : dockerroot\n  UID : 998\n  Home folder : /var/lib/docker\n  Start script : /usr/sbin/nologin\n"
         "User : chrony\n  UID : 123\n  Home folder : /var/lib/chrony\n  Start script : /usr/sbin/nologin\n"),
        # Windows local-user enumeration — usernames followed by their SID, so the agent can
        # classify by Microsoft's well-known RID (Administrator=500, Guest=501).
        ("11b803c1-0000-447b-b582-cde6e5b9fdda", "10860", "SMB Enumerate Local Users",
         "- Administrator\n  SID : S-1-5-21-1284227242-1035525444-1873268478-500\n"
         "- Guest\n  SID : S-1-5-21-1284227242-1035525444-1873268478-501\n"
         "- DefaultAccount\n  SID : S-1-5-21-1284227242-1035525444-1873268478-503\n"
         "- itadmin\n  SID : S-1-5-21-1284227242-1035525444-1873268478-1103\n"),
        ("5c422c07-9c09-438e-a422-9fdee65216d9", "83303", "Local Users Information : Passwords Never Expire", "root\nitninja"),
        # web/service banners on assets WITHOUT software inventory (shadow software)
        ("56a71fb6-d55c-413a-afd2-8c7d2e334d52", "10107", "HTTP Server Type and Version", "Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.8l PHP/5.3.1"),
        ("718e9bec-44e0-4925-8aaa-e2d6b3c3e933", "10107", "HTTP Server Type and Version", "nginx (pfSense webConfigurator)"),
        ("093be672-7236-4678-9ac8-119b87993d8b", "10719", "MySQL Server Detection", "MySQL Server detected on port 3306"),
        # EOL / Unsupported lifecycle plugins (for the EOL agent demo)
        ("56a71fb6-d55c-413a-afd2-8c7d2e334d52", "33850", "Unix Operating System Unsupported Version Detection", "The remote OS is no longer supported."),
        ("16d18078-d259-4b20-a403-bc250ec334bc", "108797", "VMware ESXi Unsupported Version Detection", "ESXi 5.5 is unsupported."),
        ("11b803c1-0000-447b-b582-cde6e5b9fdda", "11936", "Microsoft Windows Server 2012 End of Life", "Windows Server 2012 reached End of Life."),
        ("56a71fb6-d55c-413a-afd2-8c7d2e334d52", "171560", "Apache 2.2.x SEoL", "Apache 2.2.x is End of Life (SEoL)."),
    ]
    for uuid, pid, name, out in discovery_vulns:
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?)", (uuid, pid, name, out, "2026-06-15T00:00:00Z"))

    # ---- Identity-agent signals (Janus): machine identities, auth weakness, coverage gap ----
    _idu = [r[0] for r in c.execute("SELECT uuid FROM assets WHERE hostname IS NOT NULL "
                                    "AND TRIM(hostname)<>'' AND hostname NOT IN ('scan-host') LIMIT 8").fetchall()]
    _idrows = []
    if _idu:
        # machine identities: SNMP default community (public + one private/write) and Windows host SIDs
        _idrows += [(_idu[0], "41028", "SNMP Agent Default Community Name (public)", "Community name : public"),
                    (_idu[1], "41028", "SNMP Agent Default Community Name (private)", "Community name : private (WRITE)")]
        for u in _idu[:4]:
            _idrows.append((u, "10859", "Microsoft Windows SMB LsaQueryInformationPolicy Host SID", "Host SID : S-1-5-21-1234567890-1"))
        # auth weaknesses: SSH password auth + weak Windows password policy
        for u in _idu[:3]:
            _idrows.append((u, "149334", "SSH Password Authentication Accepted", "Password authentication is enabled."))
        _idrows.append((_idu[0], "17651", "Microsoft Windows SMB : Password Policy", "Password must meet complexity requirements: Disabled\nMaximum password age (days): 0"))
        # coverage gap: reachable hosts scanned WITHOUT credentials
        _blindu = [f"blind-{i:03d}" for i in range(7)]
        for bu in _blindu:
            c.execute("INSERT INTO assets (uuid, hostname, ip_address) VALUES (?,?,?)", (bu, "uncredentialed-host", "10.9.9.9"))
            _idrows.append((bu, "110723", "Target Credential Status by Authentication Protocol - No Credentials Provided", "No credentials were provided."))
        # a default-credential + an AD attack-path finding for the correlated-signals line
        _idrows.append((_idu[2], "playbook-defcred", "Default Credentials for Web Console", "Default credentials accepted (admin/admin)."))
        _idrows.append((_idu[3], "playbook-asrep", "Kerberos AS-REP Roasting", "AS-REP roastable account found (krbtgt referenced)."))
    for uuid, pid, name, out in _idrows:
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?)", (uuid, pid, name, out, "2026-06-15T00:00:00Z"))

    # ---- CVE references on a few findings (for the MITRE ATT&CK agent demo) ----
    # real CVEs that appear in the Center for Threat-Informed Defense ATT&CK->CVE map
    c.execute("ALTER TABLE vulns ADD COLUMN cves TEXT")
    demo_cves = ["CVE-2017-0144", "CVE-2014-6271", "CVE-2019-0708", "CVE-2021-34527",
                 "CVE-2020-1472", "CVE-2017-5638", "CVE-2021-44228", "CVE-2014-0160"]
    rids = [r[0] for r in c.execute("SELECT rowid FROM vulns LIMIT ?", (len(demo_cves),)).fetchall()]
    for rid, cve in zip(rids, demo_cves):
        c.execute("UPDATE vulns SET cves=? WHERE rowid=?", (f"['{cve}']", rid))

    # ---- CISA KEV (xrefs) — for the CISA KEV agent (Laelaps) + the AI Contract ----
    # real navi.db stores KEV membership in vulns.xrefs as a Python-list string:
    #   [{'type': 'CISA-KNOWN-EXPLOITED', 'id': 'YYYY/MM/DD'}]  (id = catalog dateAdded)
    c.execute("ALTER TABLE vulns ADD COLUMN xrefs TEXT")
    kev_dates = ["2022/03/25", "2021/11/03", "2023/05/01", "2024/01/10", "2022/03/25", "2021/11/03"]
    kev_rids = [r[0] for r in c.execute("SELECT rowid FROM vulns WHERE TRIM(COALESCE(cves,''))<>'' "
                                        "LIMIT ?", (len(kev_dates),)).fetchall()]
    for rid, d in zip(kev_rids, kev_dates):
        c.execute("UPDATE vulns SET xrefs=? WHERE rowid=?",
                  ("[{'type': 'CISA-KNOWN-EXPLOITED', 'id': '" + d + "'}]", rid))

    # ---- Post-Quantum cipher-analysis plugins (Heimdall) + the AI Contract ----
    # (plugin_family is ALTER-added further down and defaulted to 'General' there)
    pq_assets = [r[0] for r in c.execute("SELECT uuid FROM assets LIMIT 4").fetchall()]
    for uu in pq_assets:
        for pid, nm in [("277650", "Remote Services NOT Using Post-Quantum Ciphers"),
                        ("277652", "SSL/TLS Target Cipher Suite Inventory"),
                        ("277653", "Remote Services Using Post-Quantum Ciphers")]:
            c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) "
                      "VALUES (?,?,?,?,?)",
                      (uu, pid, nm, "cipher analysis", "2026-06-01T00:00:00Z"))
    # asset ACR (real navi.db has this column) — give CVE-bearing assets a high ACR
    # so the MITRE 'ACR > 7' view and the insights tile have something to show.
    c.execute("ALTER TABLE assets ADD COLUMN acr TEXT")
    c.execute("ALTER TABLE assets ADD COLUMN aes INTEGER")
    hi = [r[0] for r in c.execute("SELECT DISTINCT asset_uuid FROM vulns "
                                  "WHERE TRIM(COALESCE(cves,''))<>'' LIMIT 5").fetchall()]
    for u in hi:
        c.execute("UPDATE assets SET acr=?, aes=? WHERE uuid=?", ("9", 720, u))
    # give every other asset a plausible ACR/AES so the Asset Explorer shows values
    for i, (u,) in enumerate(c.execute("SELECT uuid FROM assets WHERE acr IS NULL").fetchall()):
        acr = [3, 5, 6, 7, 8][i % 5]
        c.execute("UPDATE assets SET acr=?, aes=? WHERE uuid=?", (str(acr), acr * 80, u))
    # severity + score(VPR) on vulns (real navi.db has these) so the Vuln Explorer shows them
    c.execute("ALTER TABLE vulns ADD COLUMN severity TEXT")
    c.execute("ALTER TABLE vulns ADD COLUMN score REAL")
    _sevmap = [("Critical", 9.6), ("High", 8.1), ("Medium", 5.4), ("Low", 3.1), ("Info", 0.0)]
    for i, (rid,) in enumerate(c.execute("SELECT rowid FROM vulns").fetchall()):
        sev, vpr = _sevmap[i % len(_sevmap)]
        c.execute("UPDATE vulns SET severity=?, score=? WHERE rowid=?", (sev, vpr, rid))

    # ---- Post-Quantum migration-roadmap signals (Heimdall crown-jewel correlation) ----
    # Give a handful of NAMED assets the full spread of quantum-risk signals so the
    # roadmap populates cert-risk + transport + crypto-agility + KEV columns:
    #   transport  277654 (TLS classical KEX), 70657 (SSH classical KEX),
    #              153588 (SSH SHA-1 HMAC), 56984 (deprecated TLS)
    #   agility    10267/181418 (OpenSSH banner), 168149 (OpenSSL version)
    _pqr = c.execute("SELECT uuid FROM assets WHERE hostname IS NOT NULL AND TRIM(hostname)<>'' "
                     "AND hostname NOT IN ('scan-host') LIMIT 8").fetchall()
    _pqr = [r[0] for r in _pqr]
    if _pqr:
        # crown jewels: first four get ACR 8/9 so they surface at the top
        for j, uu in enumerate(_pqr[:4]):
            c.execute("UPDATE assets SET acr=? WHERE uuid=?", (["9", "8", "8", "7"][j], uu))
        _tp = [
            ("277654", "SSL/TLS Supported Groups", "Supported groups: secp256r1, secp384r1, x25519 (classical ECDH only — no ML-KEM/Kyber)"),
            ("70657", "SSH Algorithms and Languages Supported", "kex: curve25519-sha256, ecdh-sha2-nistp256; mac: hmac-sha1, hmac-sha2-256 (no sntrup/ML-KEM)"),
            ("153588", "SSH Weak MAC Algorithms Enabled", "The following weak MAC algorithms are enabled: hmac-sha1"),
            ("56984", "SSL/TLS Versions Supported", "TLSv1.0 TLSv1.1 TLSv1.2 supported (TLS 1.0/1.1 deprecated)"),
        ]
        # transport signals on the first six
        for uu in _pqr[:6]:
            for pid, nm, out in _tp[: (3 if uu in _pqr[:3] else 2)]:
                c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) "
                          "VALUES (?,?,?,?,?)", (uu, pid, nm, out, "2026-06-01T00:00:00Z"))
        # crypto-agility banners: legacy stacks (OpenSSH 7.4 / OpenSSL 1.1.1) vs PQC-ready (9.6 / 3.2.1)
        _ag = [("OpenSSH_7.4", "OpenSSL 1.1.1w"), ("OpenSSH_7.4", "OpenSSL 1.0.2u"),
               ("OpenSSH_8.2", "OpenSSL 1.1.1w"), ("OpenSSH_9.6", "OpenSSL 3.2.1"),
               ("OpenSSH_9.3", "OpenSSL 3.0.13"), ("OpenSSH_8.9", "OpenSSL 3.0.2")]
        for uu, (ssh, ssl) in zip(_pqr[:6], _ag):
            c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) "
                      "VALUES (?,?,?,?,?)", (uu, "10267", "SSH Server Type and Version Information",
                                             "SSH version : " + ssh, "2026-06-01T00:00:00Z"))
            c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) "
                      "VALUES (?,?,?,?,?)", (uu, "168149", "OpenSSL Detection",
                                             "Version : " + ssl, "2026-06-01T00:00:00Z"))
        # KEV overlap: mark two roadmap crown jewels as actively exploited
        for uu in _pqr[:2]:
            c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found,cves,xrefs) "
                      "VALUES (?,?,?,?,?,?,?)",
                      (uu, "97833", "Remote code execution (KEV)", "", "2026-06-01T00:00:00Z",
                       "['CVE-2021-44228']",
                       "[{'type': 'CISA-KNOWN-EXPLOITED', 'id': '2021/12/10'}]"))

    # ---- tags table (real navi.db: tag_id, asset_uuid, asset_ip, tag_key, tag_uuid,
    #      tag_value, tag_added_date) — lets the Advanced search join tags⋈assets⋈vulns⋈epss
    c.execute("""CREATE TABLE tags (tag_id INTEGER PRIMARY KEY, asset_uuid TEXT,
                 asset_ip TEXT, tag_key TEXT, tag_uuid TEXT, tag_value TEXT,
                 tag_added_date TEXT);""")
    _au = [r[0] for r in c.execute("SELECT uuid FROM assets").fetchall()]
    _tagplan = [("Business Tier", "Production"), ("Business Tier", "Staging"),
                ("Environment", "Cloud"), ("Owner", "VM Team")]
    for i, u in enumerate(_au):
        ip = c.execute("SELECT ip_address FROM assets WHERE uuid=?", (u,)).fetchone()
        key, val = _tagplan[i % len(_tagplan)]
        c.execute("INSERT INTO tags (asset_uuid, asset_ip, tag_key, tag_uuid, tag_value, "
                  "tag_added_date) VALUES (?,?,?,?,?,?)",
                  (u, ip[0] if ip else "", key, f"tag-{i:04d}", val, "2026-06-01T00:00:00Z"))
        # make sure the high-ACR / CVE-bearing assets land in Production for the demo
    for u in hi:
        c.execute("UPDATE tags SET tag_key='Business Tier', tag_value='Production' "
                  "WHERE asset_uuid=? AND tag_key='Business Tier'", (u,))
    # Route-scoped Owner tags in the "<app>: <user>" scheme so the Ownership Map
    # Threads/Sankey graphs light up (owners attach to a route only when the tag's
    # app-part matches the route's app_name). Some routes fully owned, one partial,
    # and a couple left unowned to show Ownerless Risk.
    def _own(u, val, tu):
        ip = c.execute("SELECT ip_address FROM assets WHERE uuid=?", (u,)).fetchone()
        c.execute("INSERT INTO tags (asset_uuid, asset_ip, tag_key, tag_uuid, tag_value, "
                  "tag_added_date) VALUES (?,?,?,?,?,?)",
                  (u, ip[0] if ip else "", "Owner", tu, val, "2026-06-20T00:00:00Z"))
    # routes that actually have assets in the sample: CENTOS (full) + TENABLE NESSUS (partial)
    _owner_routes = [("CENTOS", "CENTOS: Linux Team", 1.0),
                     ("NGINX WEB SERVER", "NGINX WEB SERVER: Web Team", 0.5)]
    for app, val, frac in _owner_routes:
        aus = [r[0] for r in c.execute(
            "SELECT DISTINCT v.asset_uuid FROM vuln_route r JOIN vulns v "
            "ON r.plugin_list LIKE '%'''||v.plugin_id||'''%' WHERE r.app_name=?", (app,)).fetchall()]
        for u in (aus[:max(1, int(len(aus) * frac))] if aus else []):
            _own(u, val, "owner-" + app.replace(" ", "-").lower())
    # own a spread of filesystem paths so the Threads/Sankey graphs fan out to several teams
    _path_teams = ["CI/CD Team", "Platform Team", "Web Team", "App Team", "Data Team"]
    _paths = [r[0] for r in c.execute(
        "SELECT path FROM vuln_paths WHERE path IS NOT NULL GROUP BY path "
        "ORDER BY COUNT(DISTINCT asset_uuid) DESC, path LIMIT 12").fetchall()]
    for i, p in enumerate(_paths):
        team = _path_teams[i % len(_path_teams)]
        for u in [r[0] for r in c.execute(
                "SELECT DISTINCT asset_uuid FROM vuln_paths WHERE path=?", (p,)).fetchall()]:
            _own(u, p + ": " + team, "owner-path-%02d" % i)

    # ---- epss table (real navi.db: cve PK, epss_value, percentile) — join via
    #      vulns.cves LIKE '%'||epss.cve||'%'
    c.execute("CREATE TABLE epss (cve TEXT PRIMARY KEY, epss_value REAL, percentile REAL);")
    _epss = {"CVE-2017-0144": 0.975, "CVE-2014-6271": 0.967, "CVE-2019-0708": 0.944,
             "CVE-2021-34527": 0.886, "CVE-2020-1472": 0.972, "CVE-2017-5638": 0.975,
             "CVE-2021-44228": 0.975, "CVE-2014-0160": 0.939}
    for cve, val in _epss.items():
        c.execute("INSERT OR REPLACE INTO epss (cve, epss_value, percentile) VALUES (?,?,?)",
                  (cve, val, round(val, 3)))

    # ---- platform deep-link URLs (real navi.db carries these) ----
    # assets.url -> the asset's details page; vulns.url -> that finding's plugin page.
    _BASE = "https://cloud.tenable.com/tio/app.html#/vulnerability-management/dashboard/assets/asset-details/"
    c.execute("ALTER TABLE assets ADD COLUMN url TEXT")
    for (u,) in c.execute("SELECT uuid FROM assets").fetchall():
        c.execute("UPDATE assets SET url=? WHERE uuid=?", (f"{_BASE}{u}/vulns", u))
    c.execute("ALTER TABLE vulns ADD COLUMN url TEXT")
    for (rid, au, pid) in c.execute("SELECT rowid, asset_uuid, plugin_id FROM vulns").fetchall():
        if au and pid:
            c.execute("UPDATE vulns SET url=? WHERE rowid=?",
                      (f"{_BASE}{au}/vulns/vulnerability-details/{pid}/details", rid))

    # ---- plugin_family + AI / Docker / Web / Cloud signals (insights tiles + AI agent) ----
    c.execute("ALTER TABLE vulns ADD COLUMN plugin_family TEXT")
    c.execute("UPDATE vulns SET plugin_family='Web Servers' WHERE plugin_name LIKE '%HTTP%' OR plugin_name LIKE '%Web%' OR plugin_name LIKE '%SSL%'")
    c.execute("UPDATE vulns SET plugin_family='CGI abuses' WHERE plugin_name LIKE '%CGI%' OR plugin_name LIKE '%PHP%'")
    c.execute("UPDATE vulns SET plugin_family='General' WHERE plugin_family IS NULL")
    # AI software (Tenable 'Artificial Intelligence' family) on a couple of assets
    ai_plugins = [("210001", "Ollama LLM Server Detection"),
                  ("210002", "NVIDIA Triton Inference Server Detection"),
                  ("210003", "PyTorch / Hugging Face Framework Detection")]
    for u in (hi[:2] or [r[0] for r in c.execute("SELECT uuid FROM assets LIMIT 2").fetchall()]):
        for pid, name in ai_plugins:
            c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found,plugin_family,url) "
                      "VALUES (?,?,?,?,?,?,?)",
                      (u, pid, name, "Detected AI/ML runtime on host.", "2026-06-15T00:00:00Z",
                       "Artificial Intelligence", f"{_BASE}{u}/vulns/vulnerability-details/{pid}/details"))
    # Docker host — plugin 93561, output lists running containers
    if hi:
        du = hi[0]
        c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found,plugin_family,url) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (du, "93561", "Docker Software Detection",
                   "Running containers:\n  nginx:latest (Up 3 days)\n  redis:7 (Up 1 week)\n  app/api:prod (Up 2 days)",
                   "2026-06-15T00:00:00Z", "Service detection",
                   f"{_BASE}{du}/vulns/vulnerability-details/93561/details"))
    # Cloud provenance columns (real navi.db carries these) + tag a few assets
    for col in ("aws_id", "aws_ec2_name", "aws_ec2_region", "gcp_instance_id",
                "gcp_project_id", "azure_vm_id", "azure_resource_id", "azure_subscription_id"):
        try:
            c.execute(f"ALTER TABLE assets ADD COLUMN {col} TEXT")
        except Exception:
            pass
    allu = [r[0] for r in c.execute("SELECT uuid FROM assets").fetchall()]
    for i, u in enumerate(allu[:6]):
        if i % 3 == 0:
            c.execute("UPDATE assets SET aws_id=?, aws_ec2_name=?, aws_ec2_region=? WHERE uuid=?",
                      (f"i-0{i}a1b2c3d4", f"ec2-prod-{i}", "us-east-1", u))
        elif i % 3 == 1:
            c.execute("UPDATE assets SET gcp_instance_id=?, gcp_project_id=? WHERE uuid=?",
                      (f"gce-{i}-8841", "prj-security-01", u))
        else:
            c.execute("UPDATE assets SET azure_vm_id=?, azure_resource_id=?, azure_subscription_id=? WHERE uuid=?",
                      (f"az-vm-{i}", f"/subscriptions/abc/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm{i}", "abc-123", u))

    # ---- scan evaluation data: plugin 19506 (Nessus Scan Information) + 104410 cred fails ----
    _scn = [("192.168.128.8", "Basic Network Scan", "Daily Scan Production Network", 62),
            ("192.168.128.8", "Credentialed Host Audit", "Weekly Credentialed Audit", 540),
            ("192.168.140.20", "Basic Network Scan", "DMZ Perimeter Scan", 95),
            ("192.168.140.20", "Advanced Scan", "Quarterly Deep Scan", 1320),
            ("10.50.0.5", "Web App Overview", "App Tier Scan", 210)]
    allu2 = [r[0] for r in c.execute("SELECT uuid FROM assets").fetchall()]
    for i, u in enumerate(allu2):
        ip, pol, name, secs = _scn[i % len(_scn)]
        out = ("Information about this scan : \n\nScanner edition used : Nessus\n"
               f"Scan name : {name}\nScan policy used : {pol}\nScanner IP : {ip}\n"
               f"Credentialed checks : {'yes' if pol.startswith('Credential') else 'no'}\n"
               f"Scan Start Date : 2026/4/9 20:40 EDT\nScan duration : {secs} sec\n")
        c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found,plugin_family,url) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (u, "19506", "Nessus Scan Information", out, "2026-06-15T00:00:00Z",
                   "Settings", f"{_BASE}{u}/vulns/vulnerability-details/19506/details"))
    # credential failures (plugin 104410) on ~7 assets
    for u in allu2[:7]:
        c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found,plugin_family,url) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (u, "104410", "Authentication Failure - Local Checks Not Run",
                   "It was not possible to log into the remote host via SSH/SMB.",
                   "2026-06-15T00:00:00Z", "Settings",
                   f"{_BASE}{u}/vulns/vulnerability-details/104410/details"))

    # ---- provenance stamp: marks this DB as CRAFTED FIXTURE (not real Tenable data) ----
    import datetime as _dt
    c.execute("CREATE TABLE _provenance (source TEXT, generated TEXT, note TEXT);")
    c.execute("INSERT INTO _provenance VALUES (?,?,?)",
              ("fixture", _dt.datetime.now().isoformat(timespec="seconds"),
               "Crafted sample dataset built by make_sample_db.py — NOT real navi.db / Tenable data."))

    # ---- host hardware inventory (CPU/RAM): Windows WMI 24270, Linux DMI 45432/45433 ----
    c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) VALUES (?,?,?,?,?)",
              (T, "24270", "Computer Manufacturer Information (WMI)",
               "  Computer Manufacturer : VMware, Inc.\n  Computer Model : VMware7,1\n"
               "  Computer Physical CPU's : 1\n  Computer Logical CPU's  : 2\n    CPU0\n"
               "      Architecture  : x64\n      Physical Cores: 2\n      Logical Cores : 2\n"
               "  Computer Memory : 4095 MB\n", "2026-06-15T00:00:00Z"))
    c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) VALUES (?,?,?,?,?)",
              (U, "45432", "Processor Information (via DMI)",
               "Nessus detected 2 processors :\n\nCurrent Speed   : 2384 MHz\n"
               "Version         : Intel(R) Xeon(R) CPU E5-2696 v2 @ 2.50GHz\nManufacturer    : GenuineIntel\n",
               "2026-06-15T00:00:00Z"))
    c.execute("INSERT INTO vulns (asset_uuid,plugin_id,plugin_name,output,last_found) VALUES (?,?,?,?,?)",
              (U, "45433", "Memory Information (via DMI)", "Total memory : 8192 MB", "2026-06-15T00:00:00Z"))

    # ---- plugins table (per-plugin CVE lists) — reduction funnel + champion.
    # Runs LAST so it covers every plugin actually present in vulns. One Chrome-style
    # plugin (319296) carries the most CVEs = the workload-reduction champion.
    c.execute("CREATE TABLE plugins (plugin_id TEXT, name TEXT, cves TEXT, severity INTEGER);")
    import random as _rnd
    _rnd.seed(7)
    def _cvelist(n, yr=2024):
        return "[" + ",".join("'CVE-%d-%04d'" % (yr, 1000 + j) for j in range(n)) + "]"
    _pids = set(r[0] for r in c.execute("SELECT DISTINCT plugin_id FROM vulns"))
    _pids |= {"145533", "180006", "161440", "19506", "99001", "99002", "99003", "99004"}
    _names = {"319296": "Google Chrome < 149.0.7827.53 Multiple Vulnerabilities"}
    for pid in sorted(_pids):
        n = 90 if pid == "319296" else _rnd.choice([2, 3, 4, 6, 8, 12, 20])
        sev = 3 if pid == "319296" else _rnd.choice([0, 1, 2, 2, 3, 3, 4, 2, 1])  # 0=info … 4=critical
        c.execute("INSERT INTO plugins VALUES (?,?,?,?)", (pid, _names.get(pid, "Plugin " + pid), _cvelist(n), sev))

    con.commit()
    con.close()
    print(f"wrote {OUT}  (assets={len(seen)+len(pad_uuids)}, certs={len(CERTS)}, "
          f"cert-issue plugins={len(MATRIX)})")


if __name__ == "__main__":
    build()
