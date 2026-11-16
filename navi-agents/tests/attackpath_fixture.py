"""Build a realistic attack-path test navi.db for tests/test_attackpath.py.

Usage: python3 tests/attackpath_fixture.py [out.db]   (default: ./ap_full.db)

Segments
  DMZ     10.10.1.0/24  internet-facing web/app (Log4Shell, Confluence OGNL), Linux
  CORP    10.20.5.0/24  Windows workstations (PrintNightmare, SMB signing off, LLMNR, WDigest)
  SERVERS 10.30.8.0/24  DC (Zerologon), SQL (sa blank), file server — crown jewels
  APP     10.40.2.0/24  Linux app tier (PwnKit, Dirty Pipe), shared svc_deploy key
  LAB     10.50.9.0/24  isolated lab: vulns but no crown jewels, no shared creds (should NOT path)
"""
import random, sqlite3, os, uuid as _u



def build(path):
    """Create the fixture DB at `path` (overwritten). Returns (assets, vulns, compliance) row counts."""
    random.seed(42)
    P = path
    if os.path.exists(P):
        os.remove(P)
    c = sqlite3.connect(P)
    c.executescript("""
    CREATE TABLE assets(uuid TEXT PRIMARY KEY, hostname TEXT, fqdn TEXT, ip_address TEXT, operating_system TEXT,
      network TEXT, acr TEXT, aes TEXT, url TEXT, agent_uuid TEXT, last_found TEXT);
    CREATE TABLE vulns(navi_id INTEGER PRIMARY KEY, asset_ip TEXT, asset_uuid TEXT, asset_hostname TEXT, plugin_id TEXT,
      plugin_name TEXT, output TEXT, severity TEXT, cves TEXT, xrefs TEXT, port TEXT, protocol TEXT, plugin_family TEXT,
      score TEXT, state TEXT, first_found TEXT, last_found TEXT, url TEXT);
    CREATE TABLE plugins(plugin_id TEXT PRIMARY KEY, plugin_name TEXT, plugin_family TEXT, description TEXT, solution TEXT,
      cves TEXT, xrefs TEXT, severity TEXT, risk_factor TEXT);
    CREATE TABLE compliance(asset_uuid TEXT, check_id TEXT, check_name TEXT, status TEXT, reference TEXT, audit_file TEXT,
      solution TEXT, info TEXT, see_also TEXT, actual_value TEXT, expected_value TEXT, check_info TEXT);
    CREATE TABLE tags(tag_id INTEGER PRIMARY KEY, asset_uuid TEXT, asset_ip TEXT, tag_key TEXT, tag_uuid TEXT, tag_value TEXT, tag_added_date TEXT);
    CREATE TABLE epss(cve TEXT PRIMARY KEY, epss_value TEXT, percentile TEXT);
    CREATE TABLE software(asset_uuid TEXT, software_string TEXT);
    CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, signature_algorithm TEXT, not_valid_after TEXT, key_length TEXT);
    """)

    A = {}   # name -> dict
    def asset(name, ip, os_, acr, seg):
        u = str(_u.UUID(int=random.getrandbits(128)))
        A[name] = {"uuid": u, "ip": ip, "os": os_, "acr": acr, "seg": seg}
        c.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (u, name, name + ".acme.local", ip, os_, "Default", str(acr), "", "https://cloud.tenable.com/x/" + u,
                   None, "2026-11-01T00:00:00Z"))
        return u

    KEV = "CISA-KNOWN-EXPLOITED:2021/12/10"
    PLUG = {}
    def plugin(pid, name, fam, desc, sev, cves="", xrefs=""):
        PLUG[pid] = (name, fam, desc, sev, cves, xrefs)
        c.execute("INSERT OR REPLACE INTO plugins VALUES(?,?,?,?,?,?,?,?,?)", (pid, name, fam, desc, "Upgrade.", cves, xrefs, sev, sev))

    def vuln(host, pid, port="0", proto="tcp", output="", vpr=""):
        a = A[host]; name, fam, desc, sev, cves, xrefs = PLUG[pid]
        c.execute("INSERT INTO vulns(asset_ip,asset_uuid,asset_hostname,plugin_id,plugin_name,output,severity,cves,xrefs,port,protocol,plugin_family,score,state,first_found,last_found) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (a["ip"], a["uuid"], host, pid, name, output or name, sev, cves, xrefs, str(port), proto, fam, vpr,
                   "OPEN", "2026-08-01T00:00:00Z", "2026-11-01T00:00:00Z"))

    # ---- plugin catalogue (realistic names/families/descriptions) ----
    plugin("156014", "Apache Log4Shell RCE detection via callback correlation (Direct Check HTTP)", "Web Servers",
           "The remote web server is affected by a remote code execution vulnerability in Apache Log4j. An unauthenticated, remote attacker can exploit this to execute arbitrary code.", "Critical", "CVE-2021-44228", KEV)
    plugin("161721", "Atlassian Confluence Server and Data Center OGNL Injection (CVE-2022-26134)", "CGI abuses",
           "An unauthenticated, remote attacker can exploit an OGNL injection to execute arbitrary code on the Confluence server.", "Critical", "CVE-2022-26134", KEV)
    plugin("97833", "MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)", "Windows",
           "The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1. An unauthenticated, remote attacker can execute arbitrary code.", "Critical", "CVE-2017-0144", KEV)
    plugin("151488", "Windows Print Spooler Remote Code Execution (PrintNightmare)", "Windows : Microsoft Bulletins",
           "The Windows Print Spooler service is affected by a remote code execution vulnerability. An authenticated attacker can run arbitrary code with SYSTEM privileges, and a local user can elevate privileges.", "Critical", "CVE-2021-34527", KEV)
    plugin("152102", "Windows Security Accounts Manager Elevation of Privilege (HiveNightmare / SeriousSAM)", "Windows : Microsoft Bulletins",
           "A local elevation of privilege vulnerability exists because of overly permissive ACLs on the SAM database; a local attacker can read password hashes.", "High", "CVE-2021-36934", KEV)
    plugin("140657", "Netlogon Elevation of Privilege Vulnerability (Zerologon) (Remote)", "Windows",
           "An unauthenticated attacker with network access to a domain controller can establish a vulnerable Netlogon session and obtain domain administrator privileges.", "Critical", "CVE-2020-1472", KEV)
    plugin("156018", "Active Directory sAMAccountName Spoofing (noPac)", "Windows",
           "An authenticated domain user can impersonate a domain controller and gain domain administrator privileges.", "High", "CVE-2021-42278,CVE-2021-42287", KEV)
    plugin("156860", "Polkit pkexec Local Privilege Escalation (PwnKit)", "Misc.",
           "A local privilege escalation vulnerability in polkit's pkexec allows an unprivileged local user to gain root privileges.", "High", "CVE-2021-4034", KEV)
    plugin("158676", "Linux Kernel Local Privilege Escalation (Dirty Pipe)", "Misc.",
           "The Linux kernel is affected by a privilege escalation flaw; a local unprivileged user can overwrite read-only files and gain root.", "High", "CVE-2022-0847", KEV)
    plugin("10882", "SSH Protocol Version 1 Session Key Retrieval", "General",
           "The remote SSH daemon supports protocol 1 which is cryptographically weak.", "Medium", "", "")
    plugin("57608", "SMB Signing not required", "Misc.",
           "Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server (NTLM relay).", "Medium", "", "")
    plugin("58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", "Misc.",
           "The remote Terminal Services is not configured to use Network Level Authentication only.", "Medium", "", "")
    plugin("149334", "SSH Password Authentication Accepted", "Misc.",
           "The SSH server on the remote host accepts password authentication.", "Info", "", "")
    plugin("10862", "Microsoft SQL Server sa Account Default Blank Password", "Databases",
           "The remote Microsoft SQL server has a blank password for the 'sa' account. An attacker can log in with full administrative privileges and execute commands.", "Critical", "", "")
    plugin("42873", "SSL Medium Strength Cipher Suites Supported (SWEET32)", "General",
           "The remote host supports the use of SSL ciphers that offer medium strength encryption.", "High", "CVE-2016-2183", "")
    plugin("166555", "Apache HTTP Server 2.4.x < 2.4.55 Multiple Vulnerabilities", "Web Servers",
           "The remote web server is affected by multiple vulnerabilities including a denial of service.", "Medium", "CVE-2022-36760", "")
    plugin("171340", "Jenkins < 2.394 Script Console Remote Code Execution", "CGI abuses",
           "An authenticated attacker with access to the Jenkins script console can execute arbitrary Groovy code on the controller.", "High", "CVE-2023-27898", "")
    plugin("125313", "Microsoft RDP RCE (BlueKeep) (uncredentialed check)", "Windows",
           "The remote host is affected by a remote code execution vulnerability in Remote Desktop Services. An unauthenticated attacker can execute arbitrary code.", "Critical", "CVE-2019-0708", KEV)
    plugin("10107", "HTTP Server Type and Version", "Web Servers", "A web server is running on the remote host.", "Info")
    plugin("22964", "Service Detection", "Service detection", "The remote service could be identified.", "Info")
    plugin("10267", "SSH Server Type and Version Information", "Service detection", "An SSH server is listening on this port.", "Info")
    plugin("10394", "Microsoft Windows SMB Log In Possible", "Windows", "It was possible to log into the remote host via SMB.", "Info")
    plugin("10940", "Remote Desktop Protocol Service Detection", "Service detection", "The remote host has an RDP service.", "Info")
    plugin("10144", "Microsoft SQL Server TCP/IP Listener Detection", "Service detection", "A SQL server is listening.", "Info")
    plugin("66334", "Patch Report", "General", "Patches missing.", "Info")
    plugin("19506", "Nessus Scan Information", "Settings", "Scan info", "Info")
    plugin("95928", "Linux User List Enumeration", "General", "Local users", "Info")
    plugin("10860", "SMB Use Host SID to Enumerate Local Users", "Windows", "Local users", "Info")
    plugin("110723", "Target Credential Status by Authentication Protocol - No Credentials Provided", "Settings", "No creds", "Info")

    # ---- assets ----
    for i in range(1, 6):
        asset(f"web{i:02d}", f"10.10.1.{10+i}", "Ubuntu 20.04", 5, "DMZ")
    asset("confluence01", "10.10.1.40", "Ubuntu 20.04", 6, "DMZ")
    for i in range(1, 21):
        asset(f"ws{i:03d}", f"10.20.5.{20+i}", "Microsoft Windows 10 Enterprise", 3, "CORP")
    asset("dc01", "10.30.8.10", "Microsoft Windows Server 2016", 10, "SERVERS")
    asset("dc02", "10.30.8.11", "Microsoft Windows Server 2019", 10, "SERVERS")
    asset("sql01", "10.30.8.20", "Microsoft Windows Server 2016", 9, "SERVERS")
    asset("files01", "10.30.8.30", "Microsoft Windows Server 2019", 8, "SERVERS")
    asset("backup01", "10.30.8.40", "Microsoft Windows Server 2019", 8, "SERVERS")
    for i in range(1, 9):
        asset(f"app{i:02d}", f"10.40.2.{10+i}", "Red Hat Enterprise Linux 8", 6, "APP")
    asset("payments-db", "10.40.2.50", "Red Hat Enterprise Linux 8", 10, "APP")
    asset("jenkins01", "10.40.2.60", "Ubuntu 22.04", 7, "APP")
    for i in range(1, 6):
        asset(f"lab{i:02d}", f"10.50.9.{10+i}", "Ubuntu 18.04", 2, "LAB")

    # ---- services (ports) ----
    for h, a in A.items():
        win = "Windows" in a["os"]
        if win:
            vuln(h, "10394", 445); vuln(h, "10940", 3389)
        else:
            vuln(h, "10267", 22)
        if a["seg"] == "DMZ":
            vuln(h, "10107", 443); vuln(h, "10107", 8080)
        vuln(h, "19506", 0, output="Credentialed checks : yes, as 'nessus' via " + ("smb" if win else "ssh"))
    vuln("sql01", "10144", 1433); vuln("payments-db", "22964", 5432, output="A PostgreSQL server is running on this port.")
    vuln("jenkins01", "10107", 8080)

    # ---- the exploit chains ----
    # 1) internet → web03 Log4Shell → svc_deploy SSH key/password reused on APP tier → PwnKit root → payments-db
    vuln("web03", "156014", 8080, vpr="9.8"); vuln("web03", "156860", 0); vuln("web03", "149334", 22)
    vuln("confluence01", "161721", 443, vpr="9.8"); vuln("confluence01", "158676", 0)
    for h in ["app01", "app02", "app03", "app05", "payments-db"]:
        vuln(h, "149334", 22)
    vuln("app02", "156860", 0); vuln("payments-db", "158676", 0)
    # 2) CORP: PrintNightmare + HiveNightmare on workstations, SMB signing off, local Administrator reused → sql01 → dc01 Zerologon
    for i in [3, 4, 7, 11, 12, 15]:
        vuln(f"ws{i:03d}", "151488", 445, vpr="9.0")
    for i in [3, 7, 11]:
        vuln(f"ws{i:03d}", "152102", 0)
    for i in range(1, 21):
        vuln(f"ws{i:03d}", "57608", 445)
    vuln("ws009", "97833", 445, vpr="9.6")       # EternalBlue
    vuln("ws014", "125313", 3389, vpr="9.6")     # BlueKeep
    vuln("sql01", "57608", 445); vuln("sql01", "10862", 1433); vuln("sql01", "151488", 445)
    vuln("files01", "57608", 445); vuln("files01", "58453", 3389)
    vuln("dc01", "140657", 135, vpr="10"); vuln("dc02", "156018", 445)
    vuln("backup01", "166555", 443)
    # 3) Jenkins script console (authenticated) — reachable from APP
    vuln("jenkins01", "171340", 8080)
    # 4) LAB: vulnerable but isolated (no shared creds, low ACR, own segment)
    for i in range(1, 6):
        vuln(f"lab{i:02d}", "156860", 0); vuln(f"lab{i:02d}", "42873", 443)
    vuln("lab01", "161721", 443)
    # noise: medium/info stuff everywhere
    for h in list(A)[:40]:
        vuln(h, "42873", 443); vuln(h, "66334", 0)

    # ---- identities ----
    def passwd(host, users):
        blocks = ["[ User Accounts ]"]
        for u, home, sh, uid in users:
            blocks.append(f"User         : {u}\nHome folder  : {home}\nStart script : {sh}\nUID : {uid}\n")
        blocks.append("User         : root\nHome folder  : /root\nStart script : /bin/bash\nUID : 0\n")
        vuln(host, "95928", 0, output="\n".join(blocks))
    for h in ["web01", "web02", "web03", "web04", "web05", "app01", "app02", "app03", "app05", "payments-db", "jenkins01"]:
        passwd(h, [("svc_deploy", "/home/svc_deploy", "/bin/bash", 1001), ("ops", "/home/ops", "/bin/bash", 1002)])
    for h in ["app04", "app06", "app07", "app08", "confluence01"]:
        passwd(h, [("ops", "/home/ops", "/bin/bash", 1002)])
    for i in range(1, 6):
        passwd(f"lab{i:02d}", [(f"student{i}", f"/home/student{i}", "/bin/bash", 1100 + i)])
    def smbusers(host, users):
        vuln(host, "10860", 445, output="\n".join("  - " + u for u in users))
    for i in range(1, 21):
        smbusers(f"ws{i:03d}", ["Administrator", "Guest", "helpdesk"])
    smbusers("sql01", ["Administrator", "svc_sql", "helpdesk"]); smbusers("files01", ["Administrator", "svc_backup"])
    smbusers("backup01", ["Administrator", "svc_backup"]); smbusers("dc01", ["Administrator", "krbtgt"]); smbusers("dc02", ["Administrator", "krbtgt"])

    # ---- compliance (CIS / STIG style names) ----
    WIN_FAIL = [
        ("2.3.8.2", "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"),
        ("18.5.4.2", "Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only)"),
        ("18.3.7", "Ensure 'WDigest Authentication' is set to 'Disabled'"),
        ("18.3.1", "Ensure LAPS AdmPwd GPO Extension / CSE is installed"),
        ("9.1.1", "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"),
        ("17.1.1", "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"),
        ("18.4.7", "Ensure 'Configure LSASS to run as a protected process' is set to 'Enabled'"),
    ]
    WIN_PASS = [("1.1.5", "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"),
                ("2.3.1.1", "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'")]
    LNX_FAIL = [("5.2.10", "Ensure SSH PermitRootLogin is disabled"),
                ("5.3.4", "Ensure users must provide password for privilege escalation"),
                ("5.2.11", "Ensure SSH PermitEmptyPasswords is disabled"),
                ("4.1.1.1", "Ensure auditd is installed")]
    LNX_PASS = [("1.1.1.1", "Ensure mounting of cramfs filesystems is disabled"), ("5.4.1", "Ensure password creation requirements are configured")]
    def comp(host, cid, name, st, audit):
        c.execute("INSERT INTO compliance VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (A[host]["uuid"], cid, cid + " " + name, st, "[{'framework': '800-53', 'control': 'AC-17'}]", audit,
                   "Configure per benchmark.", "", "", "", "", ""))
    for h, a in A.items():
        if "Windows" in a["os"]:
            audit = "CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_MS.audit" if "Server" in a["os"] else "CIS_Microsoft_Windows_10_Enterprise_v2.0.0_L1.audit"
            for cid, nm in WIN_FAIL:
                st = "FAILED" if (a["seg"] == "CORP" or h in ("sql01", "files01")) else "PASSED"
                if h.startswith("dc") and "LAPS" in nm:
                    st = "PASSED"
                comp(h, cid, nm, st, audit)
            for cid, nm in WIN_PASS:
                comp(h, cid, nm, "PASSED", audit)
        elif a["seg"] in ("APP", "DMZ"):
            for cid, nm in LNX_FAIL:
                st = "FAILED" if h in ("app01", "app02", "app03", "payments-db", "web03", "web01") else "PASSED"
                comp(h, cid, nm, st, "CIS_Red_Hat_EL8_Server_v2.0.0_L1.audit")
            for cid, nm in LNX_PASS:
                comp(h, cid, nm, "PASSED", "CIS_Red_Hat_EL8_Server_v2.0.0_L1.audit")

    # ---- epss ----
    for cve, e in [("CVE-2021-44228", .975), ("CVE-2022-26134", .974), ("CVE-2017-0144", .975), ("CVE-2021-34527", .966),
                   ("CVE-2021-36934", .41), ("CVE-2020-1472", .976), ("CVE-2021-42278", .92), ("CVE-2021-4034", .87),
                   ("CVE-2022-0847", .64), ("CVE-2019-0708", .975), ("CVE-2023-27898", .07), ("CVE-2016-2183", .02)]:
        c.execute("INSERT INTO epss VALUES(?,?,?)", (cve, str(e), str(e)))

    # uncredentialed blind hosts in CORP
    vuln("ws020", "110723", 0)

    # ================= regression rows: realistic plugins that must NOT create steps =================
    plugin("139487", "KB4565351: Windows 10 Version 1903 and Windows 10 Version 1909 August 2020 Security Update", "Windows : Microsoft Bulletins",
           "The remote Windows host is missing security update 4565351. It is affected by multiple vulnerabilities: - An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller (CVE-2020-1472) - A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory.",
           "Critical", "CVE-2020-1472,CVE-2020-1380", "CISA-KNOWN-EXPLOITED:2020/09/18")
    vuln("ws016", "139487", 445)
    plugin("170000", "Adobe Acrobat Reader < 23.001 Multiple Vulnerabilities (APSB23-01)", "Windows",
           "The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities, including arbitrary code execution.", "Critical")
    vuln("ws017", "170000", 0)
    plugin("187201", "OpenSSH < 9.6 Multiple Vulnerabilities", "Misc.",
           "The version of OpenSSH installed on the remote host is prior to 9.6. It is affected by multiple vulnerabilities, including remote code execution via ssh-agent (CVE-2023-38408).", "Critical", "CVE-2023-38408")
    vuln("lab02", "187201", 22)
    plugin("190001", "PHP 8.1.x < 8.1.27 Multiple Vulnerabilities", "CGI abuses",
           "The version of PHP running on the remote web server is affected by multiple vulnerabilities, including a deserialization flaw that can lead to a denial of service.", "High")
    vuln("app06", "190001", 443)
    plugin("10399", "SMB Use Domain SID to Enumerate Users", "Windows", "Domain users", "Info")
    vuln("ws018", "10399", 445, output="  - Administrator (id 500)\n  - krbtgt (id 502)\n  - jdoe (id 1104)")
    plugin("190002", "WordPress Plugin XYZ < 2.0 Privilege Escalation", "CGI abuses",
           "A subscriber-level authenticated user can escalate privileges to WordPress administrator.", "Medium")
    vuln("app08", "190002", 443)
    plugin("190003", "Apache Tomcat 9.0.x < 9.0.80 Multiple Vulnerabilities", "Web Servers",
           "Affected by multiple vulnerabilities such as system information disclosure and remote code execution in the default servlet if PUT enabled.", "High")
    vuln("lab03", "190003", 8080)
    comp("app07", "1.3.1", "Ensure sudo is installed", "FAILED", "CIS_RHEL8.audit")
    comp("ws019", "2.3.8.1", "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'", "FAILED", "x")
    comp("backup01", "18.4.6", "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests' is set to 'Enabled'", "FAILED", "x")
    comp("app07", "3.4.1", "Ensure firewall logging is enabled", "FAILED", "x")

    # ================= regression rows: signals that MUST create steps =================
    plugin("100634", "Redis Server Unprotected by Password Authentication", "Databases",
           "The Redis server running on the remote host is not protected by password authentication. A remote, unauthenticated attacker can read and write data.", "Critical")
    vuln("app04", "100634", 6379)
    plugin("200001", "Active Directory Kerberoastable Service Accounts", "Windows",
           "Service accounts with SPNs and weak encryption can be requested and cracked offline by any domain user.", "High")
    vuln("dc02", "200001", 88)
    asset("vpn01", "52.10.20.30", "Ubuntu 22.04", 6, "EDGE")
    vuln("vpn01", "10267", 22); vuln("vpn01", "10107", 443); vuln("vpn01", "156014", 443, vpr="9.8")
    passwd("vpn01", [("svc_deploy", "/home/svc_deploy", "/bin/bash", 1001)])
    comp("vpn01", "5.3.4", "Ensure users must provide password for privilege escalation", "FAILED", "CIS_Ubuntu.audit")
    comp("app04", "6.2.1", "Ensure password fields are not empty", "FAILED", "CIS_RHEL8.audit")
    for h in ("dc01", "dc02"):
        vuln(h, "22964", 88, output="Kerberos"); vuln(h, "22964", 389, output="LDAP")
    c.commit()
    n = (c.execute("select count(*) from assets").fetchone()[0], c.execute("select count(*) from vulns").fetchone()[0],
         c.execute("select count(*) from compliance").fetchone()[0])
    c.close()
    return n


if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "ap_full.db"
    print(p, "assets/vulns/compliance:", build(p))
