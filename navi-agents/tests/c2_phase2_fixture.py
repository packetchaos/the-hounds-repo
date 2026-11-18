"""A small navi.db for the Amarok Phase 2 tests and walks (build 486): the mixed-distro hosts the fake navi answers on
10.9.1.x (see tests/c2_fakenavi.py), one Tenable finding per distro carrying the SAME CVE (CVE-2024-1111), in the
plugin-output formats of tests/fixtures/c2_plugin_output/. navi's real `plugins` table names the title `name` and the
family `family` — this fixture uses those columns on purpose (linux §5 data issue).

    python3 tests/c2_phase2_fixture.py <path/to/navi.db>    # build it (overwrites)
"""
import os
import sqlite3
import sys

CVE = "CVE-2024-1111"
CVE7 = "CVE-2019-0001"          # verify round: the CentOS hosts' real-sample findings (B / C / D) — a separate CVE so
                                # every CVE-2024-1111 selection above is unchanged

U20 = ("\n  - Installed package : libssl1.1_1.1.1f-1ubuntu2.16\n  - Fixed package     : libssl1.1_1.1.1f-1ubuntu2.20\n\n"
       "  - Installed package : openssl_1.1.1f-1ubuntu2.16\n  - Fixed package     : openssl_1.1.1f-1ubuntu2.20\n")
U22 = ("\n  - Installed package : libssl3_3.0.2-0ubuntu1.10\n  - Fixed package     : libssl3_3.0.2-0ubuntu1.12\n\n"
       "  - Installed package : openssl_3.0.2-0ubuntu1.10\n  - Fixed package     : openssl_3.0.2-0ubuntu1.12\n")
DEB11 = ("\nRemote package installed : libssl1.1_1.1.1n-0+deb11u4\nShould be                : libssl1.1_1.1.1n-0+deb11u5\n"
         "Remote package installed : openssl_1.1.1n-0+deb11u4\nShould be                : openssl_1.1.1n-0+deb11u5\n")
RHEL8K = "\n  Remote package installed : kernel-4.18.0-305.el8\n  Should be : kernel-4.18.0-513.el8\n"
ROCKY9 = ("\n  Remote package installed : openssl-1:3.0.7-24.el9.x86_64\n  Should be                : openssl-1:3.0.7-25.el9\n\n"
          "  Remote package installed : openssl-libs-1:3.0.7-24.el9.x86_64\n  Should be                : openssl-libs-1:3.0.7-25.el9\n")
AL2 = "\n  Remote package installed : openssl-1.0.2k-24.amzn2.0.6.x86_64\n  Should be                : openssl-1.0.2k-24.amzn2.0.7\n"
AL2023 = "\n  Remote package installed : openssl-1:3.0.8-1.amzn2023.0.9.x86_64\n  Should be                : openssl-1:3.0.8-1.amzn2023.0.11\n"
AL1 = "\n  Remote package installed : openssl-1.0.2k-16.159.amzn1.x86_64\n  Should be                : openssl-1.0.2k-16.161.amzn1\n"
SLES = "\n  Remote package installed : openssl-1_1-1.1.1l-150400.7.25.1\n  Should be                : openssl-1_1-1.1.1l-150400.7.28.1\n"
UKERN = "\nRunning Kernel level of 5.4.0-150-generic does not meet the minimum fixed level of 5.4.0-170-generic for this advisory.\n"
FEDORA = "\n  Remote package installed : openssl-3.1.1-4.fc39\n  Should be                : openssl-3.1.1-5.fc39\n"

PLUGINS = [  # plugin_id, name, family, solution
    ("300001", "Ubuntu 20.04 LTS : OpenSSL vulnerabilities (USN-6188-1)", "Ubuntu Local Security Checks",
     "Update the affected libssl1.1 and / or openssl packages."),
    ("300002", "Ubuntu 22.04 LTS : OpenSSL vulnerabilities (USN-6188-1)", "Ubuntu Local Security Checks",
     "Update the affected libssl3 and / or openssl packages."),
    ("300003", "Debian dla-3530 : openssl - security update", "Debian Local Security Checks",
     "Upgrade the libssl1.1 and openssl packages."),
    ("300004", "RHEL 8 : kernel (RHSA-2023:7077)", "Red Hat Local Security Checks", "Update the affected packages."),
    ("300005", "Rocky Linux 9 : openssl (RLSA-2024:0310)", "Rocky Linux Local Security Checks",
     "Update the affected openssl and openssl-libs packages."),
    ("300006", "Amazon Linux 2 : openssl (ALAS-2024-2400)", "Amazon Linux Local Security Checks",
     "Run 'yum update openssl' to update your system. Update the affected openssl package."),
    ("300007", "Amazon Linux 2023 : openssl (ALAS2023-2024-500)", "Amazon Linux Local Security Checks",
     "Run 'dnf update openssl' to update your system. Update the affected openssl package."),
    ("300008", "Amazon Linux AMI : openssl (ALAS-2024-1900)", "Amazon Linux Local Security Checks",
     "Run 'yum update openssl' to update your system. Update the affected openssl package."),
    ("300009", "SUSE SLES15 Security Update : openssl-1_1 (SUSE-SU-2024:0001-1)", "SuSE Local Security Checks",
     "Update the affected openssl-1_1 package."),
    ("300010", "Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-6600-1)", "Ubuntu Local Security Checks",
     "Update the affected kernel package."),
    ("300011", "Fedora 39 : openssl (FEDORA-2024-1)", "Fedora Local Security Checks", "Update the affected openssl package."),
]

HOSTS = [  # ip, hostname, navi.db OS string, acr, [(plugin, output)]
    ("10.9.1.1", "u20-web01", "Linux Kernel 5.4 on Ubuntu 20.04", "5", [("300001", U20)]),
    ("10.9.1.2", "u22-web02", "Linux Kernel 5.15 on Ubuntu 22.04", "5", [("300002", U22)]),
    ("10.9.1.3", "deb11-db03", "Linux Kernel 5.10 on Debian 11", "6", [("300003", DEB11)]),
    ("10.9.1.4", "rhel8-app04", "Red Hat Enterprise Linux 8.6", "6", [("300004", RHEL8K)]),
    ("10.9.1.5", "rocky9-app05", "Rocky Linux 9.3", "6", [("300005", ROCKY9)]),
    ("10.9.1.6", "al2-batch06", "Amazon Linux 2", "4", [("300006", AL2)]),
    ("10.9.1.7", "al2023-api07", "Amazon Linux 2023", "4", [("300007", AL2023)]),
    ("10.9.1.8", "al1-legacy08", "Amazon Linux AMI 2018.03", "4", [("300008", AL1)]),
    ("10.9.1.9", "sles15-erp09", "SUSE Linux Enterprise Server 15", "10", [("300009", SLES)]),
    ("10.9.1.10", "u20-web10", "Linux", "5", [("300001", U20)]),
    ("10.9.1.11", "u20-web11", "Linux", "5", [("300001", U20)]),
    ("10.9.1.12", "u18-old12", "Linux Kernel 4.15 on Ubuntu 18.04", "5", [("300001", U20)]),
    ("10.9.1.13", "u22-web13", "Linux Kernel 5.15 on Ubuntu 22.04", "5", [("300002", U22)]),
    ("10.9.1.14", "u20-web14", "Linux", "5", [("300001", U20)]),
    ("10.9.1.15", "u20-web15", "Linux", "5", [("300001", U20)]),
    ("10.9.1.16", "fcos-edge16", "Fedora CoreOS 39", "5", [("300011", FEDORA)]),
    ("10.9.1.17", "u20-web17", "Linux", "5", [("300001", U20)]),
    ("10.9.1.18", "u20-k18", "Linux Kernel 5.4 on Ubuntu 20.04", "5", [("300010", UKERN)]),
    ("10.9.1.26", "u20-lockmoved26", "Linux Kernel 5.4 on Ubuntu 20.04", "5", [("300001", U20)]),   # 487 fix round
]


def _real(fid):
    """(plugin_id, name, family, solution, output) of a real-sample fixture (output + Solution verbatim)."""
    import json
    fx = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "c2_plugin_output",
                                     fid + ".json"), encoding="utf-8"))
    return fx["plugin_id"], fx["plugin_name"], fx["plugin_family"], fx["solution"], fx["output"]


GLIBC8 = ("\nRemote package installed : glibc-2.28-164.el8\nShould be                : glibc-2.28-189.el8\n\n"
          "Remote package installed : glibc-common-2.28-164.el8\nShould be                : glibc-common-2.28-189.el8\n")
REAL7 = {"B": "real_B_centos7_networkmanager_case", "C": "real_C_centos7_kernel", "D": "real_D_centos7_rsyslog_zstream",
         "F": "real_F_centos8_openssl"}
HOSTS7 = [  # ip, hostname, navi.db OS string, acr, real sample
    ("10.9.1.19", "c7-nm19", "CentOS Linux 7.6.1810", "5", "B"),
    ("10.9.1.20", "c7-kern20", "CentOS Linux 7.9.2009", "5", "C"),
    ("10.9.1.21", "c7-deadmirror21", "CentOS Linux 7.7.1908", "5", "D"),
    ("10.9.1.22", "c7-yumcron22", "CentOS Linux 7.7.1908", "5", "D"),
    ("10.9.1.23", "c7-kernondisk23", "CentOS Linux 7.6.1810", "5", "C"),

    ("10.9.1.25", "c7-lockafter25", "CentOS Linux 7.7.1908", "5", "D"),     # build 487 (owner decision 7b)
]


def build(path):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT);
    CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, output TEXT, cves TEXT,
                       state TEXT, severity TEXT);
    CREATE TABLE plugins(plugin_id TEXT, name TEXT, family TEXT, solution TEXT, description TEXT, synopsis TEXT, cves TEXT);
    CREATE TABLE ssh(username TEXT, password TEXT, key_file TEXT);
    INSERT INTO ssh VALUES('svc','','/k');
    """)
    names = {}
    for pid, name, fam, sol in PLUGINS:
        con.execute("INSERT INTO plugins VALUES(?,?,?,?,?,?,?)", (pid, name, fam, sol, "The remote host is missing a security update.",
                                                                  "The remote host is missing a security update.", CVE))
        names[pid] = (name, fam)
    for k, fid in REAL7.items():
        pid, name, fam, sol, _out = _real(fid)
        con.execute("INSERT INTO plugins VALUES(?,?,?,?,?,?,?)", (pid, name, fam, sol, "The remote host is missing a security update.",
                                                                  "The remote host is missing a security update.", CVE7))
        names[pid] = (name, fam)
    for ip, hn, os_, acr, smp in HOSTS7:
        pid, name, fam, sol, out = _real(REAL7[smp])
        u = "u-" + ip.replace(".", "-")
        con.execute("INSERT INTO assets VALUES(?,?,?,?,?)", (u, hn, ip, os_, acr))
        con.execute("INSERT INTO vulns VALUES(?,?,?,?,?,?,?,?)", (u, pid, name, fam, out, CVE7, "OPEN", "high"))
    # build 487 fix round: a SYNTHETIC CentOS 8 glibc finding (glibc is on dnf needs-restarting's reboot list)
    con.execute("INSERT INTO plugins VALUES(?,?,?,?,?,?,?)", ("190001", "CentOS 8 : glibc (synthetic test finding)",
                                                              "CentOS Local Security Checks", "Update the affected packages.",
                                                              "synthetic", "synthetic", CVE7))
    con.execute("INSERT INTO assets VALUES(?,?,?,?,?)", ("u-10-9-1-24", "c8-nodnfutils24", "10.9.1.24", "CentOS Linux 8", "5"))
    con.execute("INSERT INTO vulns VALUES(?,?,?,?,?,?,?,?)", ("u-10-9-1-24", "190001", "CentOS 8 : glibc (synthetic test finding)",
                                                             "CentOS Local Security Checks", GLIBC8, CVE7, "OPEN", "high"))
    for ip, hn, os_, acr, finds in HOSTS:
        u = "u-" + ip.replace(".", "-")
        con.execute("INSERT INTO assets VALUES(?,?,?,?,?)", (u, hn, ip, os_, acr))
        for pid, out in finds:
            con.execute("INSERT INTO vulns VALUES(?,?,?,?,?,?,?,?)", (u, pid, names[pid][0], names[pid][1], out, CVE, "OPEN", "high"))
    con.commit()
    con.close()
    return path


if __name__ == "__main__":
    print(build(sys.argv[1]))
