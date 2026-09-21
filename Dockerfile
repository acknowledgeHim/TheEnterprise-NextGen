# TheEnterprise-NextGen - single image bundling the Flask/Celery app plus the external
# pentest tool roster install.sh used to provision onto a bare-metal Kali box.
#
# NOT build-tested end-to-end in the environment this was written in (no Docker daemon access
# there - see the Phase 5 plan doc). Several of the external tools cloned below are unmaintained
# 2015-2019-era projects; individual RUN steps may need adjusting against real build output.
#
# Base is plain Debian (not Kali) - install.sh assumed a Kali host and skipped packages Kali
# ships by default (nmap, whois, dnsutils, etc, added explicitly below), and Kali-only steps
# (apt-key'd Kali archive key, `amass`/`crackmapexec` from Kali's repos) are replaced with
# Debian-compatible equivalents.
#
# No Python 2.7 here - DataSploit (the one genuinely Python-2-only tool in the original roster)
# is a documented gap rather than sourcing an EOL interpreter for one abandoned-upstream tool
# (last commit ~2018, no Python 3 port). See the Phase 5 plan doc.
#
# RabbitMQ/Redis are NOT installed in this image - they run as separate, official-image
# services in docker-compose.yml. That's infrastructure, not a "pentest tool," so using the
# well-tested upstream images is the right call independent of the "one image for tools"
# decision this Dockerfile otherwise follows.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PENTESTDIR=/pentest \
    GOPATH=/pentest/golang \
    GOBIN=/pentest/golang/bin
ENV PATH="${GOBIN}:${PATH}"

WORKDIR /pentest

# ---------------------------------------------------------------------------
# Base system + the recon/scan utilities a Kali host has by default but a
# plain Debian base doesn't (install.sh never installs these explicitly).
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg git unzip p7zip-full sudo openssl libcap2-bin \
        nmap whois dnsutils netcat-openbsd iputils-ping smbclient \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# install.sh: LDAP/build toolchain (line 53) - python2.7-dev dropped, no
# Python 2 in this image (see header comment).
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential python3-dev libldap2-dev libsasl2-dev slapd ldap-utils \
        lcov valgrind \
    && rm -rf /var/lib/apt/lists/*

# install.sh: EyeWitness deps (line 83)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# install.sh: masscan build deps (line 95) + thc-ipv6 build deps (line 132)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libpcap-dev libssl-dev libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

# install.sh: Node.js (lines 158-160) - current NodeSource LTS setup instead of
# the dead setup_8.x script.
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# install.sh: PowerShell (lines 170-174) - Microsoft dropped the Stretch apt repo this
# script used; current method for Debian is a direct .deb download. Bump the version
# below if this URL 404s by the time this is actually built.
RUN curl -fsSL -o /tmp/powershell.deb \
        https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell_7.4.6-1.deb_amd64.deb \
    && apt-get update && apt-get install -y /tmp/powershell.deb && rm -f /tmp/powershell.deb \
    && rm -rf /var/lib/apt/lists/*

# install.sh: Golang (line 213) - apt's golang-go on bookworm is new enough for the
# `go install pkg@version` syntax used below (the `go get`-for-binaries this script
# originally used was removed in Go 1.18+).
RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$GOPATH" "$GOBIN"

# install.sh: Mono (lines 272-273)
RUN apt-get update && apt-get install -y --no-install-recommends mono-devel mono-complete \
    && rm -rf /var/lib/apt/lists/*

# install.sh: Python3 toolchain (lines 335-337) - python3-venv skipped (no venv here, the
# container's own interpreter is already isolated); python3-pip needed by every pip3 install
# below, including the very next step.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-pip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# install.sh: CrackMapExec (line 315) - not in Debian's repos; pip install instead of
# the Kali apt package. If this fails, the maintained fork is NetExec (pip3 install netexec).
RUN pip3 install --break-system-packages --no-cache-dir crackmapexec

# install.sh: PhantomJS build deps (lines 471-472)
RUN apt-get update && apt-get install -y --no-install-recommends \
        chrpath libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev \
    && rm -rf /var/lib/apt/lists/*

# install.sh: final utility tools (lines 482-483) - p7zip-full already installed above.
RUN apt-get update && apt-get install -y --no-install-recommends nikto \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# External tool installs (install.sh lines ~55-475). Typos/bugs in the
# original script are fixed here rather than reproduced - see the Phase 5
# plan doc's Findings section for what each one was.
# ---------------------------------------------------------------------------

# windapsearch (typo fix: original script's $PENTEST_DIR was unset)
RUN git clone --depth 1 https://github.com/ropnop/windapsearch.git $PENTESTDIR/windapsearch

# DataSploit intentionally NOT cloned - Python 2 only, abandoned upstream since ~2018,
# would not run without a Python 2.7 interpreter this image doesn't carry. See header.

# ZAP (old pinned release, matches install.sh - a newer ZAP is a separate upgrade)
RUN mkdir -p $PENTESTDIR/zap && cd $PENTESTDIR/zap \
    && wget -q https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Linux.tar.gz \
    && tar -xzf ZAP_2.7.0_Linux.tar.gz --strip-components=1 \
    && rm -f ZAP_2.7.0_Linux.tar.gz \
    && chmod +x *.sh

# EyeWitness (own installer - apt/pip heavy, most likely single point of build failure
# in this whole file given its age)
RUN git clone --depth 1 https://github.com/ChrisTruncer/EyeWitness.git $PENTESTDIR/eyewitness \
    && $PENTESTDIR/eyewitness/setup/setup.sh || true

# Responder
RUN git clone --depth 1 https://github.com/lgandx/Responder.git $PENTESTDIR/responder

# MassScan (typo fix: original script's clone/build dir name mismatch, "massscan" vs "masscan")
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan $PENTESTDIR/masscan \
    && cd $PENTESTDIR/masscan && make -j"$(nproc)"

# SMBetray (own installer)
RUN git clone --depth 1 https://github.com/QuickBreach/SMBetray.git $PENTESTDIR/smbetray \
    && cd $PENTESTDIR/smbetray && (./install.sh || true)

# Impacket intentionally NOT cloned/setup.py-installed - already a proper pip dependency
# (impacket==0.13.1) in requirements.txt; installing an old git checkout on top would
# just conflict with that modern, maintained version.

# Pywerview
RUN git clone --depth 1 https://github.com/the-useless-one/pywerview $PENTESTDIR/pywerview

# FindFrontableDomains (own installer)
RUN git clone --depth 1 https://github.com/rvrsh3ll/FindFrontableDomains.git $PENTESTDIR/FindFrontableDomains \
    && cd $PENTESTDIR/FindFrontableDomains && (./setup.sh || true)

# thc-ipv6
RUN git clone --depth 1 https://github.com/vanhauser-thc/thc-ipv6.git $PENTESTDIR/thc-ipv6 \
    && cd $PENTESTDIR/thc-ipv6 && make all && make install

# pydhcp
RUN git clone --depth 1 https://github.com/tmeiczin/pydhcp.git $PENTESTDIR/pydhcp

# struts-pwn PoCs (this repo also vendors a copy of the 2018 one directly under
# tools/attack/web/struts/ - these are separate upstream reference copies)
RUN git clone --depth 1 https://github.com/mazen160/struts-pwn_CVE-2017-9805.git $PENTESTDIR/struts/struts_pwn_2017_9805 \
    && git clone --depth 1 https://github.com/mazen160/struts-pwn_CVE-2018-11776.git $PENTESTDIR/struts/struts_pwn_2018_11776

# scope_creep (bug fix: original script's `cd scope_creep` assumed cwd, used absolute path here)
RUN git clone --depth 1 https://github.com/fkasler/scope_creep.git $PENTESTDIR/scope_creep \
    && cd $PENTESTDIR/scope_creep && npm install

# PowerMeta / MailSniper (PowerShell)
RUN git clone --depth 1 https://github.com/dafthack/PowerMeta.git $PENTESTDIR/PowerMeta \
    && git clone --depth 1 https://github.com/dafthack/MailSniper.git $PENTESTDIR/MailSniper

# metagoofil
RUN git clone --depth 1 https://github.com/laramies/metagoofil.git $PENTESTDIR/metagoofil

# Go-based tools - modern `go install module@version` syntax (the `go get` this script
# originally used for binary installs was removed in Go 1.18+); also fixes two typos in
# the original script (Ruler's GOPATH dir was missing the sensepost org segment,
# blacksheepwall's cd used "tomsteel" instead of "tomsteele").
RUN go install github.com/sensepost/ruler@latest \
    && go install github.com/OJ/gobuster/v3@latest \
    && go install github.com/bettercap/bettercap@latest \
    && go install github.com/tomsteele/blacksheepwall@latest
# OWASP Amass moved orgs (github.com/OWASP/Amass -> github.com/owasp-amass/amass) and is
# now v4+ with a /v4 module path; verify against amass's current README if this 404s.
RUN go install -v github.com/owasp-amass/amass/v4/...@master || true

# PTF
RUN git clone --depth 1 https://github.com/trustedsec/ptf.git $PENTESTDIR/ptf

# DirSearch
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git $PENTESTDIR/dirsearch

# S3Scanner (bug fix: original script ran `pip install -r requirements.txt` without
# cd'ing into the clone dir first)
RUN git clone --depth 1 https://github.com/vysec/S3Scanner.git $PENTESTDIR/s3scanner \
    && cd $PENTESTDIR/s3scanner && pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Jexboss (same cd-before-pip-install bug fix)
RUN git clone --depth 1 https://github.com/joaomatosf/jexboss.git $PENTESTDIR/jexboss \
    && cd $PENTESTDIR/jexboss && pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Seth (same cd-before-pip-install bug fix)
RUN git clone --depth 1 https://github.com/SySS-Research/Seth.git $PENTESTDIR/seth \
    && cd $PENTESTDIR/seth && pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Sublist3r / SpiderFoot
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git $PENTESTDIR/sublist3r \
    && git clone --depth 1 https://github.com/smicallef/spiderfoot.git $PENTESTDIR/spiderfoot

# fuxploider
RUN git clone --depth 1 https://github.com/almandin/fuxploider.git $PENTESTDIR/fuxploider \
    && cd $PENTESTDIR/fuxploider && pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# XSStrike
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git $PENTESTDIR/xsstrike \
    && cd $PENTESTDIR/xsstrike && pip3 install --break-system-packages --no-cache-dir -r requirements.txt fuzzywuzzy

# scapy intentionally NOT installed from source here - already a proper pip dependency
# (scapy==2.7.0) in requirements.txt, same reasoning as Impacket above.

# Drupwn
RUN git clone --depth 1 https://github.com/immunIT/drupwn.git $PENTESTDIR/drupwn \
    && cd $PENTESTDIR/drupwn && pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# PhantomJS (long-discontinued upstream, kept only because install.sh shipped it -
# a modern replacement would be headless Chrome/Playwright, out of scope for a faithful port)
RUN wget -q -O /tmp/phantomjs.tar.bz2 \
        https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 \
    && tar -xjf /tmp/phantomjs.tar.bz2 -C /usr/local/share/ \
    && ln -s /usr/local/share/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs \
    && rm -f /tmp/phantomjs.tar.bz2

# nmap needs raw-socket capabilities; install.sh's answer was a passwordless-sudo visudo
# entry (meaningless in a container). setcap here, and the compose file also grants
# NET_RAW/NET_ADMIN at the container level as defense in depth.
RUN setcap cap_net_raw,cap_net_admin+eip "$(which nmap)"

# ---------------------------------------------------------------------------
# The app itself
# ---------------------------------------------------------------------------
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x docker-entrypoint.sh

EXPOSE 1820

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["python3", "enterprise-flask.py"]
