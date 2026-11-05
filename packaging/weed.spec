# The RPM of weed, of a release built beforehand (release/dist.sh builds weed with
# cgo, on EL10), for EL10 and later: release/rpm.sh builds it.
#
#     rpmbuild -bb packaging/weed.spec --define "_sourcedir $PWD/packaging" \
#         --define "weed_version 1.2.0" --define "weed_dir weed-v1.2.0-linux-amd64"
#
# weed_dir holds weed, README.txt, CHANGELOG.md, LICENSE and guide/, as the archive
# of a release; weed_release, if defined, is the Release (default 1). The RPM's
# architecture is weed's (rpmbuild --target).

# weed as built, as in the archive of the release: not stripped, nor changed otherwise
%global debug_package %{nil}
%global __os_install_post %{nil}
# The changelog is CHANGELOG.md, in the documentation
%global source_date_epoch_from_changelog 0

Name:           weed
Version:        %{weed_version}
Release:        %{!?weed_release:1}%{?weed_release}%{?dist}
Summary:        WebDAV server that serves the files of each user as their Unix account
License:        MIT
URL:            https://github.com/labkode/weed
Source1:        weed.service
Source2:        weed.sysusers
Source3:        weed.sysctl
Source4:        weed.toml
Source5:        weed.logrotate
ExclusiveArch:  x86_64 aarch64
BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
weed serves files over WebDAV and HTTP, to clients authenticated with X.509
certificates, WLCG tokens or passwords, and makes WLCG third-party copies. Each
request accesses the files as the Unix account of its user, from a worker process
that runs as that account, confined with Landlock and seccomp. weed itself runs as
the account weed, without root.

%prep
cp -a %{weed_dir}/. .

%build

%install
install -D -m 0755 weed %{buildroot}%{_bindir}/weed
install -D -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/weed.service
install -D -m 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/weed.conf
install -D -m 0644 %{SOURCE3} %{buildroot}%{_sysctldir}/60-weed.conf
install -D -m 0640 %{SOURCE4} %{buildroot}%{_sysconfdir}/weed/weed.toml
install -m 0640 /dev/null %{buildroot}%{_sysconfdir}/weed/.htpasswd
install -m 0640 /dev/null %{buildroot}%{_sysconfdir}/weed/.app-tokens
install -D -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/logrotate.d/weed
install -d -m 0755 %{buildroot}/srv/weed

%pre
getent group weed >/dev/null || groupadd -r weed
getent passwd weed >/dev/null ||
    useradd -r -g weed -d /var/lib/weed -s /usr/sbin/nologin -c "weed WebDAV server" weed
exit 0

%post
%systemd_post weed.service
%sysctl_apply 60-weed.conf
# A unit in /etc/systemd/system, as the guide once wrote, hides this one
if [ -f /etc/systemd/system/weed.service ]; then
    echo "weed: warning: /etc/systemd/system/weed.service hides the unit of this RPM, %{_unitdir}/weed.service: remove it, and make your changes a drop-in (systemctl edit weed)" >&2
fi
# An upgrade does not restart weed: this version checks now the configuration that
# it will start with, as root and as the account weed, rather than at the restart
if [ "$1" -ge 2 ] && [ -f %{_sysconfdir}/weed/weed.toml ]; then
    if out=$(%{_bindir}/weed check -config %{_sysconfdir}/weed/weed.toml 2>&1); then
        echo "weed %{version}: $out"
        if systemctl -q is-active weed.service 2>/dev/null; then
            echo "weed: the running weed is the version before, until systemctl restart weed"
        fi
    else
        echo "weed: warning: weed %{version} would not start with %{_sysconfdir}/weed/weed.toml, which the running weed goes on with until it restarts:" >&2
        printf '%%s\n' "$out" >&2
    fi
fi

%preun
%systemd_preun weed.service

%postun
# Not restarted on upgrade (see Upgrading in the guide): %%post checked the
# configuration with the new version
%systemd_postun weed.service

%files
%license LICENSE
%doc README.txt CHANGELOG.md guide
%{_bindir}/weed
%{_unitdir}/weed.service
%{_sysusersdir}/weed.conf
%{_sysctldir}/60-weed.conf
%dir %attr(0750,root,weed) %{_sysconfdir}/weed
%config(noreplace) %attr(0640,root,weed) %{_sysconfdir}/weed/weed.toml
%config(noreplace) %attr(0640,root,weed) %{_sysconfdir}/weed/.htpasswd
%config(noreplace) %attr(0640,root,weed) %{_sysconfdir}/weed/.app-tokens
%config(noreplace) %{_sysconfdir}/logrotate.d/weed
%dir /srv/weed
