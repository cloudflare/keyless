# curl -L -o keyless-master.tar.gz https://api.github.com/repos/cloudflare/keyless/tarball
# 6227356a4a0dc608d6c3b21b3a7218d44c28a105

%define keyless_home /var/lib/keyless
%define keyless_user_group keyless

Name:           keyless
Version:        0.0.1
Release:        5%{?dist}
Summary:        Keyserver for Keyless SSL.

Group:          Proxy Server
License:        BSD
URL:            https://github.com/cloudflare/keyless
Source0:        https://api.github.com/repos/cloudflare/keyless/tarball/keyless-master.tar.gz
Patch0:		      revision.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libuv-devel, openssl-devel
Requires: 	    libuv

%description
Use Keyserver to run a webserver without private keys. This is usefull for centralized private key control.

%pre
/usr/sbin/groupadd -r %{keyless_user_group} &>/dev/null ||:
/usr/sbin/useradd -g %{keyless_user_group} -s /bin/false -r -c "user for %{keyless_user_group}" -m -d %{keyless_home} %{keyless_user_group} &>/dev/null ||:

%prep
%setup -q -n keyless-master/keyserver
%patch0 -p0

%build
make

%install
rm -rf %{buildroot}
%{__install} -p -D -m 0755 o/kssl_server %{buildroot}%{_bindir}/kssl_server
%{__install} -p -D -m 0755 o/kssl_testclient %{buildroot}%{_bindir}/kssl_testclient
rm -rf o/*.o

%clean
rm -rf $RPM_BUILD_ROOT

%post
mkdir -p /var/log/keyless
chown %{keyless_user_group}:%{keyless_user_group} /var/log/keyless
mkdir -p %{keyless_home}
chown -R %{keyless_user_group}:%{keyless_user_group} %{keyless_home}

%files
%defattr(-,root,root,-)
%doc README ABOUT
%{_bindir}/kssl_server
%{_bindir}/kssl_testclient

%changelog
* Tue Apr 15 2014 Arnoud Vermeer <arnoud@tumblr.com> 0.0.1-5.tumblr
- Create a keyless user/group/home (a.vermeer@freshway.biz)
- Adding the latest upstream that has an unprivileged user option
  (a.vermeer@freshway.biz)

* Mon Apr 14 2014 Arnoud Vermeer <arnoud@tumblr.com> 0.0.1-4.tumblr
- Adding a patch for healthchecks (a.vermeer@freshway.biz)

* Wed Apr 09 2014 Arnoud Vermeer <arnoud@tumblr.com> 0.0.1-3.tumblr
- requires libuv to run (arnoud@tumblr.com)

* Wed Apr 09 2014 Arnoud Vermeer <arnoud@tumblr.com> 0.0.1-2.tumblr
- Working build (arnoud@tumblr.com)

* Wed Apr 09 2014 Arnoud Vermeer <arnoud@tumblr.com>
- new package built with tito

