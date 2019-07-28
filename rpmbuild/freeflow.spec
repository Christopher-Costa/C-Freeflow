Name:           freeflow
Version:        1.0
Release:        1%{?dist}
Summary:        Freeflow netflow collection for Splunk

License:        GPLv3+
URL:            https://github.com/Christopher-Costa/C-Freeflow
Source0:        freeflow-1.0.tar.gz
BuildRequires:  openssl-devel

Requires(post): info
Requires(preun): info

%define _prefix /opt/freeflow
%define _libdir /usr/lib

%description
Freeflow netflow collection for Splunk

%prep
%setup

%build
make PREFIX=%{_prefix}

%install
mkdir -p %{?buildroot}/usr/lib/systemd/system
make PREFIX=%{_prefix} DESTDIR=%{?buildroot} install

%clean
rm -rf %{buildroot}

%files
%{_prefix}/bin/freeflow
%{_prefix}/etc/freeflow.cfg
%{_libdir}/systemd/system/freeflow.service
%dir %{_prefix}/var/log
