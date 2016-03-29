Name:       pkgmgr-tool
Summary:    Packager Manager Tool package
Version:    0.1.0
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest

Requires:  unzip

BuildRequires:  cmake
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(xdgmime)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  fdupes

%description
Packager Manager Tool for packaging

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .

%__make %{?_smp_mflags}

%install
%make_install
mkdir -p %{buildroot}%{_sysconfdir}/opt/upgrade

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%fdupes %{buildroot}

%post
/sbin/ldconfig

# Update mime database to support package mime types
update-mime-database %{_datadir}/mime
chsmack -a '*' %{TZ_SYS_RW_PACKAGES}

%posttrans
if [ $1 == 1 ]; then
  pkg_initdb
  install_preload_tpk
  if [ -f /tmp/.preload_install_error ]; then
    if [ ! -d /tmp/.postscript/error ]; then
      mkdir -p /tmp/.postscript/error
    fi
    echo "preload install failed" > /tmp/.postscript/error/%{name}_error
  fi
fi

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%dir %{_sysconfdir}/opt/upgrade
%{_sysconfdir}/opt/upgrade/pkgmgr.patch.sh
%{_bindir}/pkgcmd
%attr(06755,root,root) %{_bindir}/pkg_initdb
%attr(755,root,root) %{_sysconfdir}/gumd/useradd.d/10_package-manager-add.post
%{_bindir}/pkg_getsize
%{_bindir}/pkg_clearcache
%{_bindir}/pkginfo
%attr(0755,root,root) %{_bindir}/install_preload_tpk
%{_datadir}/mime/packages/mime.wac.xml
%{_datadir}/mime/packages/mime.tpk.xml
%attr(0700,root,root) /etc/package-manager/pkgmgr-unzip-tpk.sh
%attr(0700,root,root) /etc/package-manager/pkgmgr-create-delta.sh
/usr/share/license/%{name}
