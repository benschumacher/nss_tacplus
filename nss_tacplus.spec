#
# spec file for package 'nss_tacplus' (version '1.0.0')
#
# The following software is released as specified below.
# This spec file is released to the public domain.
# (c) Lincom Software Team

# Basic Information
Name: nss_tacplus
Version: 1.0.0
Release: 1%{?dist}
Summary: NSS Tacacs+ module
Group: System
License: GPL
URL: https://github.com/benschumacher/nss_tacplus

# Packager Information
Packager: NRB

# Build Information
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# Source Information
Source0: 1.0.0.tar.gz

# Dependency Information
BuildRequires: gcc 
Requires: pam_tacplus-devel

%description
NSS Tacacs+ module based on code produced by Ben Schumacher

%prep
%setup -q -a 0
touch tacplus.conf

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/
mkdir -p $RPM_BUILD_ROOT/%{_lib}/

install -m 755 libnss_tacplus.so.2 \
               $RPM_BUILD_ROOT/%{_lib}/

install -m 644 tacplus.conf $RPM_BUILD_ROOT/etc/tacplus.conf

chmod 755 $RPM_BUILD_ROOT/%{_lib}/*.so*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /%{_lib}/*.so*
%attr(0644,root,root) %config(noreplace) /etc/tacplus.conf
%doc README.md

#%changelog

