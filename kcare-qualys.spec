Name:		kcare-qualys
Version:	0.1.0
Release:	1%{?dist}
Summary:	The script marks vulnerabilities detected by Qualys, but patched by KernelCare as exceptions

Group:		Applications/System
License:	Apache License v2.0
URL:		http://www.kernelcare.com
Source0:	%{name}-%{version}.tar.gz

BuildArch:   noarch

BuildRequires:	python-poery

%description
The script marks vulnerabilities detected by Qualys, but patched by KernelCare as exceptions

%prep
%setup -q %{name}-%{version}

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

%files
%doc README.md LICENSE
/usr/local/etc/kcare-qualys.conf.tempate
/usr/bin/kcare-qualys
%{python_sitelib}/kcare_qualys.py*

