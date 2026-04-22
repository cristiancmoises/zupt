Name:           zupt-gui
Version:        1.0.0
Release:        1%{?dist}
Summary:        Zupt GUI — Post-Quantum Backup Utility
License:        MIT
URL:            https://github.com/cristiancmoises/zupt
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.9
Requires:       python3-pyside6
Requires:       zupt >= 2.1.6

%description
Cross-platform graphical interface for the zupt backup compression
utility with post-quantum hybrid encryption (ML-KEM-768 + X25519),
hardware-adaptive codecs, block-level deduplication, and full-disk
backup/restore support.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/zupt-gui
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/256x256/apps

install -m 755 src/zupt_gui.py %{buildroot}%{_datadir}/zupt-gui/zupt_gui.py
install -m 644 packaging/zupt-gui.desktop %{buildroot}%{_datadir}/applications/

cat > %{buildroot}%{_bindir}/zupt-gui << 'EOF'
#!/bin/sh
exec python3 %{_datadir}/zupt-gui/zupt_gui.py "$@"
EOF
chmod 755 %{buildroot}%{_bindir}/zupt-gui

%files
%license LICENSE
%{_bindir}/zupt-gui
%{_datadir}/zupt-gui/
%{_datadir}/applications/zupt-gui.desktop

%changelog
* Mon Apr 21 2026 Cristian Cezar Moises - 1.0.0-1
- Initial release
