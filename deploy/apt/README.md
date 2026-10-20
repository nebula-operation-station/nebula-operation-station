# APT repository

Release packages are built by GoReleaser (`nebula-operation-station_<version>_<arch>.deb`, unsigned) and published as a static APT repository that the maintainer signs offline with the release's OpenPGP signing subkey (ADR 0001: no signing key in CI).

Build the repository on the offline signing machine:

```
mkdir -p repo/pool/main repo/dists/stable/main/binary-amd64 repo/dists/stable/main/binary-arm64
cp nebula-operation-station_*_*.deb repo/pool/main/
cd repo
for a in amd64 arm64; do
  apt-ftparchive --arch "$a" packages pool > "dists/stable/main/binary-$a/Packages"
  gzip -k9 "dists/stable/main/binary-$a/Packages"
done
apt-ftparchive -o APT::FTPArchive::Release::Origin=nebula-operation-station \
  -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" -o APT::FTPArchive::Release::Components=main \
  release dists/stable > dists/stable/Release
gpg --local-user RELEASE-SUBKEY --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --local-user RELEASE-SUBKEY -abs -o dists/stable/Release.gpg dists/stable/Release
```

Users install with the key in a keyring file of its own (never `apt-key`):

```
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 nebula-archive-keyring.gpg /etc/apt/keyrings/
echo "deb [signed-by=/etc/apt/keyrings/nebula-archive-keyring.gpg] https://apt.example.org stable main" | sudo tee /etc/apt/sources.list.d/nebula.list
sudo apt update && sudo apt install nebula-operation-station
sudo /usr/share/nebula/deploy/install.sh --from-package --admin-users alice --rp-id nebula.lab.example.org
```

An upgrade (`apt upgrade`) installs the new version but never restarts the services, because the pre-upgrade backup needs the admin's own `sudo`: run `sudo nebula backup && sudo systemctl restart nebula-executor nebula-server`, then `nebula unlock` (handbook, section 13).
