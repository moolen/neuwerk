# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"

  config.vm.define "proxy1" do |proxy1|
  end

  config.vm.define "proxy2" do |proxy2|
  end

  config.vm.define "proxy3" do |proxy2|
  end


  config.vm.network "public_network", bridge: "wlp61s0"
  config.vm.network "private_network", type: "dhcp"

  # Enable provisioning with a shell script. Additional provisioners such as
  # Ansible, Chef, Docker, Puppet and Salt are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt install -y make gcc clang llvm
    VERSION="1.20.2"
    ARCH="amd64"
    curl -O -L "https://golang.org/dl/go${VERSION}.linux-${ARCH}.tar.gz"
    ls -l
    tar -xf "go${VERSION}.linux-${ARCH}.tar.gz"
    sudo chown -R root:root ./go
    sudo mv -v go /usr/local
    echo 'export GOPATH=$HOME/go' >> /home/vagrant/.bash_profile
    echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> /home/vagrant/.bash_profile
    source /home/vagrant/.bash_profile
    go version
  SHELL
end
