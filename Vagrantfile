Vagrant.configure("2") do |config|
  config.vm.box = "generic/debian12"

  config.vm.box_check_update = true

  # Synced folders
  config.vm.synced_folder ".", "/app"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = 1
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y python3

    # Create an alias for easy running
    echo "alias run-sniffer='sudo python3 /app/sniffer/sniffer.py --interface all'" >> /home/vagrant/.bashrc
    echo "cd /app" >> /home/vagrant/.bashrc
  SHELL
end
