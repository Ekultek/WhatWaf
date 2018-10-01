#!/bin/bash


function helpPage {
  echo -e "\n./setup.sh {install|remove}\n";
}

function install {
  home="$HOME/.whatwaf";
  exec_dir="$home/.install/bin";
  exec_filename="$exec_dir/whatwaf"
  copy_dir="$home/.install/etc";
  mkdir $home;
  mkdir $home/.install
  mkdir $exec_dir;
  mkdir $copy_dir;
  chmod +x ./whatwaf.py
  echo "copying files over..";
  rsync -drq . $copy_dir
  echo "creating executable";
  cat << EOF > $exec_filename
#!/bin/bash
# this is the execution script for whatwaf
# created by the whatwaf installer on $(date +%F)
cd $copy_dir
exec python whatwaf.py \$@
EOF
  echo "editing file stats";
  chmod +x $exec_filename;
  echo "export PATH=\"$PATH:$exec_dir\"" >> $HOME/.bash_profile;
  echo "installed, you need to run: source ~/.bash_profile";
}

function uninstall {
  rm -rf ~/.whatwaf
  echo "home directory removed, manually remove the export PATH pertaining to $HOME/.whatwaf/bin"
}

function main {
  if [[ "$1" == "install" ]]; then
    echo -e " Installing:";
    echo -e "	                          ,------. ";
    echo -e "	                         '  .--.  '";
    echo -e "	,--.   .--.   ,--.   .--.|  |  |  |";
    echo -e "	|  |   |  |   |  |   |  |'--'  |  |";
    echo -e "	|  |   |  |   |  |   |  |    __.  |";
    echo -e "	|  |.'.|  |   |  |.'.|  |   |   .' ";
    echo -e "	|         |   |         |   |___|  ";
    echo -e "	|   ,'.   |hat|   ,'.   |af .---.  ";
    echo -e "	'--'   '--'   '--'   '--'   '---'  ";
    install;
  elif [[ "$1" == "remove" ]]; then
    echo -e " Uninstalling:";
    echo -e "	                          ,------. ";
    echo -e "	                         '  .--.  '";
    echo -e "	,--.   .--.   ,--.   .--.|  |  |  |";
    echo -e "	|  |   |  |   |  |   |  |'--'  |  |";
    echo -e "	|  |   |  |   |  |   |  |    __.  |";
    echo -e "	|  |.'.|  |   |  |.'.|  |   |   .' ";
    echo -e "	|         |   |         |   |___|  ";
    echo -e "	|   ,'.   |hat|   ,'.   |af .---.  ";
    echo -e "	'--'   '--'   '--'   '--'   '---'  ";
    uninstall;
  else
    helpPage;
  fi;
}

main $@;
