#!/bin/bash

bgreen='\033[1;32m'
yellow='\033[0;33m'
reset='\033[0m'
bred='\033[1;31m'

DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if grep -q "ARMv"  /proc/cpuinfo
then
   IS_ARM="True";
else
   IS_ARM="False";
fi

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
fi

printf "${bgreen}Installing recon-bluster${reset}\n\n"

install_apt(){
    eval $SUDO apt update && $SUDO apt install -y curl sqlmap jq python3-pip git
}

install_yum(){
    eval $SUDO yum install -y curl sqlmap jq python3-pip git
}

install_pacman(){
    eval $SUDO pacman -Sy install -y curl sqlmap jq python3-pip git
}

if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

#installing latest Golang version
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]]
    then
        printf "${bgreen}\nGolang is already installed${reset}\n\n"
    else
        printf "${bgreen}\nInstalling Golang${reset}\n\n"
        if [ "True" = "$IS_ARM" ]; then
            eval wget https://dl.google.com/go/$(curl -s https://go.dev/VERSION?m=text).linux-armv6l.tar.gz
            eval $SUDO tar -C /usr/local -xzf go$LATEST_GO.linux-armv6l.tar.gz
            $SUDO cp /usr/local/go/binbash/go /usr/bin
        else
            eval wget https://dl.google.com/go/$(curl -s https://go.dev/VERSION?m=text).linux-amd64.tar.gz
            eval $SUDO tar -C /usr/local -xzf go*.linux-amd64.tar.gz
            $SUDO cp /usr/local/go/bin/go /usr/bin
        fi
        rm -rf go$LATEST_GO*
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
if [ -f ~/.bashrc ]
then
cat << EOF >> ~/.bashrc

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH
unalias gf
unalias gau
EOF
fi

if [ -f ~/.zshrc ]
then
cat << EOF >> ~/.zshrc

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH
unalias gf
unalias gau
EOF
fi
# printf "${yellow} Golang installed! Open a new terminal and run again this script ${reset}\n"
# exit
fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }

printf "${bgreen}System env ready${reset}\n\n"


[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/tools" ] && mkdir -p ~/tools
DIR=~/tools

eval pip3 install -r requirements.txt
printf "${bgreen}\nRequirements installed\n\nTools installation begins${reset}\n\n"

eval go install -v github.com/tomnomnom/waybackurls@latest
eval go install -v github.com/tomnomnom/assetfinder@latest
eval go install -v github.com/tomnomnom/anew@latest
eval go install -v github.com/tomnomnom/gf@latest
eval go install -v github.com/tomnomnom/qsreplace@latest
eval go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
eval go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
eval go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
eval go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
eval go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
eval go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
eval go install -v github.com/projectdiscovery/katana/cmd/katana@latest
eval go install -v github.com/OWASP/Amass/v3/...@master
eval go install -v github.com/lc/gau/v2/cmd/gau@latest
eval go install -v github.com/hakluke/hakrawler@latest
eval go install -v github.com/dwisiswant0/unew@latest
eval go install -v github.com/ferreiraklet/airixss@latest
eval go install -v github.com/s0md3v/smap/cmd/smap@latest
eval git clone https://github.com/1ndianl33t/Gf-Patterns $DIR/Gf-Patterns
eval git clone https://github.com/tomnomnom/gf $DIR/gf
eval git clone https://github.com/xnl-h4ck3r/waymore $DIR/waymore; cd $DIR/waymore; python3 setup.py install
eval cp $DIR/gf/examples/* ~/.gf
eval cp $DIR/Gf-Patterns/*.json ~/.gf

printf "${bgreen}\nrecon-bluster installed! Please reboot your system.${reset}\n\n"