#!/bin/bash
AZUREUSERNAME=${1}
AZUREPASSWORD=${2}
AZURETENANTID=${3}
AZURESUBSCRIPTIONID=${4}
ODLID=${5}
DEPLOYMENTID=${6}

sudo apt-get update

sudo apt-get install pass gnupg2 -y

sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release -y

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get install docker-compose -y

sudo apt-get install make -y

sudo docker pull docker.io/azurebellhop/engine:v0.4

sudo docker pull wernight/bfgminer

sudo docker pull metal3d/xmrig:latest

sudo docker pull mcr.microsoft.com/dotnet/core/aspnet:2.1

#install azure cli
cd

curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

#install powershell

# Update the list of packages
sudo apt-get update
# Install pre-requisite packages.
sudo apt-get install -y wget apt-transport-https software-properties-common
# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb
# Update the list of products
sudo apt-get update
# Enable the "universe" repositories
sudo add-apt-repository universe
# Install PowerShell
sudo apt-get install -y powershell

sudo snap install powershell --classic

#get the key from azrue container instance
ACRNAME=""
ACRPASSWORD=""

#deploy the items
sudo docker login $ACRNAME.azurecr.io -u $ACRNAME -p $ACRPASSWORD

sudo docker tag docker.io/azurebellhop/engine:v0.4 $ACRNAME.azurecr.io/azurebellhop/engine:v0.4

sudo docker tag wernight/bfgminer $ACRNAME.azurecr.io/bitcoin/windows

sudo docker tag metal3d/xmrig $ACRNAME.azurecr.io/metal3d/xmrig

sudo docker tag mcr.microsoft.com/dotnet/core/aspnet:2.1 $ACRNAME.azurecr.io/dotnet/core/aspnet:2.1

sudo docker push $ACRNAME.azurecr.io/azurebellhop/engine:v0.4

sudo docker push $ACRNAME.azurecr.io/bitcoin/windows

sudo docker push $ACRNAME.azurecr.io/metal3d/xmrig

sudo docker push $ACRNAME.azurecr.io/dotnet/core/aspnet:2.1

