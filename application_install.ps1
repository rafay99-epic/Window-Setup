#-----------------------------------------------------------------------------------------------
# Script: Customize Window 10
# Author: Abdul Rafay
# Email: 99marafay@gmail.com                                                                           
# Version: 1.0
#-----------------------------------------------------------------------------------------------

function winget()
{
	Write-Host "Checking winget..."

	# Check if winget is installed
	if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
		'Winget Already Installed'
	}  
	else{
		# Installing winget from the Microsoft Store
		Write-Host "Winget not found, installing it now."
		Write-Host "Installing Winget... Please Wait"
		Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
		$nid = (Get-Process AppInstaller).Id
		Wait-Process -Id $nid
		Write-Host Winget Installed
		Write-Host "Winget Installed - Ready for Next Task"
	}

}
function brave()
{
	Write-Host "Installing Brave Browser"
    winget install -e BraveSoftware.BraveBrowser | Out-Host
    if($?) { Write-Host "Installed Brave Browser" }
    Write-Host "Finished Installing Brave"
}
function google_chrome()
{
	Write-Host "Installing Google Chrome"
    winget install -e Google.Chrome | Out-Host
    if($?) { Write-Host "Installed Google Chrome" }
    Write-Host "Finished Installing Google Chrome"
}
function discord()
{
	Write-Host "Installing Discord"
    winget install -e Discord.Discord | Out-Host
    if($?) { Write-Host "Installed Discord" }
	Write-Host "Finished Installing Discord"
}
function vlc()
{
	Write-Host "Installing VLC Media Player"
    winget install -e VideoLAN.VLC | Out-Host
    if($?) { Write-Host "Installed VLC Media Player" }
    Write-Host "Finished Installing VLC Media Player"
}
function 7zip()
{
	Write-Host "Installing 7-Zip Compression Tool"
    winget install -e 7zip.7zip | Out-Host
    if($?) { Write-Host "Installed 7-Zip Compression Tool" }
    Write-Host "Finished Installing 7-Zip Compression Tool" 
}
function vscode()
{
	Write-Host "Installing Visual Studio Code"
    winget install -e Microsoft.VisualStudioCode --source winget | Out-Host
    if($?) { Write-Host "Installed Visual Studio Code" }
    Write-Host "Finished Installing Visual Studio Code" 

}
function window_terminal()
{
	Write-Host "Installing New Windows Terminal"
    winget install -e Microsoft.WindowsTerminal | Out-Host
    if($?) { Write-Host "Installed New Windows Terminal" }
 	Write-Host "Finished Installing New Windows Terminal" 
}
function githubdesktop()
{
	Write-Host "Installing GitHub Desktop"
    winget install -e GitHub.GitHubDesktop | Out-Host
    Write-Host "Installed Github Desktop"
}
function epic_launcher()
{
	Write-Host "Installing Epic Game Store Desktop"
	winget install -e --id EpicGames.EpicGamesLauncher | Out-Host
	if($?) { Write-Host "Installed Epic Game Desktop" }
	Write-Host "Installed Epic Game Store Desktop"
}
function android_studio()
{
	Write-Host "Installing Android Studio"
	winget install -e --id Google.AndroidStudio | Out-Host
	if($?) { Write-Host "Installing Android Studio" }
	Write-Host "Installed Android Studio"
}
function java_jdk()
{
	Write-Host "Installing Java JDK"
	winget install -e --id Oracle.JavaRuntimeEnvironment | Out-Host
	if($?) { Write-Host " Installing Java JDK" }
	Write-Host "Installed Java JDK"
}
function java_IDE()
{
	Write-Host "Installing Java IDE"
	winget install -e --id JetBrains.IntelliJIDEA.Ultimate.EAP
	if($?) { Write-Host "Installing Java IDE" }
	Write-Host "Installed Java IDE"
}
function bitwarden()
{
	Write-Host "Installing Bitwarden"
	winget install -e --id Bitwarden.Bitwarden | Out-Host
	if($?) { Write-Host "Installing Bitwarden" }
	Write-Host "Installed Bitwarden"
}
function python3()
{
	Write-Host "Installing Python3"
	winget install -e --id Python.Python.3 | Out-Host
	if($?) { Write-Host "Installing Python3" }
	Write-Host "Installed Python3"
}
function steam()
{
	Write-Host "Installing Steam"
	winget install -e --id Valve.Steam | Out-Host
	if($?) { Write-Host "Installing Steam" }
	Write-Host "Installed Steam"
}
function xampp()
{
	Write-Host "Installing Xampp"
	winget install -e --id ApacheFriends.Xampp | Out-Host
	if($?) { Write-Host "Installing Xampp" }
	Write-Host "Installed Steam"
}

function application_install()
{
	Write-Host "Installing Applications"
	brave
	google_chrome
	discord
	vlc
	7zip
	vscode
	window_terminal
	githubdesktop
	epic_launcher
	android_studio
	java_jdk
	java_IDE
	bitwarden
	python3
	steam
	xampp
}

function application_main() 
{
	#Checking for winget and if not install then install winget.
	winget
	#This function will install applications
	application_install
}
application_main

