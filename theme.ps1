#-----------------------------------------------------------------------------------------------
# Script: Customize Window 10
# Author: Abdul Rafay
# Email: 99marafay@gmail.com                                                                           
# Version: 1.0
#-----------------------------------------------------------------------------------------------

function move_file()
{
    Write-Host "Moving Wallpapers from one folder to another folder"
    #the file location
    $_SourcePath = "E:\Github\Window-Setup\wallpapers"
    #The file where is need to be located
    $_DestinationPath = "C:\Users\maraf\Pictures\"
    
    #The buildin function that will move the file from one location to another location
    Move-item –path $_SourcePath –destination $_DestinationPath
}
#This function will be changing wallpaper using the powershell
function Set-Wallpaper($MyWallpaper){
    Write-Host "Changing Wallpaper"
    $code = @' 
    using System.Runtime.InteropServices; 
    namespace Win32{ 
        
         public class Wallpaper{ 
            [DllImport("user32.dll", CharSet=CharSet.Auto)] 
             static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
             
             public static void SetWallpaper(string thePath){ 
                SystemParametersInfo(20,0,thePath,3); 
             }
        }
     } 
'@    
add-type $code 
[Win32.Wallpaper]::SetWallpaper($MyWallpaper)
}

function lock_screen()
{
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" 
    $img =  "C:\Users\maraf\Pictures\wallpapers\wallpaper (9).jpg"
    Set-ItemProperty -Path $path -Name LockScreenImage -value $img
}
 function theme_color()
 {
    $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"


    #Accent Color Menu Key
    $AccentColorMenuKey = @{
        Key   = 'AccentColorMenu';
        Type  = "DWORD";
        Value = '0xff4e3f30'
    }
    
    If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -ErrorAction SilentlyContinue))
    {
        New-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -PropertyType $AccentColorMenuKey.Type -Force
    }
    Else
    {
        Set-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -Force
    }
    
    
    #Accent Palette Key
    $AccentPaletteKey = @{
        Key   = 'AccentPalette';
        Type  = "BINARY";
        Value = '51,6b,84,ff,43,59,6e,ff,3a,4c,5e,ff,30,3f,4e,ff,26,33,3f,ff,1d,26,2f,ff,0f,14,19,ff,88,17,98,00'
    }
    $hexified = $AccentPaletteKey.Value.Split(',') | ForEach-Object { "0x$_" }
    
    If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -ErrorAction SilentlyContinue))
    {
        New-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -PropertyType Binary -Value ([byte[]]$hexified)
    }
    Else
    {
        Set-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -Value ([byte[]]$hexified) -Force
    }
    
    
    #MotionAccentId_v1.00 Key
    $MotionAccentIdKey = @{
        Key   = 'MotionAccentId_v1.00';
        Type  = "DWORD";
        Value = '0x000000db'
    }
    
    If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $MotionAccentIdKey.Key -ErrorAction SilentlyContinue))
    {
        New-ItemProperty -Path $RegPath -Name $MotionAccentIdKey.Key -Value $MotionAccentIdKey.Value -PropertyType $MotionAccentIdKey.Type -Force
    }
    Else
    {
        Set-ItemProperty -Path $RegPath -Name $MotionAccentIdKey.Key -Value $MotionAccentIdKey.Value -Force
    }
    
    
    
    #Start Color Menu Key
    $StartMenuKey = @{
        Key   = 'StartColorMenu';
        Type  = "DWORD";
        Value = '0xff3f3326'
    }
    
    If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -ErrorAction SilentlyContinue))
    {
        New-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -PropertyType $StartMenuKey.Type -Force
    }
    Else
    {
        Set-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -Force
    }
    
    
    Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue
 }

#The running point for the functions below
function theme_main()
{
    #moving File from one location to another location
    move_file
    
    #Setting The wallpapers
    Set-Wallpaper("C:\Users\maraf\Pictures\wallpapers\wallpaper (9).jpg")

    #this will set the lock screen wallpapers
    lock_screen

    #Changing Color theme_color
    theme_color

}
