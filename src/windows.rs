#[cfg(target_os = "windows")]
use crate::errors::HWIDError;
#[cfg(target_os = "windows")]
use serde::Deserialize;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};

thread_local! {
    #[cfg(target_os="windows")]
    static COM_LIB:COMLibrary = COMLibrary::without_security().unwrap();
}

#[cfg(target_os = "windows")]
pub fn get_hwid() -> Result<String, HWIDError> {
    use winreg::enums::{KEY_READ, KEY_WOW64_64KEY};

    let rkey = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Cryptography",
        KEY_READ | KEY_WOW64_64KEY,
    )?;

    let id = rkey.get_value("MachineGuid")?;
    Ok(id)
}

#[cfg(target_os = "windows")]
#[derive(Deserialize)]
struct MACGeneric {
    MACAddress: String,
}

#[cfg(target_os = "windows")]
fn command_stdout(command: &str, args: &[&str]) -> Result<String, HWIDError> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            format!("{} exited with status {}", command, output.status)
        } else {
            format!(
                "{} exited with status {}: {}",
                command,
                output.status,
                stderr.trim()
            )
        };
        return Err(HWIDError::new("DiskIdError", message.as_str()));
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(target_os = "windows")]
fn get_disk_id_from_wmic() -> Result<String, HWIDError> {
    let output = command_stdout(
        "wmic",
        &[
            "path",
            "Win32_DiskDrive",
            "where",
            "Index=0",
            "get",
            "SerialNumber",
        ],
    )?;

    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "SerialNumber")
        .map(str::to_owned)
        .ok_or(HWIDError::new(
            "DiskIdError",
            "failed to read disk serial from WMIC output",
        ))
}

#[cfg(target_os = "windows")]
fn get_disk_id_from_powershell() -> Result<String, HWIDError> {
    const POWERSHELL_DISK_SERIAL_COMMAND: &str = r#"$ErrorActionPreference = 'Stop'; Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.Index -eq 0 } | Select-Object -ExpandProperty SerialNumber -First 1"#;

    let output = command_stdout(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_DISK_SERIAL_COMMAND,
        ],
    )?;

    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or(HWIDError::new(
            "DiskIdError",
            "failed to read disk serial from PowerShell output",
        ))
}

#[cfg(target_os = "windows")]
pub(crate) fn get_disk_id() -> Result<String, HWIDError> {
    match get_disk_id_from_wmic() {
        Ok(serial) => Ok(serial),
        Err(wmic_error) => match get_disk_id_from_powershell() {
            Ok(serial) => Ok(serial),
            Err(powershell_error) => {
                let message = format!(
                    "failed to retrieve disk serial via WMIC ({}) and PowerShell CIM ({})",
                    wmic_error, powershell_error
                );
                Err(HWIDError::new("DiskIdError", message.as_str()))
            }
        },
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn get_mac_address() -> Result<String, HWIDError> {
    let con = WMIConnection::new(COM_LIB.with(|con| *con))?;
    let ser: Vec<MACGeneric> =
        con.raw_query("SELECT MACAddress from Win32_NetworkAdapter WHERE MACAddress IS NOT NULL")?;
    Ok(ser
        .first()
        .ok_or(HWIDError::new(
            "MACAddress",
            "Could not retrieve Mac Address",
        ))?
        .MACAddress
        .clone())
}
