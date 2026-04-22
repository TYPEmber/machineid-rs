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
// Resolve the physical disk behind the Windows OS volume instead of assuming disk index 0.
const POWERSHELL_OS_DISK_SERIAL_COMMAND: &str = r#"$ErrorActionPreference = 'Stop';
$driveLetter = ((Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive).TrimEnd(':');
$disk = Get-Partition -DriveLetter $driveLetter | Get-Disk | Select-Object -First 1;
if (-not $disk -or [string]::IsNullOrWhiteSpace($disk.SerialNumber)) {
    throw 'failed to resolve physical disk serial for system drive'
}
[Console]::Out.Write($disk.SerialNumber.Trim())"#;

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
    // Ask Windows which logical drive hosts the OS. This is usually C:, but not guaranteed.
    let os_drive_output = command_stdout("wmic", &["os", "get", "SystemDrive"])?;
    let os_drive = os_drive_output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "SystemDrive")
        .ok_or(HWIDError::new(
            "DiskIdError",
            "failed to read system drive from WMIC output",
        ))?;

    let association_output = command_stdout(
        "wmic",
        &[
            "path",
            "Win32_LogicalDiskToPartition",
            "get",
            "Antecedent,Dependent",
            "/value",
        ],
    )?;

    let os_drive_marker = format!(r#"DeviceID="{}""#, os_drive);
    let mut partition_path: Option<&str> = None;
    let mut resolved_disk_index: Option<String> = None;

    // WMIC emits Antecedent/Dependent pairs separated by blank lines.
    for line in association_output.lines().map(str::trim) {
        if line.is_empty() {
            partition_path = None;
            continue;
        }

        if let Some(value) = line.strip_prefix("Antecedent=") {
            partition_path = Some(value);
            continue;
        }

        if let Some(value) = line.strip_prefix("Dependent=") {
            if !value.contains(&os_drive_marker) {
                continue;
            }

            let partition_path = match partition_path {
                Some(value) => value,
                None => continue,
            };

            if let Some(start) = partition_path.find("Disk #") {
                let index: String = partition_path[start + "Disk #".len()..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                if !index.is_empty() {
                    resolved_disk_index = Some(index);
                    break;
                }
            }
        }
    }

    let disk_index = resolved_disk_index.ok_or(HWIDError::new(
        "DiskIdError",
        "failed to resolve system drive disk index from WMIC output",
    ))?;
    let disk_index_filter = format!("Index={}", disk_index);

    // Query the physical disk resolved from the OS volume association.
    let output = command_stdout(
        "wmic",
        &[
            "path",
            "Win32_DiskDrive",
            "where",
            disk_index_filter.as_str(),
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
    let output = command_stdout(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_OS_DISK_SERIAL_COMMAND,
        ],
    )?;

    let serial = output.trim();
    if serial.is_empty() {
        Err(HWIDError::new(
            "DiskIdError",
            "failed to read disk serial from PowerShell output",
        ))
    } else {
        Ok(serial.to_owned())
    }
}

#[cfg(target_os = "windows")]
/// Get OS Disk Serial Number.
/// This is more reliable than assuming the OS disk is always Disk 0, especially in multi-disk systems or those with removable drives.
pub(crate) fn get_disk_id() -> Result<String, HWIDError> {
    // Keep WMIC as the preferred path, but fall back to PowerShell on systems where WMIC is absent.
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
