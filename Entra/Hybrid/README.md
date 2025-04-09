# Hybrid Enviroment Scripts (Entra and On-prem Active Directory) <br />
![image](https://github.com/user-attachments/assets/1dee1766-eaa8-439f-945f-70d52fcd5f02) <br />
**Descriptions of Scripts within this Folder:** <br />
1. `Windows-AD&Entra-HybridEligibilityChecker.ps1` - is a PowerShell auditing tool that scans Active Directory computer objects, filters for Windows-based devices, and evaluates their group memberships. It generates Excel reports showing ungrouped devices, workstation-only groups, mixed server/workstation groups, and devices that are ineligible for Hybrid Azure AD Join. A final report lists all Windows systems, and the script automatically installs required modules, organizes outputs in a clean ADReports folder, and cleans up when complete. <br />
