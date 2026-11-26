# Couverture mesurée : EVTX-ATTACK-SAMPLES

_Fichier généré par `attack_coverage.py` et vérifié par l'intégration continue à chaque envoi : il ne peut pas être retouché à la main sans que les tests échouent._

Jeu de données : [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) de Samir Bousseaden, version [`4ceed2f4706d`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/4ceed2f4706daf601c212a8f91c113dd85349a2c) : 278 enregistrements de journaux Windows capturés pendant de vraies techniques d'attaque. Ils ne sont pas copiés dans ce dépôt ; l'intégration continue les télécharge.

Règles évaluées : 22.

## Résultat

- **32 enregistrements sur 278** déclenchent au moins une alerte (11,5 %).
- Parmi les 206 enregistrements qui contiennent des événements que mini-SIEM sait lire, **32 déclenchent une alerte (15,5 %)**.
- ✅ **14 détectées** : au moins une alerte de la tactique attendue.
- 🟡 **18 signalées** : une alerte, mais d'une autre tactique (ou dossier sans tactique unique). L'analyste est prévenu, avec une étiquette imparfaite.
- ❌ **174 manquées** : mini-SIEM lit des événements du fichier, aucune règle ne se déclenche. L'attaque passe.
- ⚪ **72 hors périmètre** : aucun événement d'un journal ou d'un type que mini-SIEM lit (voir plus bas les sources les plus fréquentes).

Le chiffre est volontairement modeste : mini-SIEM est un projet d'apprentissage avec une vingtaine de règles, et ce jeu de données couvre des centaines de techniques. Le tableau sert à montrer honnêtement ce qui passe et à suivre l'effet de chaque nouvelle règle.

## Par tactique

| Dossier (tactique) | Enregistrements | ✅ | 🟡 | ❌ | ⚪ | Alerte, dans le périmètre |
|---|---:|---:|---:|---:|---:|---:|
| Command and Control | 6 | 0 | 0 | 4 | 2 | 0,0 % |
| Credential Access | 39 | 10 | 1 | 11 | 17 | 50,0 % |
| Defense Evasion | 36 | 2 | 2 | 23 | 9 | 14,8 % |
| Discovery | 11 | 0 | 1 | 3 | 7 | 25,0 % |
| Execution | 34 | 0 | 4 | 26 | 4 | 13,3 % |
| Lateral Movement | 47 | 0 | 3 | 28 | 16 | 9,7 % |
| Persistence | 22 | 2 | 2 | 13 | 5 | 23,5 % |
| Privilege Escalation | 66 | 0 | 0 | 61 | 5 | 0,0 % |
| (sans tactique) | 17 | 0 | 5 | 5 | 7 | 50,0 % |
| **Total** | **278** | **14** | **18** | **174** | **72** | **15,5 %** |

## Règles qui se déclenchent

| Règle | Enregistrements | dont tactique attendue |
|---|---:|---:|
| `SYSMON_LSASS_ACCESS` | 13 | 9 |
| `SYSMON_LOLBIN_NETWORK` | 9 | 1 |
| `SYSMON_RUN_KEY` | 6 | 1 |
| `SYSMON_LOLBIN_DOWNLOAD` | 2 | 0 |
| `SYSMON_COMSVCS_MINIDUMP` | 1 | 1 |
| `SYSMON_INFECTION_CHAIN` | 1 | 0 |
| `SYSMON_OFFICE_SHELL` | 1 | 0 |
| `SYSMON_PS_ENCODED` | 1 | 0 |
| `WIN_ACCOUNT_CREATED` | 1 | 0 |
| `WIN_GROUP_ADD` | 1 | 1 |
| `WIN_LOG_CLEARED` | 1 | 1 |

## Ce qui manque le plus

Sources (journal et numéro d'événement) présentes dans les enregistrements **manqués ou hors périmètre**, par nombre d'enregistrements : les meilleures pistes. Quand mini-SIEM lit déjà la source, ce sont des règles qui manquent ; sinon, un type d'événement à lire.

| Journal | EventID | Enregistrements non détectés | Lu par mini-SIEM |
|---|---:|---:|---|
| Sysmon | 1 | 124 | oui : il manque des règles |
| Sysmon | 13 | 53 | oui : il manque des règles |
| Sysmon | 11 | 49 | oui : il manque des règles |
| Sysmon | 7 | 36 | non |
| Sysmon | 10 | 32 | oui : il manque des règles |
| Sysmon | 3 | 29 | oui : il manque des règles |
| Sysmon | 12 | 23 | non |
| Sysmon | 5 | 22 | non |
| Security | 4624 | 21 | oui : il manque des règles |
| Sysmon | 18 | 16 | non |
| Security | 5145 | 15 | non |
| Sysmon | 17 | 8 | non |
| Sysmon | 8 | 7 | non |
| Security | 4688 | 7 | non |
| Security | 4672 | 6 | oui : il manque des règles |

## Détail par enregistrement

<details><summary><b>Command and Control</b> : 6 enregistrements (❌ 4 · ⚪ 2)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `DE_RDP_Tunnel_5156.evtx` | ❌ manquée | – |
| `DE_RDP_Tunneling_4624.evtx` | ❌ manquée | – |
| `DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | ⚪ hors périmètre | – |
| `DE_sysmon-3-rdp-tun.evtx` | ❌ manquée | – |
| `bits_openvpn.evtx` | ⚪ hors périmètre | – |
| `tunna_iis_rdp_smb_tunneling_sysmon_3.evtx` | ❌ manquée | – |

</details>

<details><summary><b>Credential Access</b> : 39 enregistrements (✅ 10 · 🟡 1 · ❌ 11 · ⚪ 17)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `4794_DSRM_password_change_t1098.evtx` | ⚪ hors périmètre | – |
| `ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx` | ⚪ hors périmètre | – |
| `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | ❌ manquée | – |
| `CA_DCSync_4662.evtx` | ⚪ hors périmètre | – |
| `CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx` | ❌ manquée | – |
| `CA_PetiPotam_etw_rpc_efsr_5_6.evtx` | ⚪ hors périmètre | – |
| `CA_chrome_firefox_opera_4663.evtx` | ⚪ hors périmètre | – |
| `CA_hashdump_4663_4656_lsass_access.evtx` | ⚪ hors périmètre | – |
| `CA_keefarce_keepass_credump.evtx` | ❌ manquée | – |
| `CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx` | ⚪ hors périmètre | – |
| `CA_protectedstorage_5145_rpc_masterkey.evtx` | ⚪ hors périmètre | – |
| `CA_sysmon_hashdump_cmd_meterpreter.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `CA_teamviewer-dumper_sysmon_10.evtx` | ❌ manquée | – |
| `LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx` | ⚪ hors périmètre | – |
| `MSSQL_multiple_failed_logon_EventID_18456.evtx` | ⚪ hors périmètre | – |
| `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` | ⚪ hors périmètre | – |
| `Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.evtx` | ❌ manquée | – |
| `Sysmon_13_Local_Admin_Password_Changed.evtx` | ❌ manquée | – |
| `Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx` | ⚪ hors périmètre | – |
| `Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx` | ❌ manquée | – |
| `babyshark_mimikatz_powershell.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `dc_applog_ntdsutil_dfir_325_326_327.evtx` | ⚪ hors périmètre | – |
| `discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` | 🟡 signalée | `SYSMON_PS_ENCODED` |
| `etw_rpc_zerologon.evtx` | ⚪ hors périmètre | – |
| `kerberos_pwd_spray_4771.evtx` | ⚪ hors périmètre | – |
| `phish_windows_credentials_powershell_scriptblockLog_4104.evtx` | ⚪ hors périmètre | – |
| `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx` | ❌ manquée | – |
| `remote_sam_registry_access_via_backup_operator_priv.evtx` | ❌ manquée | – |
| `sysmon17_18_kekeo_tsssp_default_np.evtx` | ⚪ hors périmètre | – |
| `sysmon_10_11_lsass_memdump.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `sysmon_10_1_memdump_comsvcs_minidump.evtx` | ✅ détectée | `SYSMON_COMSVCS_MINIDUMP` |
| `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `sysmon_13_keylogger_directx.evtx` | ❌ manquée | – |
| `sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |
| `sysmon_rdrleakdiag_lsass_dump.evtx` | ❌ manquée | – |
| `tutto_malseclogon.evtx` | ✅ détectée | `SYSMON_LSASS_ACCESS` |

</details>

<details><summary><b>Defense Evasion</b> : 36 enregistrements (✅ 2 · 🟡 2 · ❌ 23 · ⚪ 9)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `DE_104_system_log_cleared.evtx` | ⚪ hors périmètre | – |
| `DE_1102_security_log_cleared.evtx` | ✅ détectée | `WIN_LOG_CLEARED` |
| `DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | 🟡 signalée | `SYSMON_LSASS_ACCESS` |
| `DE_EventLog_Service_Crashed.evtx` | ❌ manquée | – |
| `DE_Fake_ComputerAccount_4720.evtx` | 🟡 signalée | `WIN_ACCOUNT_CREATED` |
| `DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx` | ⚪ hors périmètre | – |
| `DE_Powershell_CLM_Disabled_Sysmon_12.evtx` | ⚪ hors périmètre | – |
| `DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx` | ❌ manquée | – |
| `DE_UAC_Disabled_Sysmon_12_13.evtx` | ❌ manquée | – |
| `DE_WinEventLogSvc_Crash_System_7036.evtx` | ⚪ hors périmètre | – |
| `DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.evtx` | ❌ manquée | – |
| `DE_renamed_psexec_service_sysmon_17_18.evtx` | ⚪ hors périmètre | – |
| `DE_suspicious_remote_eventlog_svc_access_5145.evtx` | ❌ manquée | – |
| `DE_xp_cmdshell_enabled_MSSQL_EID_15457.evtx` | ⚪ hors périmètre | – |
| `DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.evtx` | ❌ manquée | – |
| `Sysmon 7  Update Session Orchestrator Dll Hijack.evtx` | ✅ détectée | `SYSMON_LOLBIN_NETWORK` |
| `Sysmon 7 dllhijack_cdpsshims_CDPSvc.evtx` | ❌ manquée | – |
| `Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.evtx` | ❌ manquée | – |
| `Sysmon_12_DE_AntiForensics_MRU_DeleteKey.evtx` | ⚪ hors périmètre | – |
| `Win_4985_T1186_Process_Doppelganging.evtx` | ⚪ hors périmètre | – |
| `apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx` | ❌ manquée | – |
| `de_PsScriptBlockLogging_disabled_sysmon12_13.evtx` | ❌ manquée | – |
| `de_hiding_files_via_attrib_cmdlet.evtx` | ❌ manquée | – |
| `de_portforward_netsh_rdp_sysmon_13_1.evtx` | ❌ manquée | – |
| `de_powershell_execpolicy_changed_sysmon_13.evtx` | ❌ manquée | – |
| `de_sysmon_13_VBA_Security_AccessVBOM.evtx` | ❌ manquée | – |
| `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx` | ❌ manquée | – |
| `evasion_codeinj_odzhan_conhost_sysmon_10_1.evtx` | ❌ manquée | – |
| `evasion_codeinj_odzhan_spoolsv_sysmon_10_1.evtx` | ❌ manquée | – |
| `faxhell_sysmon_7_1_18_3_bindshell_dllhijack.evtx` | ❌ manquée | – |
| `meterpreter_migrate_to_explorer_sysmon_8.evtx` | ⚪ hors périmètre | – |
| `process_suspend_sysmon_10_ga_800.evtx` | ❌ manquée | – |
| `sideloading_wwlib_sysmon_7_1_11.evtx` | ❌ manquée | – |
| `sysmon_10_1_ppid_spoofing.evtx` | ❌ manquée | – |
| `sysmon_13_rdp_settings_tampering.evtx` | ❌ manquée | – |
| `sysmon_2_11_evasion_timestomp_MACE.evtx` | ❌ manquée | – |

</details>

<details><summary><b>Discovery</b> : 11 enregistrements (🟡 1 · ❌ 3 · ⚪ 7)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `4799_remote_local_groups_enumeration.evtx` | ⚪ hors périmètre | – |
| `Discovery_Remote_System_NamedPipes_Sysmon_18.evtx` | ⚪ hors périmètre | – |
| `dicovery_4661_net_group_domain_admins_target.evtx` | ❌ manquée | – |
| `discovery_UEFI_Settings_rweverything_sysmon_6.evtx` | ⚪ hors périmètre | – |
| `discovery_bloodhound.evtx` | ⚪ hors périmètre | – |
| `discovery_enum_shares_target_sysmon_3_18.evtx` | ❌ manquée | – |
| `discovery_local_user_or_group_windows_security_4799_4798.evtx` | ⚪ hors périmètre | – |
| `discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx` | 🟡 signalée | `SYSMON_LSASS_ACCESS` |
| `discovery_psloggedon.evtx` | ⚪ hors périmètre | – |
| `discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx` | ⚪ hors périmètre | – |
| `discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx` | ❌ manquée | – |

</details>

<details><summary><b>Execution</b> : 34 enregistrements (🟡 4 · ❌ 26 · ⚪ 4)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` | ❌ manquée | – |
| `Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.evtx` | ⚪ hors périmètre | – |
| `Sysmon_Exec_CompiledHTML.evtx` | ❌ manquée | – |
| `Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `evasion_execution_imageload_wuauclt_lolbas.evtx` | ❌ manquée | – |
| `exec_driveby_cve-2018-15982_sysmon_1_10.evtx` | ❌ manquée | – |
| `exec_msxsl_xsl_sysmon_1_7.evtx` | ❌ manquée | – |
| `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx` | ❌ manquée | – |
| `exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx` | ❌ manquée | – |
| `exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx` | ❌ manquée | – |
| `exec_sysmon_1_7_jscript9_defense_evasion.evtx` | ❌ manquée | – |
| `exec_sysmon_1_ftp.evtx` | ❌ manquée | – |
| `exec_sysmon_1_lolbin_pcalua.evtx` | ❌ manquée | – |
| `exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` | ❌ manquée | – |
| `exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx` | ❌ manquée | – |
| `exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx` | ❌ manquée | – |
| `exec_sysmon_lobin_regsvr32_sct.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `exec_wmic_xsl_internet_sysmon_3_1_11.evtx` | ❌ manquée | – |
| `execution_evasion_visual_studio_prebuild_event.evtx` | ❌ manquée | – |
| `revshell_cmd_svchost_sysmon_1.evtx` | ❌ manquée | – |
| `rogue_msi_url_1040_1042.evtx` | ⚪ hors périmètre | – |
| `susp_explorer_exec.evtx` | ❌ manquée | – |
| `susp_explorer_exec_root_cmdline_@rimpq_@CyberRaiju.evtx` | ❌ manquée | – |
| `sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx` | ❌ manquée | – |
| `sysmon_1_11_rundll32_cpl_ostap.evtx` | ❌ manquée | – |
| `sysmon_exec_from_vss_persistence.evtx` | ❌ manquée | – |
| `sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx` | ❌ manquée | – |
| `sysmon_lolbin_bohops_vshadow_exec.evtx` | ❌ manquée | – |
| `sysmon_mshta_sharpshooter_stageless_meterpreter.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `sysmon_vbs_sharpshooter_stageless_meterpreter.evtx` | ❌ manquée | – |
| `sysmon_zipexec.evtx` | ❌ manquée | – |
| `temp_scheduled_task_4698_4699.evtx` | ⚪ hors périmètre | – |
| `windows_bits_4_59_60_lolbas desktopimgdownldr.evtx` | ⚪ hors périmètre | – |

</details>

<details><summary><b>Lateral Movement</b> : 47 enregistrements (🟡 3 · ❌ 28 · ⚪ 16)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` | ⚪ hors périmètre | – |
| `ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx` | ❌ manquée | – |
| `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | ❌ manquée | – |
| `LM_5145_Remote_FileCopy.evtx` | ⚪ hors périmètre | – |
| `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `LM_ImageLoad_NFSH_Sysmon_7.evtx` | ⚪ hors périmètre | – |
| `LM_NewShare_Added_Sysmon_12_13.evtx` | ❌ manquée | – |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | ❌ manquée | – |
| `LM_REMCOM_5145_TargetHost.evtx` | ⚪ hors périmètre | – |
| `LM_Remote_Service01_5145_svcctl.evtx` | ⚪ hors périmètre | – |
| `LM_Remote_Service02_7045.evtx` | ⚪ hors périmètre | – |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | ❌ manquée | – |
| `LM_WMIC_4648_rpcss.evtx` | ⚪ hors périmètre | – |
| `LM_WMI_4624_4688_TargetHost.evtx` | ❌ manquée | – |
| `LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx` | ❌ manquée | – |
| `LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx` | ⚪ hors périmètre | – |
| `LM_impacket_docmexec_mmc_sysmon_01.evtx` | ❌ manquée | – |
| `LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx` | ❌ manquée | – |
| `LM_renamed_psexecsvc_5145.evtx` | ⚪ hors périmètre | – |
| `LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx` | ❌ manquée | – |
| `LM_sysmon_3_12_13_1_SharpRDP.evtx` | ❌ manquée | – |
| `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx` | ❌ manquée | – |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | ❌ manquée | – |
| `LM_sysmon_remote_task_src_powershell.evtx` | ❌ manquée | – |
| `LM_tsclient_startup_folder.evtx` | ❌ manquée | – |
| `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` | ❌ manquée | – |
| `LM_winrm_exec_sysmon_1_winrshost.evtx` | ❌ manquée | – |
| `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` | ⚪ hors périmètre | – |
| `LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx` | ❌ manquée | – |
| `LM_wmiexec_impacket_sysmon_whoami.evtx` | ❌ manquée | – |
| `LM_xp_cmdshell_MSSQL_Events.evtx` | ⚪ hors périmètre | – |
| `MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx` | ⚪ hors périmètre | – |
| `RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx` | ⚪ hors périmètre | – |
| `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` | ⚪ hors périmètre | – |
| `lateral_movement_startup_3_11.evtx` | ❌ manquée | – |
| `lm_remote_registry_sysmon_1_13_3.evtx` | 🟡 signalée | `SYSMON_RUN_KEY` |
| `lm_sysmon_18_remshell_over_namedpipe.evtx` | ❌ manquée | – |
| `net_share_drive_5142.evtx` | ⚪ hors périmètre | – |
| `powercat_revShell_sysmon_1_3.evtx` | ❌ manquée | – |
| `remote task update 4624 4702 same logonid.evtx` | ❌ manquée | – |
| `remote_file_copy_system_proc_file_write_sysmon_11.evtx` | ❌ manquée | – |
| `sharprdp_sysmon_7_mstscax.dll.evtx` | ❌ manquée | – |
| `smb_bi_auth_conn_spoolsample.evtx` | ❌ manquée | – |
| `smbmap_upload_exec_sysmon.evtx` | ❌ manquée | – |
| `spoolsample_5145.evtx` | ⚪ hors périmètre | – |
| `sysmon_1_exec_via_sql_xpcmdshell.evtx` | ❌ manquée | – |
| `wmi_remote_registry_sysmon.evtx` | 🟡 signalée | `SYSMON_RUN_KEY` |

</details>

<details><summary><b>Persistence</b> : 22 enregistrements (✅ 2 · 🟡 2 · ❌ 13 · ⚪ 5)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` | ⚪ hors périmètre | – |
| `Network_Service_Guest_added_to_admins_4732.evtx` | ✅ détectée | `WIN_GROUP_ADD` |
| `Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.evtx` | ⚪ hors périmètre | – |
| `Persistence_Winsock_Catalog Change EventId_1.evtx` | ⚪ hors périmètre | – |
| `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx` | ✅ détectée | `SYSMON_RUN_KEY` |
| `persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx` | ⚪ hors périmètre | – |
| `persist_firefox_comhijack_sysmon_11_13_7_1.evtx` | ❌ manquée | – |
| `persist_turla_outlook_backdoor_comhijack.evtx` | ❌ manquée | – |
| `persist_valid_account_guest_rid_hijack.evtx` | ❌ manquée | – |
| `persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx` | ❌ manquée | – |
| `persistence_accessibility_features_osk_sysmon1.evtx` | ❌ manquée | – |
| `persistence_hidden_local_account_sysmon.evtx` | ❌ manquée | – |
| `persistence_pendingGPO_sysmon_13.evtx` | ❌ manquée | – |
| `persistence_security_dcshadow_4742.evtx` | ⚪ hors périmètre | – |
| `persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx` | ❌ manquée | – |
| `persistence_sysmon_11_13_1_shime_appfix.evtx` | ❌ manquée | – |
| `sysmon_13_1_persistence_via_winlogon_shell.evtx` | ❌ manquée | – |
| `sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` | 🟡 signalée | `SYSMON_LOLBIN_NETWORK` |
| `sysmon_1_smss_child_proc_bootexecute_setupexecute.evtx` | ❌ manquée | – |
| `sysmon_20_21_1_CommandLineEventConsumer.evtx` | 🟡 signalée | `SYSMON_LSASS_ACCESS` |
| `sysmon_local_account_creation_and_added_admingroup_12_13.evtx` | ❌ manquée | – |
| `wmighost_sysmon_20_21_1.evtx` | ❌ manquée | – |

</details>

<details><summary><b>Privilege Escalation</b> : 66 enregistrements (❌ 61 · ⚪ 5)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx` | ❌ manquée | – |
| `4765_sidhistory_add_t1178.evtx` | ⚪ hors périmètre | – |
| `CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.evtx` | ❌ manquée | – |
| `EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx` | ❌ manquée | – |
| `Invoke_TokenDuplication_UAC_Bypass4624.evtx` | ❌ manquée | – |
| `NTLM2SelfRelay-med0x2e-security_4624_4688.evtx` | ❌ manquée | – |
| `PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx` | ❌ manquée | – |
| `PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx` | ❌ manquée | – |
| `PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx` | ⚪ hors périmètre | – |
| `PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` | ⚪ hors périmètre | – |
| `RogueWinRM.evtx` | ❌ manquée | – |
| `Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx` | ❌ manquée | – |
| `Sysmon_13_1_UACBypass_SDCLTBypass.evtx` | ❌ manquée | – |
| `Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx` | ❌ manquée | – |
| `Sysmon_UACME_22.evtx` | ❌ manquée | – |
| `Sysmon_UACME_23.evtx` | ❌ manquée | – |
| `Sysmon_UACME_30.evtx` | ❌ manquée | – |
| `Sysmon_UACME_32.evtx` | ❌ manquée | – |
| `Sysmon_UACME_33.evtx` | ❌ manquée | – |
| `Sysmon_UACME_34.evtx` | ❌ manquée | – |
| `Sysmon_UACME_36_FileCreate.evtx` | ❌ manquée | – |
| `Sysmon_UACME_37_FileCreate.evtx` | ❌ manquée | – |
| `Sysmon_UACME_38.evtx` | ❌ manquée | – |
| `Sysmon_UACME_39.evtx` | ❌ manquée | – |
| `Sysmon_UACME_41.evtx` | ❌ manquée | – |
| `Sysmon_UACME_43.evtx` | ❌ manquée | – |
| `Sysmon_UACME_45.evtx` | ❌ manquée | – |
| `Sysmon_UACME_53.evtx` | ❌ manquée | – |
| `Sysmon_UACME_54.evtx` | ❌ manquée | – |
| `Sysmon_UACME_56.evtx` | ❌ manquée | – |
| `Sysmon_UACME_63.evtx` | ❌ manquée | – |
| `Sysmon_UACME_64.evtx` | ❌ manquée | – |
| `Sysmon_uacme_58.evtx` | ❌ manquée | – |
| `System_7045_namedpipe_privesc.evtx` | ⚪ hors périmètre | – |
| `UACME_59_Sysmon.evtx` | ❌ manquée | – |
| `UACME_61_Changepk.evtx` | ❌ manquée | – |
| `eop_appcontainer_il_broker_filewrite.evtx` | ❌ manquée | – |
| `privesc_KrbRelayUp_windows_4624.evtx` | ❌ manquée | – |
| `privesc_registry_symlink_CVE-2020-1377.evtx` | ❌ manquée | – |
| `privesc_roguepotato_sysmon_17_18.evtx` | ❌ manquée | – |
| `privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx` | ❌ manquée | – |
| `privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx` | ❌ manquée | – |
| `privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx` | ❌ manquée | – |
| `privesc_spoolsv_spl_file_write_sysmon11.evtx` | ❌ manquée | – |
| `privesc_sysmon_cve_20201030_spooler.evtx` | ❌ manquée | – |
| `privesc_unquoted_svc_sysmon_1_11.evtx` | ❌ manquée | – |
| `privexchange_dirkjan.evtx` | ❌ manquée | – |
| `samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx` | ❌ manquée | – |
| `security_4624_4673_token_manip.evtx` | ❌ manquée | – |
| `sysmon_11_1_15_WScriptBypassUAC.evtx` | ❌ manquée | – |
| `sysmon_11_1_7_uacbypass_cliconfg.evtx` | ❌ manquée | – |
| `sysmon_11_7_1_uacbypass_windirectory_mocking.evtx` | ❌ manquée | – |
| `sysmon_13_1_12_11_perfmonUACBypass.evtx` | ❌ manquée | – |
| `sysmon_13_1_compmgmtlauncherUACBypass.evtx` | ❌ manquée | – |
| `sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx` | ❌ manquée | – |
| `sysmon_1_11_exec_as_system_via_schedtask.evtx` | ❌ manquée | – |
| `sysmon_1_13_11_cmstp_ini_uacbypass.evtx` | ❌ manquée | – |
| `sysmon_1_13_UACBypass_AppPath_Control.evtx` | ❌ manquée | – |
| `sysmon_1_7_11_mcx2prov_uacbypass.evtx` | ❌ manquée | – |
| `sysmon_1_7_11_migwiz.evtx` | ❌ manquée | – |
| `sysmon_1_7_11_sysprep_uacbypass.evtx` | ❌ manquée | – |
| `sysmon_1_7_elevate_uacbypass_sysprep.evtx` | ❌ manquée | – |
| `sysmon_privesc_from_admin_to_system_handle_inheritance.evtx` | ❌ manquée | – |
| `sysmon_privesc_psexec_dwell.evtx` | ❌ manquée | – |
| `sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.evtx` | ❌ manquée | – |
| `win10_4703_SeDebugPrivilege_enabled.evtx` | ⚪ hors périmètre | – |

</details>

<details><summary><b>(sans tactique)</b> : 17 enregistrements (🟡 5 · ❌ 5 · ⚪ 7)</summary>

| Enregistrement | Verdict | Règles déclenchées |
|---|---|---|
| `AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` | 🟡 signalée | `SYSMON_RUN_KEY` |
| `AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx` | ❌ manquée | – |
| `AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx` | ❌ manquée | – |
| `AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx` | 🟡 signalée | `SYSMON_RUN_KEY` |
| `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` | 🟡 signalée | `SYSMON_OFFICE_SHELL` |
| `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` | 🟡 signalée | `SYSMON_INFECTION_CHAIN`, `SYSMON_LOLBIN_DOWNLOAD`, `SYSMON_LOLBIN_NETWORK`, `SYSMON_LSASS_ACCESS`, `SYSMON_RUN_KEY` |
| `AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx` | ⚪ hors périmètre | – |
| `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` | 🟡 signalée | `SYSMON_LOLBIN_DOWNLOAD`, `SYSMON_LOLBIN_NETWORK` |
| `Other/emotet/exec_emotet_ps_4104.evtx` | ⚪ hors périmètre | – |
| `Other/emotet/exec_emotet_ps_800_get-item.evtx` | ⚪ hors périmètre | – |
| `Other/emotet/exec_emotet_ps_800_invoke-item.evtx` | ⚪ hors périmètre | – |
| `Other/emotet/exec_emotet_ps_800_new-item.evtx` | ⚪ hors périmètre | – |
| `Other/emotet/exec_emotet_ps_800_new-object.evtx` | ⚪ hors périmètre | – |
| `Other/emotet/exec_emotet_sysmon_1.evtx` | ❌ manquée | – |
| `Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx` | ❌ manquée | – |
| `Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.evtx` | ⚪ hors périmètre | – |
| `UACME_59_Sysmon.evtx` | ❌ manquée | – |

</details>

## Méthode

- Chaque enregistrement est lu par le lecteur `.evtx` de mini-SIEM (celui de la ligne de commande), puis passé seul dans toutes les règles, corrélations comprises.
- Le verdict compare la tactique des alertes au dossier où l'auteur a rangé l'enregistrement. Depuis ATT&CK v19, « Defense Evasion » correspond à Stealth ou Defense Impairment.
- Artefact de capture : dans 23 enregistrements, le premier événement est l'effacement du journal de sécurité (1102) fait juste avant la capture. Il est retiré, sinon la règle `WIN_LOG_CLEARED` « détecterait » ces fichiers sans rien voir de l'attaque. Il est gardé quand l'effacement est l'attaque enregistrée (nom de fichier contenant 1102).
- **Ce n'est pas un test à l'aveugle.** Ces enregistrements ont déjà servi à repérer des manques (la règle `SYSMON_COMSVCS_MINIDUMP` vient de là). Une règle écrite pour un fichier précis ferait monter le chiffre sans rien améliorer ailleurs : le tableau sert à suivre l'évolution et à voir ce qui passe, pas à annoncer un taux de détection réel.

Pour régénérer ce fichier :

```
python attack_coverage.py --fetch /tmp/evtx-attack-samples --markdown COVERAGE.md --readme README.md
```
