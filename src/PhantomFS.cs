// PhantomFS.cs
// ProjFS-based honeypot provider — projects synthetic credential, key, and document
// files into a virtual directory, then alerts via Windows Event Log and Toast
// notifications whenever a monitored file is opened or its content is read.
//
// ----------------------------------------------------------------------------
// MIT License
// Copyright (c) 2026 Alloy Secure
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// Trademark Notice: PhantomFS(TM) is a trademark of Alloy Secure. The MIT license
// grants rights to this source code only \u2014 it does not grant the right to use
// the PhantomFS name, logo, or branding in a manner that implies endorsement
// or competes with the original product.
//
// DISCLAIMER: This software is provided for lawful defensive security purposes
// only. You are solely responsible for ensuring your use complies with all
// applicable laws. The authors accept no liability for any damages arising
// from use or misuse of this software. USE AT YOUR OWN RISK.
// ----------------------------------------------------------------------------
//
// \u2500\u2500 PREREQUISITES \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//   Windows 10 v1809 (Build 17763) or later with ProjFS enabled.
//   Run once in an elevated PowerShell to enable the optional feature:
//     Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart
//
// \u2500\u2500 COMPILE \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//   csc.exe /platform:x64 /r:System.Xml.dll /out:PhantomFS.exe PhantomFS.cs
//   (csc.exe lives at C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe)
//
// \u2500\u2500 RUN (Administrator required) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//   Synthetic-only (recommended \u2014 no real source folder needed):
//     PhantomFS.exe --virtroot C:\Honeypot --syntheticonly
//
//   Mixed \u2014 real files plus synthetic entries:
//     PhantomFS.exe --virtroot C:\Honeypot --sourceroot C:\RealFiles
//
// \u2500\u2500 CONFIGURATION \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//   PhantomFS.exe.config  (same directory as the exe)
//     <settings>           \u2014 alerting, logging, cleanup, and path options
//     <syntheticFileList>  \u2014 virtual file tree (paths, sizes, timestamps)
//     <syntheticTemplates> \u2014 content returned when files are opened
//   Edit and restart; no recompile needed.
//
// \u2500\u2500 VERSION \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//   1.0.0  Initial release \u2014 ProjFS honeypot with Event Log and Toast alerts.
//   1.1.0  Auto-cleanup of materialized synthetic files after configurable
//          delay.  Remote session logging \u2014 captures SMB username and source
//          address when a honeypot file is accessed over a network share.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Xml;
using Synthetic;

// =============================================================================
// Synthetic virtual file system \u2014 namespace: Synthetic
// =============================================================================

namespace Synthetic
{
    // -------------------------------------------------------------------------
    // PhantomFSSettings \u2014 reads <settings> from <exe>.exe.config at startup.
    // All properties fall back to safe defaults when the section is absent,
    // so v1.0.0 config files continue to work without modification.
    // -------------------------------------------------------------------------
    internal static class PhantomFSSettings
    {
        public static bool   EnableEventLog         = true;
        public static bool   EnableToast            = true;
        public static bool   AlertOnOpen            = true;   // placeholder created
        public static bool   AlertOnRead            = true;   // content read
        public static int    ToastCooldownSeconds   = 15;
        public static bool   Verbose                = false;
        public static string ConfigVirtRoot         = null;
        public static string ConfigSourceRoot       = null;
        public static bool   ConfigSyntheticOnly    = false;

        // v1.1.0 \u2014 auto-cleanup of materialized synthetic placeholders.
        // Both keys are optional; defaults ensure backwards compatibility.
        public static bool   AutoCleanupEnabled      = true;
        public static int    AutoCleanupDelaySeconds = 300;   // 5 minutes

        // v1.1.0 \u2014 DNS reverse-lookup of the SMB client hostname.
        // Set to false if the lookup latency is unacceptable in your environment.
        public static bool   ResolveRemoteIPs        = true;

        public static void Load(string configPath)
        {
            if (!File.Exists(configPath)) return;
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(configPath);

                EnableEventLog       = ReadBool  (doc, "/configuration/settings/enableEventLog",       true);
                EnableToast          = ReadBool  (doc, "/configuration/settings/enableToast",          true);
                AlertOnOpen          = ReadBool  (doc, "/configuration/settings/alertOnOpen",          true);
                AlertOnRead          = ReadBool  (doc, "/configuration/settings/alertOnRead",          true);
                Verbose              = ReadBool  (doc, "/configuration/settings/verbose",              false);
                ConfigSyntheticOnly  = ReadBool  (doc, "/configuration/settings/syntheticOnly",        false);
                ToastCooldownSeconds = ReadInt   (doc, "/configuration/settings/toastCooldownSeconds", 15);
                ConfigVirtRoot       = ReadString(doc, "/configuration/settings/virtRoot");
                ConfigSourceRoot     = ReadString(doc, "/configuration/settings/sourceRoot");

                // v1.1.0 keys \u2014 safe defaults keep v1.0.0 configs working unchanged
                AutoCleanupEnabled      = ReadBool(doc, "/configuration/settings/autoCleanupEnabled",      true);
                AutoCleanupDelaySeconds = ReadInt (doc, "/configuration/settings/autoCleanupDelaySeconds", 300);
                ResolveRemoteIPs        = ReadBool(doc, "/configuration/settings/resolveRemoteIPs",        true);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] Could not load <settings> from config \u2014 " + ex.Message);
            }
        }

        private static bool ReadBool(XmlDocument d, string xpath, bool def)
        {
            XmlNode n = d.SelectSingleNode(xpath);
            if (n == null) return def;
            bool v; return bool.TryParse(n.InnerText.Trim(), out v) ? v : def;
        }

        private static int ReadInt(XmlDocument d, string xpath, int def)
        {
            XmlNode n = d.SelectSingleNode(xpath);
            if (n == null) return def;
            int v; return int.TryParse(n.InnerText.Trim(), out v) ? v : def;
        }

        private static string ReadString(XmlDocument d, string xpath)
        {
            XmlNode n = d.SelectSingleNode(xpath);
            if (n == null) return null;
            string s = n.InnerText.Trim();
            return string.IsNullOrEmpty(s) ? null : s;
        }
    }

    // -------------------------------------------------------------------------
    // AlertManager \u2014 writes to Windows Event Log and sends Toast notifications
    // when honeypot files are accessed.  All public methods are thread-safe.
    // -------------------------------------------------------------------------
    internal static class AlertManager
    {
        private const string SourceName   = "PhantomFS";
        private const string LogName      = "Application";

        public const int EvtFileRead        = 1001;
        public const int EvtFilePlaceholder = 1002;
        public const int EvtStarted         = 1003;
        public const int EvtStopped         = 1004;

        private static readonly ConcurrentDictionary<string, DateTime> _lastToast
            = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        private static bool _logReady;

        // Call once from Program.Main \u2014 registers the EventLog source (admin required).
        public static void Initialize()
        {
            if (!PhantomFSSettings.EnableEventLog) return;
            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    EventLog.CreateEventSource(SourceName, LogName);
                    Console.WriteLine("  EventLog source registered: " + SourceName);
                }
                _logReady = true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] EventLog source registration failed \u2014 " + ex.Message);
            }
        }

        public static void OnProviderStarted(string virtRoot)
        {
            WriteLog(
                "PhantomFS \u2014 Provider Started\r\n"
              + "VirtRoot : " + virtRoot + "\r\n"
              + "EventLog : " + PhantomFSSettings.EnableEventLog
              + "  Toast : "  + PhantomFSSettings.EnableToast + "\r\n"
              + "Cleanup  : " + (PhantomFSSettings.AutoCleanupEnabled
                    ? "enabled (" + PhantomFSSettings.AutoCleanupDelaySeconds + "s)"
                    : "disabled"),
                EventLogEntryType.Information, EvtStarted);
        }

        public static void OnProviderStopped(string virtRoot)
        {
            WriteLog("PhantomFS \u2014 Provider Stopped\r\nVirtRoot: " + virtRoot,
                EventLogEntryType.Information, EvtStopped);
        }

        // Fires when a process first opens a honeypot file (placeholder created).
        // sessions is non-null when the access originated from an SMB client.
        public static void OnPlaceholderCreated(string path, string proc, uint pid,
            List<RemoteSessionHelper.SessionInfo> sessions)
        {
            if (!PhantomFSSettings.AlertOnOpen) return;

            string sessionStr = RemoteSessionHelper.FormatSessions(sessions);
            string msg = "PhantomFS \u2014 Honeypot File Opened\r\n"
                       + "File    : " + path + "\r\n"
                       + "Process : " + Proc(proc, pid)
                       + sessionStr;

            bool   isRemote = sessions != null && sessions.Count > 0;
            string remTag   = isRemote ? "  [REMOTE]" : string.Empty;
            Console.WriteLine("[ALERT:OPEN]  " + path + " \u2014 " + Proc(proc, pid) + remTag);
            WriteLog(msg, EventLogEntryType.Warning, EvtFilePlaceholder);
            // Toast deferred to OnFileAccessed \u2014 content read is the stronger signal.
        }

        // Fires when a process reads content from a honeypot file.
        // This is the primary alert trigger and sends both log entry and Toast.
        // sessions is non-null when the access originated from an SMB client.
        public static void OnFileAccessed(string path, uint pid, string proc,
            List<RemoteSessionHelper.SessionInfo> sessions)
        {
            if (!PhantomFSSettings.AlertOnRead) return;

            string sessionStr = RemoteSessionHelper.FormatSessions(sessions);
            string msg = "PhantomFS \u2014 Honeypot File Content Read\r\n"
                       + "File    : " + path + "\r\n"
                       + "Process : " + Proc(proc, pid)
                       + sessionStr;

            bool   isRemote = sessions != null && sessions.Count > 0;
            string remTag   = isRemote ? "  [REMOTE]" : string.Empty;
            Console.WriteLine("[ALERT:READ]  " + path + " \u2014 " + Proc(proc, pid) + remTag);
            WriteLog(msg, EventLogEntryType.Warning, EvtFileRead);

            if (PhantomFSSettings.EnableToast && CooldownExpired(path))
            {
                string toastTitle = "PhantomFS \u2014 Honeypot File Accessed";
                string toastBody;

                if (isRemote)
                {
                    // Include SMB user and source address in the Toast body.
                    RemoteSessionHelper.SessionInfo first = sessions[0];
                    toastBody = path + "\r\n"
                              + "User: " + first.UserName
                              + "  From: " + first.ClientName
                              + (string.IsNullOrEmpty(first.ClientIP)
                                    ? string.Empty
                                    : "  [" + first.ClientIP + "]");
                }
                else
                {
                    toastBody = path + "  (" + Proc(proc, pid) + ")";
                }

                SendToast(toastTitle, toastBody);
            }
        }

        // ---- Private helpers ----

        private static string Proc(string name, uint pid)
        {
            return string.IsNullOrEmpty(name) ? "PID " + pid : name + " (PID " + pid + ")";
        }

        private static bool CooldownExpired(string key)
        {
            DateTime now = DateTime.UtcNow;
            TimeSpan cd  = TimeSpan.FromSeconds(PhantomFSSettings.ToastCooldownSeconds);
            DateTime last;
            if (_lastToast.TryGetValue(key, out last) && (now - last) < cd) return false;
            _lastToast[key] = now;
            return true;
        }

        private static void WriteLog(string msg, EventLogEntryType type, int id)
        {
            if (!_logReady || !PhantomFSSettings.EnableEventLog) return;
            try { EventLog.WriteEntry(SourceName, msg, type, id); }
            catch (Exception ex) { Console.Error.WriteLine("[WARN] EventLog write failed \u2014 " + ex.Message); }
        }

        // Sends a Windows Toast notification by launching a hidden PowerShell process.
        // Uses the Windows PowerShell AUMID \u2014 a standard technique for desktop apps
        // that have not registered their own AppUserModelId.
        // The script is Base64-encoded (-EncodedCommand) to avoid quoting pitfalls.
        private static void SendToast(string title, string body)
        {
            string safeTitle = XmlEsc(title);
            string safeBody  = XmlEsc(body);

            // AUMID for Windows PowerShell \u2014 works on all Windows 10/11 installs.
            string aumid = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
                         + "\\WindowsPowerShell\\v1.0\\powershell.exe";

            string toastXml = "<toast>"
                            + "<visual><binding template=\"ToastGeneric\">"
                            + "<text>" + safeTitle + "</text>"
                            + "<text>" + safeBody  + "</text>"
                            + "</binding></visual>"
                            + "</toast>";

            string script = string.Concat(
                "[void][Windows.UI.Notifications.ToastNotificationManager,",
                    " Windows.UI.Notifications, ContentType=WindowsRuntime];",
                "[void][Windows.Data.Xml.Dom.XmlDocument,",
                    " Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime];",
                "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;",
                "$x.LoadXml('", toastXml.Replace("'", "''"), "');",
                "$t=New-Object Windows.UI.Notifications.ToastNotification $x;",
                "$n=[Windows.UI.Notifications.ToastNotificationManager]",
                      "::CreateToastNotifier('", aumid.Replace("'", "''"), "');",
                "$n.Show($t)"
            );

            try
            {
                byte[] bytes = Encoding.Unicode.GetBytes(script);
                string b64   = Convert.ToBase64String(bytes);

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName               = "powershell.exe";
                psi.Arguments              = "-NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand " + b64;
                psi.UseShellExecute        = false;
                psi.CreateNoWindow         = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] Toast notification failed \u2014 " + ex.Message);
            }
        }

        private static string XmlEsc(string s)
        {
            if (s == null) return string.Empty;
            return s.Replace("&", "&amp;")
                    .Replace("<", "&lt;")
                    .Replace(">", "&gt;")
                    .Replace("\"", "&quot;")
                    .Replace("'", "&apos;");
        }
    }

    // -------------------------------------------------------------------------
    // RemoteSessionHelper \u2014 detects SMB/network file access and enumerates
    // active sessions via NetSessionEnum to capture the remote username and
    // source address.
    //
    // Detection heuristic: ProjFS reports PID 4 (the Windows System process)
    // as the triggering process when the file access originates from the SMB
    // kernel driver (srv2.sys).  An empty process image name is treated the
    // same way.
    //
    // NetSessionEnum requires the Server service to be running (it is by
    // default whenever a share is active).  The call is a fast local RPC;
    // DNS resolution is the only potentially slow operation and can be
    // disabled via resolveRemoteIPs=false in the config.
    // -------------------------------------------------------------------------
    internal static class RemoteSessionHelper
    {
        public sealed class SessionInfo
        {
            public string UserName;
            public string ClientName;   // hostname / NetBIOS name as reported by SMB
            public string ClientIP;     // DNS-resolved IP, or empty when resolution
                                        // fails or resolveRemoteIPs is false
        }

        // SESSION_INFO_10 \u2014 x64 layout:
        //   offset  0  LMSTR sesi10_cname     (8-byte pointer)
        //   offset  8  LMSTR sesi10_username  (8-byte pointer)
        //   offset 16  DWORD sesi10_time      (4 bytes)
        //   offset 20  DWORD sesi10_idle_time (4 bytes)
        [StructLayout(LayoutKind.Sequential)]
        private struct SESSION_INFO_10
        {
            public IntPtr ClientNamePtr;
            public IntPtr UserNamePtr;
            public uint   Time;
            public uint   IdleTime;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetSessionEnum(
            string serverName, string uncClientName, string userName,
            int level, out IntPtr bufPtr, int prefMaxLen,
            out int entriesRead, out int totalEntries, ref int resumeHandle);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        private const int ERROR_MORE_DATA = 234;

        // Returns true when the triggering process is likely the SMB kernel driver.
        // PID 4 = Windows System process; an empty image path also signals a
        // kernel-mode caller.
        public static bool IsLikelyRemote(uint pid, string procName)
        {
            if (pid == 4) return true;
            if (string.IsNullOrEmpty(procName)) return true;
            return false;
        }

        // Enumerates active SMB sessions on this host.
        // Returns an empty list when no sessions are open or when the Server
        // service is unavailable.  Partial results are returned if the buffer
        // fills before all sessions are read (unlikely in practice).
        public static List<SessionInfo> GetActiveSessions()
        {
            List<SessionInfo> result = new List<SessionInfo>();
            IntPtr buf       = IntPtr.Zero;
            int resumeHandle = 0;

            try
            {
                int entriesRead, totalEntries;
                int hr = NetSessionEnum(
                    null, null, null, 10,
                    out buf, -1,
                    out entriesRead, out totalEntries,
                    ref resumeHandle);

                // hr == 0 is NERR_Success; 234 is ERROR_MORE_DATA (partial results).
                // Both are usable \u2014 anything else indicates a real failure.
                if (hr != 0 && hr != ERROR_MORE_DATA)
                    return result;
                if (buf == IntPtr.Zero || entriesRead == 0)
                    return result;

                int sz = Marshal.SizeOf(typeof(SESSION_INFO_10));
                for (int i = 0; i < entriesRead; i++)
                {
                    SESSION_INFO_10 s = (SESSION_INFO_10)Marshal.PtrToStructure(
                        IntPtr.Add(buf, i * sz), typeof(SESSION_INFO_10));

                    string clientName = s.ClientNamePtr != IntPtr.Zero
                        ? (Marshal.PtrToStringUni(s.ClientNamePtr) ?? string.Empty)
                        : string.Empty;
                    string userName = s.UserNamePtr != IntPtr.Zero
                        ? (Marshal.PtrToStringUni(s.UserNamePtr) ?? string.Empty)
                        : string.Empty;

                    // SMB reports the client as \\hostname; strip the leading backslashes.
                    string cleanClient = clientName.TrimStart('\\');

                    SessionInfo si = new SessionInfo();
                    si.UserName   = userName;
                    si.ClientName = cleanClient;
                    si.ClientIP   = PhantomFSSettings.ResolveRemoteIPs
                        ? ResolveToIP(cleanClient)
                        : string.Empty;
                    result.Add(si);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] NetSessionEnum \u2014 " + ex.Message);
            }
            finally
            {
                if (buf != IntPtr.Zero)
                    try { NetApiBufferFree(buf); } catch { }
            }
            return result;
        }

        // Attempts to resolve a hostname to an IP address string.
        // Returns the input unchanged if it is already an IP, or an empty string
        // if DNS resolution fails.
        private static string ResolveToIP(string hostName)
        {
            if (string.IsNullOrEmpty(hostName)) return string.Empty;
            IPAddress addr;
            if (IPAddress.TryParse(hostName, out addr)) return hostName;
            try
            {
                IPAddress[] addrs = Dns.GetHostAddresses(hostName);
                if (addrs.Length > 0) return addrs[0].ToString();
            }
            catch { }
            return string.Empty;
        }

        // Formats a session list for inclusion in Event Log messages.
        // Returns an empty string when the list is null or empty.
        public static string FormatSessions(List<SessionInfo> sessions)
        {
            if (sessions == null || sessions.Count == 0) return string.Empty;
            StringBuilder sb = new StringBuilder();
            foreach (SessionInfo s in sessions)
            {
                sb.Append("\r\nRemote  : ").Append(s.UserName);
                if (!string.IsNullOrEmpty(s.ClientName))
                    sb.Append(" @ ").Append(s.ClientName);
                if (!string.IsNullOrEmpty(s.ClientIP)
                    && !string.Equals(s.ClientIP, s.ClientName,
                            StringComparison.OrdinalIgnoreCase))
                    sb.Append("  [").Append(s.ClientIP).Append("]");
            }
            return sb.ToString();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticEntry \u2014 one parsed row from <syntheticFileList>.
    // RelativePath uses backslash separators with no leading backslash.
    // -------------------------------------------------------------------------
    internal sealed class SyntheticEntry
    {
        public string RelativePath;   // "AWS\credentials"
        public string Name;           // "credentials"
        public string ParentPath;     // "AWS"  (empty = root)
        public bool   IsDirectory;
        public long   FileSize;
        public long   UnixTimestamp;

        public long GetFiletime()
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds((double)UnixTimestamp).ToFileTime();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticData \u2014 loads and indexes the virtual file tree from the config.
    //
    // Line format:  \Path\To\Entry,isDirectory,fileSize,unixTimestamp
    // -------------------------------------------------------------------------
    internal sealed class SyntheticData
    {
        private readonly Dictionary<string, SyntheticEntry>       _byPath;
        private readonly Dictionary<string, List<SyntheticEntry>> _byParent;

        private SyntheticData()
        {
            _byPath   = new Dictionary<string, SyntheticEntry>(StringComparer.OrdinalIgnoreCase);
            _byParent = new Dictionary<string, List<SyntheticEntry>>(StringComparer.OrdinalIgnoreCase);
        }

        public int EntryCount { get { return _byPath.Count; } }

        public static SyntheticData LoadFromConfig(string configPath)
        {
            if (!File.Exists(configPath))
            {
                Console.Error.WriteLine("[WARN] Config not found: " + configPath);
                return null;
            }
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(configPath);

                XmlNode node = doc.SelectSingleNode("/configuration/syntheticFileList");
                if (node == null)
                {
                    Console.Error.WriteLine("[WARN] No <syntheticFileList> in config.");
                    return null;
                }

                string raw = node.InnerText;
                if (string.IsNullOrEmpty(raw.Trim()))
                {
                    Console.Error.WriteLine("[WARN] <syntheticFileList> is empty.");
                    return null;
                }

                return ParseLines(raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.None));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] Could not load file list \u2014 " + ex.Message);
                return null;
            }
        }

        private static SyntheticData ParseLines(string[] lines)
        {
            SyntheticData data = new SyntheticData();
            foreach (string line in lines)
            {
                string t = line.Trim();
                if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;

                string[] parts = t.Split(',');
                if (parts.Length < 4) continue;

                bool isDir; long sz; long ts;
                if (!bool.TryParse(parts[1].Trim(), out isDir)) continue;
                if (!long.TryParse(parts[2].Trim(), out sz))    continue;
                if (!long.TryParse(parts[3].Trim(), out ts))    continue;

                string np = parts[0].Trim().TrimStart('\\');

                SyntheticEntry e = new SyntheticEntry();
                e.RelativePath  = np;
                e.IsDirectory   = isDir;
                e.FileSize      = sz;
                e.UnixTimestamp = ts;

                int sl = np.LastIndexOf('\\');
                if (sl >= 0) { e.Name = np.Substring(sl + 1); e.ParentPath = np.Substring(0, sl); }
                else         { e.Name = np; e.ParentPath = string.Empty; }

                data._byPath[np] = e;

                List<SyntheticEntry> siblings;
                if (!data._byParent.TryGetValue(e.ParentPath, out siblings))
                { siblings = new List<SyntheticEntry>(); data._byParent[e.ParentPath] = siblings; }
                siblings.Add(e);
            }
            return data;
        }

        public SyntheticEntry Find(string relativePath)
        {
            if (relativePath == null) relativePath = string.Empty;
            SyntheticEntry e;
            return _byPath.TryGetValue(relativePath, out e) ? e : null;
        }

        public List<SyntheticEntry> GetChildren(string parent)
        {
            if (parent == null) parent = string.Empty;
            List<SyntheticEntry> r;
            return _byParent.TryGetValue(parent, out r) ? r : new List<SyntheticEntry>();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticContent \u2014 generates plausible file content for synthetic entries.
    //
    // Template types (set via type= attribute on <template> elements):
    //   type="pem"   \u2014 deterministic LCG-generated PEM block sized to fileSize
    //   (CDATA text) \u2014 static text, padded/trimmed to match fileSize
    //
    // Match order:  exact filename match \u2192 file extension \u2192 built-in fallback
    // -------------------------------------------------------------------------
    internal static class SyntheticContent
    {
        private sealed class TemplateEntry
        {
            public bool   IsPem;
            public string PemLabel;
            public string Text;
        }

        private static Dictionary<string, TemplateEntry> _exact;
        private static Dictionary<string, TemplateEntry> _ext;

        public static void LoadFromConfig(string configPath)
        {
            _exact = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);
            _ext   = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(configPath))
            {
                Console.WriteLine("[INFO] Config not found \u2014 synthetic files will return generic text.");
                return;
            }

            int count = 0;
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(configPath);

                XmlNodeList nodes = doc.SelectNodes("/configuration/syntheticTemplates/template");
                if (nodes == null) { Console.WriteLine("[INFO] No <syntheticTemplates> found."); return; }

                foreach (XmlNode node in nodes)
                {
                    string nv  = Attr(node, "name");
                    string ev  = Attr(node, "extension");
                    string tv  = Attr(node, "type");
                    string pv  = Attr(node, "pemLabel");
                    bool   pem = string.Equals(tv, "pem", StringComparison.OrdinalIgnoreCase);

                    TemplateEntry te = new TemplateEntry();
                    te.IsPem    = pem;
                    te.PemLabel = pem && pv != null ? pv : "PRIVATE KEY";
                    te.Text     = pem ? null : (node.InnerText.Trim() + "\n");

                    if      (nv != null) { _exact[nv.ToLowerInvariant()] = te; count++; }
                    else if (ev != null) { _ext  [ev.ToLowerInvariant()] = te; count++; }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[WARN] Could not load templates \u2014 " + ex.Message);
                return;
            }
            Console.WriteLine("  Loaded " + count + " content templates from config.");
        }

        public static byte[] Generate(string fileName, long declaredSize)
        {
            string lower = fileName.ToLowerInvariant();
            string text  = Resolve(lower, declaredSize);
            return FitToSize(Encoding.UTF8.GetBytes(text), declaredSize);
        }

        private static string Resolve(string lower, long size)
        {
            TemplateEntry te;
            if (_exact != null && _exact.TryGetValue(lower, out te)) return Produce(te, size);
            string ext = Path.GetExtension(lower);
            if (!string.IsNullOrEmpty(ext) && _ext != null && _ext.TryGetValue(ext, out te)) return Produce(te, size);
            return "# " + lower + "\n# Synthetic honeypot file \u2014 add a <template> to PhantomFS.exe.config\n";
        }

        private static string Produce(TemplateEntry te, long size)
        {
            return te.IsPem ? PemBlock(te.PemLabel, size) : (te.Text ?? string.Empty);
        }

        private static string PemBlock(string label, long targetSize)
        {
            string hdr  = "-----BEGIN " + label + "-----\n";
            string ftr  = "\n-----END " + label + "-----\n";
            int    body = (int)targetSize - hdr.Length - ftr.Length;
            if (body < 64) body = 64;
            return hdr + FakeBase64(body) + ftr;
        }

        private static string FakeBase64(int approxLen)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int state = unchecked(0x12345678);
            StringBuilder sb = new StringBuilder(approxLen + 80);
            int col = 0;
            while (sb.Length < approxLen)
            {
                state = unchecked(state * 1664525 + 1013904223);
                sb.Append(chars[((state >> 8) & 0x7FFFFFFF) % 64]);
                if (++col == 64) { sb.Append('\n'); col = 0; }
            }
            if (col > 0) sb.Append('\n');
            return sb.ToString();
        }

        private static byte[] FitToSize(byte[] raw, long size)
        {
            if (size <= 0) return new byte[0];
            byte[] r = new byte[(int)size];
            if (raw.Length >= (int)size) { Array.Copy(raw, r, (int)size); }
            else { Array.Copy(raw, r, raw.Length); for (int i = raw.Length; i < (int)size; i++) r[i] = (byte)'\n'; }
            return r;
        }

        private static string Attr(XmlNode n, string name)
        {
            if (n.Attributes == null) return null;
            XmlAttribute a = n.Attributes[name];
            return a != null ? a.Value : null;
        }
    }
}

// =============================================================================
// Unified directory-listing entry \u2014 shared between PhantomFSProvider
// and EnumerationSession (both at the global namespace level).
// =============================================================================

internal struct DirEntry
{
    public string Name;
    public bool   IsSynthetic;
    public bool   IsDirectory;
    public long   FileSize;
    public long   CreationTimeFt;
    public long   LastAccessTimeFt;
    public long   LastWriteTimeFt;
    public uint   FileAttributes;
}

// =============================================================================
// EnumerationSession \u2014 tracks the cursor for a single directory enumeration.
// =============================================================================

internal sealed class EnumerationSession
{
    private readonly DirEntry[] _entries;
    private int _index;

    public EnumerationSession(DirEntry[] entries)
    {
        _entries = entries;
        _index   = 0;
    }

    public void Reset()    { _index = 0; }
    public void StepBack() { if (_index > 0) _index--; }

    public bool TryGetNext(out DirEntry entry)
    {
        if (_index < _entries.Length) { entry = _entries[_index++]; return true; }
        entry = default(DirEntry);
        return false;
    }
}

// =============================================================================
// P/Invoke layer \u2014 ProjectedFSLib.dll
// =============================================================================

internal static class Prj
{
    public const int S_OK                   =  0;
    public const int E_FAIL                 = unchecked((int)0x80004005);
    public const int HR_INSUFFICIENT_BUFFER = unchecked((int)0x8007007A);
    public const int HR_FILE_NOT_FOUND      = unchecked((int)0x80070002);
    public const int HR_PATH_NOT_FOUND      = unchecked((int)0x80070003);
    public const int HR_NOT_A_REPARSE_POINT = unchecked((int)0x80071126);

    public const int FLAG_ENUM_RESTART_SCAN = 0x00000001;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int StartDirEnumCb(IntPtr cbd, IntPtr enumId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int EndDirEnumCb(IntPtr cbd, IntPtr enumId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetDirEnumCb(IntPtr cbd, IntPtr enumId, IntPtr searchExpr, IntPtr dirBuf);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetPlaceholderInfoCb(IntPtr cbd);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetFileDataCb(IntPtr cbd, ulong byteOffset, uint length);

    [StructLayout(LayoutKind.Sequential)]
    public struct Callbacks
    {
        public IntPtr StartDirEnum;
        public IntPtr EndDirEnum;
        public IntPtr GetDirEnum;
        public IntPtr GetPlaceholderInfo;
        public IntPtr GetFileData;
        public IntPtr QueryFileName;
        public IntPtr Notification;
        public IntPtr CancelCommand;
    }

    // PRJ_FILE_BASIC_INFO \u2014 MSVC x64 layout (56 bytes)
    [StructLayout(LayoutKind.Explicit, Size = 56)]
    public struct FileBasicInfo
    {
        [FieldOffset( 0)] public byte IsDirectory;
        [FieldOffset( 8)] public long FileSize;
        [FieldOffset(16)] public long CreationTime;
        [FieldOffset(24)] public long LastAccessTime;
        [FieldOffset(32)] public long LastWriteTime;
        [FieldOffset(40)] public long ChangeTime;
        [FieldOffset(48)] public uint FileAttributes;
    }

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
    public static extern int PrjStartVirtualizing(
        string rootPath, ref Callbacks callbacks,
        IntPtr instanceContext, IntPtr options, out IntPtr virtCtx);

    [DllImport("ProjectedFSLib.dll")]
    public static extern void PrjStopVirtualizing(IntPtr virtCtx);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
    public static extern int PrjMarkDirectoryAsPlaceholder(
        string rootPathName, string targetPathName,
        IntPtr versionInfo, ref Guid virtualizationInstanceID);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
    public static extern int PrjWritePlaceholderInfo(
        IntPtr virtCtx, string destFileName,
        [In] byte[] placeholderInfo, uint placeholderInfoSize);

    [DllImport("ProjectedFSLib.dll")]
    public static extern int PrjWriteFileData(
        IntPtr virtCtx, ref Guid dataStreamId,
        IntPtr buffer, ulong byteOffset, uint length);

    [DllImport("ProjectedFSLib.dll")]
    public static extern IntPtr PrjAllocateAlignedBuffer(IntPtr virtCtx, UIntPtr size);

    [DllImport("ProjectedFSLib.dll")]
    public static extern void PrjFreeAlignedBuffer(IntPtr buffer);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
    public static extern int PrjFillDirEntryBuffer(
        string fileName, ref FileBasicInfo info, IntPtr dirBuf);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PrjFileNameMatch(string fileName, string pattern);

    // PRJ_CALLBACK_DATA field offsets (x64 layout)
    public static int    CbdFlags    (IntPtr c) { return Marshal.ReadInt32(c,  4); }
    public static IntPtr CbdVirtCtx  (IntPtr c) { return Marshal.ReadIntPtr(c, 8); }
    public static string CbdFilePath (IntPtr c) { return PcwstrAt(c, 56); }
    public static uint   CbdTrigPid  (IntPtr c) { return (uint)Marshal.ReadInt32(c, 72); }
    public static string CbdTrigProc (IntPtr c) { return PcwstrAt(c, 80); }

    public static Guid CbdDataStreamId(IntPtr c)
    {
        return (Guid)Marshal.PtrToStructure(IntPtr.Add(c, 36), typeof(Guid));
    }

    public static Guid ReadGuid(IntPtr p)
    {
        return (Guid)Marshal.PtrToStructure(p, typeof(Guid));
    }

    public static string ReadPcwstr(IntPtr p)
    {
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
    }

    // PRJ_PLACEHOLDER_INFO \u2014 344 bytes
    public static byte[] BuildPlaceholderInfo(
        bool isDir, long size,
        long createdFt, long accessFt, long writeFt, long changeFt,
        uint attrs)
    {
        byte[] b = new byte[344];
        b[0] = isDir ? (byte)1 : (byte)0;
        Wi64(b,  8, isDir ? 0L : size);
        Wi64(b, 16, createdFt);
        Wi64(b, 24, accessFt);
        Wi64(b, 32, writeFt);
        Wi64(b, 40, changeFt);
        Wu32(b, 48, attrs);
        return b;
    }

    private static void Wi64(byte[] b, int o, long v) { ulong u=(ulong)v; for(int i=0;i<8;i++) b[o+i]=(byte)(u>>(i*8)); }
    private static void Wu32(byte[] b, int o, uint v) {               for(int i=0;i<4;i++) b[o+i]=(byte)(v>>(i*8)); }

    public static string Hr(int hr)
    {
        switch (hr)
        {
            case S_OK:                   return "S_OK";
            case HR_FILE_NOT_FOUND:      return "FileNotFound";
            case HR_PATH_NOT_FOUND:      return "PathNotFound";
            case HR_INSUFFICIENT_BUFFER: return "InsufficientBuffer";
            case HR_NOT_A_REPARSE_POINT: return "NotAReparsePoint";
            case E_FAIL:                 return "E_FAIL";
            default:                     return "0x" + ((uint)hr).ToString("X8");
        }
    }

    private static string PcwstrAt(IntPtr base_, int offset)
    {
        IntPtr p = Marshal.ReadIntPtr(base_, offset);
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
    }
}

// =============================================================================
// Entry point
// =============================================================================

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.WriteLine();
        Console.WriteLine("  PhantomFS v1.1.0  \u2014  Virtual Honeypot File System");
        Console.WriteLine("  " + new string('\u2500', 50));
        Console.WriteLine();

        // Locate config
        System.Reflection.Assembly asm = System.Reflection.Assembly.GetEntryAssembly();
        string configPath = asm != null
            ? asm.Location + ".config"
            : Path.Combine(Directory.GetCurrentDirectory(), "PhantomFS.exe.config");

        Console.WriteLine("  Config   : " + configPath);

        // Load settings, templates, and file list
        PhantomFSSettings.Load(configPath);
        SyntheticContent.LoadFromConfig(configPath);
        SyntheticData synthetic = SyntheticData.LoadFromConfig(configPath);
        if (synthetic != null)
            Console.WriteLine("  Entries  : " + synthetic.EntryCount + " synthetic files/dirs");

        // Parse CLI args \u2014 override config-embedded paths if supplied
        string sourceRoot    = PhantomFSSettings.ConfigSourceRoot;
        string virtRoot      = PhantomFSSettings.ConfigVirtRoot;
        bool   syntheticOnly = PhantomFSSettings.ConfigSyntheticOnly;

        for (int i = 0; i < args.Length; i++)
        {
            string f = args[i];
            if (f.Equals("--syntheticonly", StringComparison.OrdinalIgnoreCase)) { syntheticOnly = true; continue; }
            if (i + 1 >= args.Length) continue;
            string v = args[i + 1];
            if      (f.Equals("--sourceroot", StringComparison.OrdinalIgnoreCase)) { sourceRoot = v; i++; }
            else if (f.Equals("--virtroot",   StringComparison.OrdinalIgnoreCase)) { virtRoot   = v; i++; }
        }

        if (virtRoot == null)            { PrintUsage(); return 1; }
        if (!syntheticOnly && sourceRoot == null)
        { Console.Error.WriteLine("[ERROR] --sourceroot required unless --syntheticonly"); PrintUsage(); return 1; }
        if (syntheticOnly && synthetic == null)
        { Console.Error.WriteLine("[ERROR] --syntheticonly requires <syntheticFileList> in config"); return 1; }

        // Initialise alert channels
        AlertManager.Initialize();

        // Create and start the provider
        PhantomFSProvider provider;
        try { provider = new PhantomFSProvider(sourceRoot, virtRoot, synthetic, syntheticOnly); }
        catch (Exception ex) { Console.Error.WriteLine("[ERROR] " + ex.Message); return 1; }

        int hr = provider.StartVirtualizing();
        if (hr != Prj.S_OK)
        {
            Console.Error.WriteLine("[ERROR] PrjStartVirtualizing failed: " + Prj.Hr(hr));
            if (hr == Prj.HR_NOT_A_REPARSE_POINT)
                Console.Error.WriteLine("        Run: rmdir /s /q \"" + Path.GetFullPath(virtRoot) + "\"");
            else
                Console.Error.WriteLine("        Ensure Client-ProjFS is enabled and this process is elevated.");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("  \u2611  Provider running.");
        Console.WriteLine("  VirtRoot : " + Path.GetFullPath(virtRoot));
        if (!syntheticOnly) Console.WriteLine("  Source   : " + Path.GetFullPath(sourceRoot));
        Console.WriteLine("  Mode     : " + (syntheticOnly ? "synthetic-only" : "mixed"));
        Console.WriteLine("  EventLog : " + PhantomFSSettings.EnableEventLog
                        + "   Toast : " + PhantomFSSettings.EnableToast);
        Console.WriteLine("  Cleanup  : "
            + (PhantomFSSettings.AutoCleanupEnabled
                ? "enabled \u2014 " + PhantomFSSettings.AutoCleanupDelaySeconds + "s delay"
                : "disabled"));
        Console.WriteLine();
        Console.WriteLine("  Press ENTER to stop\u2026");

        AlertManager.OnProviderStarted(Path.GetFullPath(virtRoot));
        Console.ReadLine();
        AlertManager.OnProviderStopped(Path.GetFullPath(virtRoot));
        provider.StopVirtualizing();
        Console.WriteLine("  PhantomFS stopped.");
        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine("  Usage:");
        Console.WriteLine("    PhantomFS.exe --virtroot <path> [--sourceroot <path>] [--syntheticonly]");
        Console.WriteLine();
        Console.WriteLine("  Options:");
        Console.WriteLine("    --virtroot   <path>   Directory where virtual files appear.");
        Console.WriteLine("    --sourceroot <path>   Real files to mirror alongside synthetic ones.");
        Console.WriteLine("    --syntheticonly       Serve only config-defined synthetic files.");
        Console.WriteLine();
        Console.WriteLine("  Notes:");
        Console.WriteLine("    \u2022 Requires Administrator.");
        Console.WriteLine("    \u2022 Paths can also be set in PhantomFS.exe.config <settings>.");
        Console.WriteLine("    \u2022 Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart");
    }
}

// =============================================================================
// PhantomFSProvider \u2014 ProjFS provider implementation
// =============================================================================

internal sealed class PhantomFSProvider
{
    private readonly string        _sourceRoot;
    private readonly string        _virtRoot;
    private readonly SyntheticData _synthetic;
    private readonly bool          _syntheticOnly;
    private IntPtr                 _virtCtx;

    private readonly ConcurrentDictionary<Guid, EnumerationSession> _sessions
        = new ConcurrentDictionary<Guid, EnumerationSession>();

    // Tracks synthetic files that have been materialized to disk, keyed by
    // their relative path.  The value is the UTC time of first hydration.
    // The cleanup timer reads and removes entries from this dictionary on its
    // own thread \u2014 ConcurrentDictionary ensures thread safety.
    private readonly ConcurrentDictionary<string, DateTime> _materializedFiles
        = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

    private Timer _cleanupTimer;

    private static PhantomFSProvider _current;

    // Delegate fields prevent GC while ProjFS callbacks are active.
    private readonly Prj.StartDirEnumCb       _cbStart;
    private readonly Prj.EndDirEnumCb         _cbEnd;
    private readonly Prj.GetDirEnumCb         _cbEnum;
    private readonly Prj.GetPlaceholderInfoCb _cbPhi;
    private readonly Prj.GetFileDataCb        _cbData;

    public PhantomFSProvider(
        string sourceRoot, string virtRoot,
        SyntheticData synthetic, bool syntheticOnly)
    {
        _syntheticOnly = syntheticOnly;
        _synthetic     = synthetic;
        _virtRoot      = Path.GetFullPath(virtRoot);

        if (syntheticOnly) { _sourceRoot = string.Empty; }
        else
        {
            if (!Directory.Exists(sourceRoot))
                throw new ArgumentException("Source root does not exist: " + sourceRoot);
            _sourceRoot = Path.GetFullPath(sourceRoot);
        }

        Directory.CreateDirectory(_virtRoot);

        _cbStart = StartThunk;
        _cbEnd   = EndThunk;
        _cbEnum  = EnumThunk;
        _cbPhi   = PhiThunk;
        _cbData  = DataThunk;
    }

    public int StartVirtualizing()
    {
        _current = this;

        // Safety check: require explicit confirmation before discarding any existing
        // content. This prevents accidental data loss if --virtroot is mistakenly
        // pointed at a real directory that happens to share the intended path.
        if (Directory.Exists(_virtRoot))
        {
            string[] existing = Directory.GetFileSystemEntries(_virtRoot);
            if (existing.Length > 0)
            {
                Console.WriteLine();
                Console.WriteLine("  [SAFETY] VirtRoot is not empty \u2014 "
                                + existing.Length + " item(s) detected:");
                Console.WriteLine("  " + _virtRoot);
                Console.WriteLine();
                Console.Write("  Permanently delete all contents and continue? [y/N] ");
                string answer = Console.ReadLine();
                if (answer == null ||
                    !answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine("[ABORT] Clear the directory manually and re-run.");
                    return Prj.E_FAIL;
                }
            }

            // Remove stale ProjFS state to prevent HR_NOT_A_REPARSE_POINT.
            Console.WriteLine("  Clearing stale virtroot: " + _virtRoot);
            try { Directory.Delete(_virtRoot, true); }
            catch (Exception ex) { Console.Error.WriteLine("[WARN] " + ex.Message); }
        }
        Directory.CreateDirectory(_virtRoot);

        Guid id = Guid.NewGuid();
        int hr = Prj.PrjMarkDirectoryAsPlaceholder(_virtRoot, null, IntPtr.Zero, ref id);
        if (hr != Prj.S_OK) { Console.Error.WriteLine("[ERROR] PrjMark: " + Prj.Hr(hr)); return hr; }

        Prj.Callbacks cbs = new Prj.Callbacks();
        cbs.StartDirEnum       = Marshal.GetFunctionPointerForDelegate(_cbStart);
        cbs.EndDirEnum         = Marshal.GetFunctionPointerForDelegate(_cbEnd);
        cbs.GetDirEnum         = Marshal.GetFunctionPointerForDelegate(_cbEnum);
        cbs.GetPlaceholderInfo = Marshal.GetFunctionPointerForDelegate(_cbPhi);
        cbs.GetFileData        = Marshal.GetFunctionPointerForDelegate(_cbData);

        int startHr = Prj.PrjStartVirtualizing(_virtRoot, ref cbs, IntPtr.Zero, IntPtr.Zero, out _virtCtx);

        if (startHr == Prj.S_OK && PhantomFSSettings.AutoCleanupEnabled)
        {
            // Check every 30 seconds; delete files older than AutoCleanupDelaySeconds.
            _cleanupTimer = new Timer(
                CleanupCallback, null,
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));
            Log("[CLEANUP] Timer started \u2014 delay=" + PhantomFSSettings.AutoCleanupDelaySeconds + "s");
        }

        return startHr;
    }

    public void StopVirtualizing()
    {
        if (_cleanupTimer != null)
        {
            _cleanupTimer.Dispose();
            _cleanupTimer = null;
        }
        if (_virtCtx == IntPtr.Zero) return;
        Prj.PrjStopVirtualizing(_virtCtx);
        _virtCtx = IntPtr.Zero;
    }

    // ---- Auto-cleanup callback ----

    // Runs on a thread-pool thread every 30 seconds.
    // Deletes any hydrated synthetic placeholder whose materialization time
    // exceeds AutoCleanupDelaySeconds, reverting it back to a virtual file.
    // The next access will trigger a fresh GetFileData callback as normal.
    // Files that are still open (locked) are skipped silently and retried
    // on the next cycle.
    private void CleanupCallback(object state)
    {
        if (!PhantomFSSettings.AutoCleanupEnabled) return;
        TimeSpan threshold = TimeSpan.FromSeconds(PhantomFSSettings.AutoCleanupDelaySeconds);
        DateTime now       = DateTime.UtcNow;

        foreach (KeyValuePair<string, DateTime> kvp in _materializedFiles)
        {
            if ((now - kvp.Value) < threshold) continue;

            string fullPath = Path.Combine(_virtRoot, kvp.Key);
            try
            {
                if (File.Exists(fullPath))
                {
                    File.Delete(fullPath);
                    Log("[CLEANUP] Reverted placeholder: " + kvp.Key);
                }
                DateTime dummy;
                _materializedFiles.TryRemove(kvp.Key, out dummy);
            }
            catch (Exception ex)
            {
                // File is likely still open \u2014 leave in the dictionary and retry next cycle.
                Log("[CLEANUP] Skipped (in use): " + kvp.Key + " \u2014 " + ex.Message);
            }
        }
    }

    // ---- Static thunks ----
    private static int StartThunk(IntPtr c, IntPtr e) { try { return _current.OnStart(c, e); } catch { return Prj.E_FAIL; } }
    private static int EndThunk  (IntPtr c, IntPtr e) { try { return _current.OnEnd  (c, e); } catch { return Prj.E_FAIL; } }
    private static int EnumThunk (IntPtr c, IntPtr e, IntPtr s, IntPtr b) { try { return _current.OnEnum(c,e,s,b); } catch { return Prj.E_FAIL; } }
    private static int PhiThunk  (IntPtr c)           { try { return _current.OnPhi  (c);    } catch { return Prj.E_FAIL; } }
    private static int DataThunk (IntPtr c, ulong o, uint l) { try { return _current.OnData(c,o,l); } catch { return Prj.E_FAIL; } }

    // ---- Callback implementations ----

    private int OnStart(IntPtr cbd, IntPtr enumIdPtr)
    {
        string rel = Prj.CbdFilePath(cbd) ?? string.Empty;
        Log("StartEnum [" + rel + "]");

        List<DirEntry> all = new List<DirEntry>();

        if (!_syntheticOnly)
        {
            string full = SrcPath(rel);
            if (Directory.Exists(full))
            {
                try { foreach (FileSystemInfo fsi in new DirectoryInfo(full).GetFileSystemInfos()) all.Add(RealEntry(fsi)); }
                catch (Exception ex) { Log("[WARN] " + ex.Message); }
            }
        }

        if (_synthetic != null)
            foreach (SyntheticEntry s in _synthetic.GetChildren(rel))
                if (!NameExists(all, s.Name)) all.Add(SynthEntry(s));

        all.Sort(delegate(DirEntry a, DirEntry b)
        { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });

        _sessions[Prj.ReadGuid(enumIdPtr)] = new EnumerationSession(all.ToArray());
        return Prj.S_OK;
    }

    private int OnEnd(IntPtr cbd, IntPtr enumIdPtr)
    {
        EnumerationSession rm; _sessions.TryRemove(Prj.ReadGuid(enumIdPtr), out rm);
        return Prj.S_OK;
    }

    private int OnEnum(IntPtr cbd, IntPtr enumIdPtr, IntPtr sePtr, IntPtr dirBuf)
    {
        string filter = Prj.ReadPcwstr(sePtr) ?? string.Empty;
        Guid   id     = Prj.ReadGuid(enumIdPtr);

        EnumerationSession session;
        if (!_sessions.TryGetValue(id, out session)) return Prj.E_FAIL;
        if ((Prj.CbdFlags(cbd) & Prj.FLAG_ENUM_RESTART_SCAN) != 0) session.Reset();

        DirEntry e;
        while (session.TryGetNext(out e))
        {
            if (!string.IsNullOrEmpty(filter) && !Prj.PrjFileNameMatch(e.Name, filter)) continue;

            Prj.FileBasicInfo fi = new Prj.FileBasicInfo();
            fi.IsDirectory    = e.IsDirectory ? (byte)1 : (byte)0;
            fi.FileSize       = e.FileSize;
            fi.CreationTime   = e.CreationTimeFt;
            fi.LastAccessTime = e.LastAccessTimeFt;
            fi.LastWriteTime  = e.LastWriteTimeFt;
            fi.ChangeTime     = e.LastWriteTimeFt;
            fi.FileAttributes = e.FileAttributes;

            int hr = Prj.PrjFillDirEntryBuffer(e.Name, ref fi, dirBuf);
            if (hr == Prj.HR_INSUFFICIENT_BUFFER) { session.StepBack(); break; }
            if (hr != Prj.S_OK) return hr;
        }
        return Prj.S_OK;
    }

    private int OnPhi(IntPtr cbd)
    {
        string rel   = Prj.CbdFilePath(cbd) ?? string.Empty;
        string proc  = Prj.CbdTrigProc(cbd);
        uint   pid   = Prj.CbdTrigPid(cbd);
        IntPtr vCtx  = Prj.CbdVirtCtx(cbd);

        Log("GetPlaceholderInfo [" + rel + "] proc=" + proc + " pid=" + pid);

        // Detect SMB/network access \u2014 PID 4 is the Windows System process, which
        // is the triggering PID when the kernel SMB driver (srv2.sys) opens a file.
        List<RemoteSessionHelper.SessionInfo> sessions = null;
        if (RemoteSessionHelper.IsLikelyRemote(pid, proc))
            sessions = RemoteSessionHelper.GetActiveSessions();

        // \u2500\u2500 Real source \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (!_syntheticOnly)
        {
            FileSystemInfo fsi = SrcFsi(SrcPath(rel));
            if (fsi != null)
            {
                bool   isDir = (fsi.Attributes & FileAttributes.Directory) != 0;
                long   sz    = isDir ? 0L : ((FileInfo)fsi).Length;
                byte[] ph    = Prj.BuildPlaceholderInfo(isDir, sz,
                    fsi.CreationTime.ToFileTime(), fsi.LastAccessTime.ToFileTime(),
                    fsi.LastWriteTime.ToFileTime(), fsi.LastWriteTime.ToFileTime(),
                    (uint)fsi.Attributes & 0xFFFF);
                int hr2 = Prj.PrjWritePlaceholderInfo(vCtx, rel, ph, (uint)ph.Length);
                Log("Phi(real) " + Prj.Hr(hr2));
                return hr2;
            }
        }

        // \u2500\u2500 Synthetic \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (_synthetic != null)
        {
            SyntheticEntry s = _synthetic.Find(rel);
            if (s != null)
            {
                long   ft   = s.GetFiletime();
                byte[] ph   = Prj.BuildPlaceholderInfo(s.IsDirectory,
                    s.IsDirectory ? 0L : s.FileSize,
                    ft, ft, ft, ft, s.IsDirectory ? 0x10u : 0x20u);

                int hr2 = Prj.PrjWritePlaceholderInfo(vCtx, rel, ph, (uint)ph.Length);
                if (hr2 == Prj.S_OK && !s.IsDirectory)
                    AlertManager.OnPlaceholderCreated(rel, proc, pid, sessions);

                Log("Phi(synthetic) " + Prj.Hr(hr2));
                return hr2;
            }
        }

        return Prj.HR_FILE_NOT_FOUND;
    }

    private int OnData(IntPtr cbd, ulong byteOffset, uint length)
    {
        string rel  = Prj.CbdFilePath(cbd) ?? string.Empty;
        string proc = Prj.CbdTrigProc(cbd);
        uint   pid  = Prj.CbdTrigPid(cbd);
        IntPtr vCtx = Prj.CbdVirtCtx(cbd);
        Guid   sid  = Prj.CbdDataStreamId(cbd);

        Log("GetFileData [" + rel + "] offset=" + byteOffset + " len=" + length);

        // Detect SMB/network access \u2014 PID 4 indicates the kernel SMB driver.
        List<RemoteSessionHelper.SessionInfo> sessions = null;
        if (RemoteSessionHelper.IsLikelyRemote(pid, proc))
            sessions = RemoteSessionHelper.GetActiveSessions();

        // PRIMARY ALERT \u2014 a process is reading honeypot file content
        AlertManager.OnFileAccessed(rel, pid, proc, sessions);

        // \u2500\u2500 Real source \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (!_syntheticOnly)
        {
            string full = SrcPath(rel);
            if (File.Exists(full))
            {
                byte[] data;
                try { data = File.ReadAllBytes(full); }
                catch (Exception ex) { Log("[WARN] Read error \u2014 " + ex.Message); return Prj.E_FAIL; }
                return WriteData(vCtx, ref sid, data, byteOffset, length);
            }
        }

        // \u2500\u2500 Synthetic content \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (_synthetic != null)
        {
            SyntheticEntry s = _synthetic.Find(rel);
            if (s != null && !s.IsDirectory)
            {
                int writeHr = WriteData(vCtx, ref sid,
                    SyntheticContent.Generate(s.Name, s.FileSize),
                    byteOffset, length);

                // Record the materialization time so the cleanup timer can revert
                // this file back to a virtual placeholder after the configured delay.
                // TryAdd is a no-op if the key already exists \u2014 we only want the
                // time of first hydration, not the most recent partial read.
                if (writeHr == Prj.S_OK && PhantomFSSettings.AutoCleanupEnabled)
                    _materializedFiles.TryAdd(rel, DateTime.UtcNow);

                return writeHr;
            }
        }

        return Prj.HR_FILE_NOT_FOUND;
    }

    private int WriteData(IntPtr vCtx, ref Guid sid, byte[] data, ulong byteOffset, uint length)
    {
        uint off   = (uint)byteOffset;
        uint end   = off + length;
        if (end > (uint)data.Length) end = (uint)data.Length;
        uint count = end > off ? end - off : 0u;
        if (count == 0) return Prj.S_OK;

        IntPtr buf = Prj.PrjAllocateAlignedBuffer(vCtx, new UIntPtr(count));
        if (buf == IntPtr.Zero) return Prj.E_FAIL;
        try
        {
            Marshal.Copy(data, (int)off, buf, (int)count);
            return Prj.PrjWriteFileData(vCtx, ref sid, buf, byteOffset, count);
        }
        finally { Prj.PrjFreeAlignedBuffer(buf); }
    }

    // ---- Helpers ----
    private string SrcPath(string rel)
    {
        return string.IsNullOrEmpty(rel) ? _sourceRoot : Path.Combine(_sourceRoot, rel);
    }

    private static FileSystemInfo SrcFsi(string full)
    {
        if (File.Exists(full))      return new FileInfo(full);
        if (Directory.Exists(full)) return new DirectoryInfo(full);
        return null;
    }

    private static DirEntry RealEntry(FileSystemInfo fsi)
    {
        DirEntry e = new DirEntry();
        e.Name             = fsi.Name;
        bool isDir         = (fsi.Attributes & FileAttributes.Directory) != 0;
        e.IsDirectory      = isDir;
        e.FileSize         = isDir ? 0L : ((FileInfo)fsi).Length;
        e.CreationTimeFt   = fsi.CreationTime.ToFileTime();
        e.LastAccessTimeFt = fsi.LastAccessTime.ToFileTime();
        e.LastWriteTimeFt  = fsi.LastWriteTime.ToFileTime();
        e.FileAttributes   = (uint)fsi.Attributes & 0xFFFF;
        return e;
    }

    private static DirEntry SynthEntry(SyntheticEntry s)
    {
        DirEntry e = new DirEntry();
        e.Name             = s.Name;
        e.IsSynthetic      = true;
        e.IsDirectory      = s.IsDirectory;
        e.FileSize         = s.IsDirectory ? 0L : s.FileSize;
        long ft            = s.GetFiletime();
        e.CreationTimeFt   = ft;
        e.LastAccessTimeFt = ft;
        e.LastWriteTimeFt  = ft;
        e.FileAttributes   = s.IsDirectory ? 0x10u : 0x20u;
        return e;
    }

    private static bool NameExists(List<DirEntry> list, string name)
    {
        foreach (DirEntry e in list)
            if (string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void Log(string msg)
    {
        if (PhantomFSSettings.Verbose)
            Console.WriteLine("  [" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + msg);
    }
}
