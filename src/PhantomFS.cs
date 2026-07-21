// PhantomFS.cs
// ProjFS-based honeypot provider - projects synthetic credential, key, and document
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
// grants rights to this source code only - it does not grant the right to use
// the PhantomFS name, logo, or branding in a manner that implies endorsement
// or competes with the original product.
//
// DISCLAIMER: This software is provided for lawful defensive security purposes
// only. You are solely responsible for ensuring your use complies with all
// applicable laws. The authors accept no liability for any damages arising
// from use or misuse of this software. USE AT YOUR OWN RISK.
// ----------------------------------------------------------------------------
//
// -- PREREQUISITES ------------------------------------------------------------
//   Windows 10 v1809 (Build 17763) or later with ProjFS enabled.
//   Run once in an elevated PowerShell to enable the optional feature:
//     Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart
//
// -- COMPILE --------------------------------------------------------------
//   csc.exe /platform:x64 /r:System.Xml.dll /out:PhantomFS.exe PhantomFS.cs
//   (csc.exe lives at C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe)
//   No extra reference is needed for "type: base64gzip" - GZipStream lives in
//   System.dll on .NET Framework 4.8, which is already referenced by default.
//
// -- RUN (Administrator required) -----------------------------------------------
//   Synthetic-only (recommended - no real source folder needed):
//     PhantomFS.exe --virtroot C:\Honeypot --syntheticonly
//
//   Mixed - real files plus synthetic entries:
//     PhantomFS.exe --virtroot C:\Honeypot --sourceroot C:\RealFiles
//
// -- CONFIGURATION -------------------------------------------------------------
//   PhantomFS.exe.config  (same directory as the exe)
//     <settings>           - alerting, logging, cleanup, and path options
//     <syntheticFileList>  - virtual file tree (paths, sizes, timestamps)
//     <syntheticTemplates> - content returned when files are opened
//   Edit and restart; no recompile needed.
//
//   Optionally, the synthetic file list and content templates can instead be
//   loaded from a YAML file, leaving <settings> in PhantomFS.exe.config as the
//   source of truth for everything else:
//     PhantomFS.exe --virtroot C:\Honeypot --syntheticonly --syntheticyaml C:\Honeypot\synthetic-data.yml
//   or embed the path once via <settings><syntheticYamlPath> for scheduled
//   tasks / services that run without CLI arguments. See synthetic-data.yml
//   for the expected "files:" / "templates:" shape.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Xml;
using Synthetic;

// =============================================================================
// Synthetic virtual file system - namespace: Synthetic
// =============================================================================

namespace Synthetic
{
    // -------------------------------------------------------------------------
    // PhantomFSSettings - reads <settings> from <exe>.exe.config at startup.
    // All properties fall back to safe defaults when the section is absent.
    // -------------------------------------------------------------------------
    internal static class PhantomFSSettings
    {
        public static bool EnableEventLog = true;
        public static bool EnableToast = true;
        public static bool AlertOnOpen = true;   // placeholder created
        public static bool AlertOnRead = true;   // content read
        public static int ToastCooldownSeconds = 15;
        public static bool Verbose = false;
        public static string ConfigVirtRoot = null;
        public static string ConfigSourceRoot = null;
        public static bool ConfigSyntheticOnly = false;

        // Auto-cleanup of materialized synthetic placeholders.
        public static bool AutoCleanupEnabled = true;
        public static int AutoCleanupDelaySeconds = 300;   // 5 minutes

        // DNS reverse-lookup of the SMB client hostname.
        // Set to false if the lookup latency is unacceptable in your environment.
        public static bool ResolveRemoteIPs = true;

        public static void Load(string configPath)
        {
            if (!File.Exists(configPath))
            {
                return;
            }

            try
            {
                XmlDocument configDocument = new XmlDocument();
                configDocument.Load(configPath);

                EnableEventLog = ReadBool(configDocument, "/configuration/settings/enableEventLog", true);
                EnableToast = ReadBool(configDocument, "/configuration/settings/enableToast", true);
                AlertOnOpen = ReadBool(configDocument, "/configuration/settings/alertOnOpen", true);
                AlertOnRead = ReadBool(configDocument, "/configuration/settings/alertOnRead", true);
                Verbose = ReadBool(configDocument, "/configuration/settings/verbose", false);
                ConfigSyntheticOnly = ReadBool(configDocument, "/configuration/settings/syntheticOnly", false);
                ToastCooldownSeconds = ReadInt(configDocument, "/configuration/settings/toastCooldownSeconds", 15);
                ConfigVirtRoot = ReadString(configDocument, "/configuration/settings/virtRoot");
                ConfigSourceRoot = ReadString(configDocument, "/configuration/settings/sourceRoot");
                AutoCleanupEnabled = ReadBool(configDocument, "/configuration/settings/autoCleanupEnabled", true);
                AutoCleanupDelaySeconds = ReadInt(configDocument, "/configuration/settings/autoCleanupDelaySeconds", 300);
                ResolveRemoteIPs = ReadBool(configDocument, "/configuration/settings/resolveRemoteIPs", true);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Could not load <settings> from config - " + exception.Message);
            }
        }

        private static bool ReadBool(XmlDocument document, string xpath, bool defaultValue)
        {
            XmlNode node = document.SelectSingleNode(xpath);
            if (node == null)
            {
                return defaultValue;
            }

            bool parsedValue;
            return bool.TryParse(node.InnerText.Trim(), out parsedValue) ? parsedValue : defaultValue;
        }

        private static int ReadInt(XmlDocument document, string xpath, int defaultValue)
        {
            XmlNode node = document.SelectSingleNode(xpath);
            if (node == null)
            {
                return defaultValue;
            }

            int parsedValue;
            return int.TryParse(node.InnerText.Trim(), out parsedValue) ? parsedValue : defaultValue;
        }

        private static string ReadString(XmlDocument document, string xpath)
        {
            XmlNode node = document.SelectSingleNode(xpath);
            if (node == null)
            {
                return null;
            }

            string value = node.InnerText.Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
    }

    // -------------------------------------------------------------------------
    // AlertManager - writes to Windows Event Log and sends Toast notifications
    // when honeypot files are accessed.  All public methods are thread-safe.
    // -------------------------------------------------------------------------
    internal static class AlertManager
    {
        private const string SourceName = "PhantomFS";
        private const string LogName = "Application";

        public const int EventIdFileRead = 1001;
        public const int EventIdFilePlaceholder = 1002;
        public const int EventIdStarted = 1003;
        public const int EventIdStopped = 1004;

        private static readonly ConcurrentDictionary<string, DateTime> LastToastTimes =
            new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        private static bool _logReady;

        // Call once from Program.Main - registers the EventLog source (admin required).
        public static void Initialize()
        {
            if (!PhantomFSSettings.EnableEventLog)
            {
                return;
            }

            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    EventLog.CreateEventSource(SourceName, LogName);
                    Console.WriteLine("  EventLog source registered: " + SourceName);
                }

                _logReady = true;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] EventLog source registration failed - " + exception.Message);
            }
        }

        public static void OnProviderStarted(string virtualRoot)
        {
            WriteLog(
                "PhantomFS - Provider Started\r\n"
              + "VirtRoot : " + virtualRoot + "\r\n"
              + "EventLog : " + PhantomFSSettings.EnableEventLog
              + "  Toast : " + PhantomFSSettings.EnableToast + "\r\n"
              + "Cleanup  : " + (PhantomFSSettings.AutoCleanupEnabled
                    ? "enabled (" + PhantomFSSettings.AutoCleanupDelaySeconds + "s)"
                    : "disabled"),
                EventLogEntryType.Information, EventIdStarted);
        }

        public static void OnProviderStopped(string virtualRoot)
        {
            WriteLog("PhantomFS - Provider Stopped\r\nVirtRoot: " + virtualRoot,
                EventLogEntryType.Information, EventIdStopped);
        }

        // Fires when a process first opens a honeypot file (placeholder created).
        // sessions is non-null when the access originated from an SMB client.
        public static void OnPlaceholderCreated(string filePath, string processName, uint processId,
            List<RemoteSessionHelper.SessionInfo> sessions)
        {
            if (!PhantomFSSettings.AlertOnOpen)
            {
                return;
            }

            string sessionText = RemoteSessionHelper.FormatSessions(sessions);
            string message = "PhantomFS - Honeypot File Opened\r\n"
                           + "File    : " + filePath + "\r\n"
                           + "Process : " + DescribeProcess(processName, processId)
                           + sessionText;

            bool isRemote = sessions != null && sessions.Count > 0;
            string remoteTag = isRemote ? "  [REMOTE]" : string.Empty;
            Console.WriteLine("[ALERT:OPEN]  " + filePath + " - " + DescribeProcess(processName, processId) + remoteTag);
            WriteLog(message, EventLogEntryType.Warning, EventIdFilePlaceholder);
            // Toast deferred to OnFileAccessed - content read is the stronger signal.
        }

        // Fires when a process reads content from a honeypot file.
        // This is the primary alert trigger and sends both log entry and Toast.
        // sessions is non-null when the access originated from an SMB client.
        public static void OnFileAccessed(string filePath, uint processId, string processName,
            List<RemoteSessionHelper.SessionInfo> sessions)
        {
            if (!PhantomFSSettings.AlertOnRead)
            {
                return;
            }

            string sessionText = RemoteSessionHelper.FormatSessions(sessions);
            string message = "PhantomFS - Honeypot File Content Read\r\n"
                           + "File    : " + filePath + "\r\n"
                           + "Process : " + DescribeProcess(processName, processId)
                           + sessionText;

            bool isRemote = sessions != null && sessions.Count > 0;
            string remoteTag = isRemote ? "  [REMOTE]" : string.Empty;
            Console.WriteLine("[ALERT:READ]  " + filePath + " - " + DescribeProcess(processName, processId) + remoteTag);
            WriteLog(message, EventLogEntryType.Warning, EventIdFileRead);

            if (PhantomFSSettings.EnableToast && CooldownExpired(filePath))
            {
                string toastTitle = "PhantomFS - Honeypot File Accessed";
                string toastBody;

                if (isRemote)
                {
                    // Include SMB user and source address in the Toast body.
                    RemoteSessionHelper.SessionInfo firstSession = sessions[0];
                    toastBody = filePath + "\r\n"
                              + "User: " + firstSession.UserName
                              + "  From: " + firstSession.ClientName
                              + (string.IsNullOrEmpty(firstSession.ClientIP)
                                    ? string.Empty
                                    : "  [" + firstSession.ClientIP + "]");
                }
                else
                {
                    toastBody = filePath + "  (" + DescribeProcess(processName, processId) + ")";
                }

                SendToast(toastTitle, toastBody);
            }
        }

        // ---- Private helpers ----

        private static string DescribeProcess(string processName, uint processId)
        {
            return string.IsNullOrEmpty(processName)
                ? "PID " + processId
                : processName + " (PID " + processId + ")";
        }

        private static bool CooldownExpired(string cooldownKey)
        {
            DateTime now = DateTime.UtcNow;
            TimeSpan cooldown = TimeSpan.FromSeconds(PhantomFSSettings.ToastCooldownSeconds);
            DateTime lastToast;
            if (LastToastTimes.TryGetValue(cooldownKey, out lastToast) && (now - lastToast) < cooldown)
            {
                return false;
            }

            LastToastTimes[cooldownKey] = now;
            return true;
        }

        private static void WriteLog(string message, EventLogEntryType entryType, int eventId)
        {
            if (!_logReady || !PhantomFSSettings.EnableEventLog)
            {
                return;
            }

            try
            {
                EventLog.WriteEntry(SourceName, message, entryType, eventId);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] EventLog write failed - " + exception.Message);
            }
        }

        // Sends a Windows Toast notification by launching a hidden PowerShell process.
        // Uses the Windows PowerShell AUMID - a standard technique for desktop apps
        // that have not registered their own AppUserModelId.
        // The script is Base64-encoded (-EncodedCommand) to avoid quoting pitfalls.
        private static void SendToast(string title, string body)
        {
            string safeTitle = EscapeXml(title);
            string safeBody = EscapeXml(body);

            // AUMID for Windows PowerShell - works on all Windows 10/11 installs.
            string applicationUserModelId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
                                          + "\\WindowsPowerShell\\v1.0\\powershell.exe";

            string toastXml = "<toast>"
                            + "<visual><binding template=\"ToastGeneric\">"
                            + "<text>" + safeTitle + "</text>"
                            + "<text>" + safeBody + "</text>"
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
                      "::CreateToastNotifier('", applicationUserModelId.Replace("'", "''"), "');",
                "$n.Show($t)"
            );

            try
            {
                byte[] scriptBytes = Encoding.Unicode.GetBytes(script);
                string encodedCommand = Convert.ToBase64String(scriptBytes);

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "powershell.exe";
                startInfo.Arguments = "-NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand " + encodedCommand;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                Process.Start(startInfo);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Toast notification failed - " + exception.Message);
            }
        }

        private static string EscapeXml(string text)
        {
            if (text == null)
            {
                return string.Empty;
            }

            return text.Replace("&", "&amp;")
                       .Replace("<", "&lt;")
                       .Replace(">", "&gt;")
                       .Replace("\"", "&quot;")
                       .Replace("'", "&apos;");
        }
    }

    // -------------------------------------------------------------------------
    // RemoteSessionHelper - detects SMB/network file access and enumerates
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

        private static class NativeMethods
        {
            // SESSION_INFO_10 - x64 layout:
            //   offset  0  LMSTR sesi10_cname     (8-byte pointer)
            //   offset  8  LMSTR sesi10_username  (8-byte pointer)
            //   offset 16  DWORD sesi10_time      (4 bytes)
            //   offset 20  DWORD sesi10_idle_time (4 bytes)
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct SESSION_INFO_10
            {
                internal IntPtr ClientName;
                internal IntPtr UserName;
                internal uint SecondsActive;
                internal uint SecondsIdle;
            }

            internal const int NerrSuccess = 0;
            internal const int ErrorMoreData = 234;
            internal const int SessionInfoLevel10 = 10;
            internal const int MaxPreferredLength = -1;

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            internal static extern int NetSessionEnum(
                string serverName,
                string uncClientName,
                string userName,
                int level,
                out IntPtr buffer,
                int preferredMaximumLength,
                out int entriesRead,
                out int totalEntries,
                ref int resumeHandle);

            [DllImport("Netapi32.dll", ExactSpelling = true)]
            internal static extern int NetApiBufferFree(IntPtr buffer);
        }

        // Returns true when the triggering process is likely the SMB kernel driver.
        // PID 4 = Windows System process; an empty image path also signals a
        // kernel-mode caller.
        public static bool IsLikelyRemote(uint processId, string processName)
        {
            if (processId == 4)
            {
                return true;
            }

            return string.IsNullOrEmpty(processName);
        }

        // Enumerates active SMB sessions on this host.
        // Returns an empty list when no sessions are open or when the Server
        // service is unavailable.  Partial results are returned if the buffer
        // fills before all sessions are read (unlikely in practice).
        //
        // DNS resolution is performed as a separate pass after the NetSessionEnum
        // call completes and the buffer is freed.  This ensures that a DNS failure
        // (including the ConfigurationErrorsException that fires on first use when
        // the app config contains unrecognised sections) never suppresses the
        // username and hostname that were already captured from the session buffer.
        //
        // Duplicate sessions - Windows sometimes returns two entries for the same
        // connection with differing username casing (one for the negotiation phase,
        // one for the authenticated session).  A case-insensitive deduplication pass
        // collapses these before the list is returned.
        public static List<SessionInfo> GetActiveSessions()
        {
            List<SessionInfo> sessions = new List<SessionInfo>();
            IntPtr sessionBuffer = IntPtr.Zero;
            int resumeHandle = 0;

            // ---- Phase 1: session enumeration (no DNS, no managed I/O) ----
            try
            {
                int entriesRead;
                int totalEntries;
                int resultCode = NativeMethods.NetSessionEnum(
                    null, null, null,
                    NativeMethods.SessionInfoLevel10,
                    out sessionBuffer,
                    NativeMethods.MaxPreferredLength,
                    out entriesRead,
                    out totalEntries,
                    ref resumeHandle);

                // NerrSuccess and ErrorMoreData (partial results) are both usable -
                // anything else indicates a real failure.
                if (resultCode != NativeMethods.NerrSuccess && resultCode != NativeMethods.ErrorMoreData)
                {
                    return sessions;
                }

                if (sessionBuffer == IntPtr.Zero || entriesRead == 0)
                {
                    return sessions;
                }

                int structSize = Marshal.SizeOf(typeof(NativeMethods.SESSION_INFO_10));
                for (int entryIndex = 0; entryIndex < entriesRead; entryIndex++)
                {
                    NativeMethods.SESSION_INFO_10 nativeSession =
                        (NativeMethods.SESSION_INFO_10)Marshal.PtrToStructure(
                            IntPtr.Add(sessionBuffer, entryIndex * structSize),
                            typeof(NativeMethods.SESSION_INFO_10));

                    string clientName = nativeSession.ClientName != IntPtr.Zero
                        ? (Marshal.PtrToStringUni(nativeSession.ClientName) ?? string.Empty)
                        : string.Empty;
                    string userName = nativeSession.UserName != IntPtr.Zero
                        ? (Marshal.PtrToStringUni(nativeSession.UserName) ?? string.Empty)
                        : string.Empty;

                    // SMB reports the client as \\hostname; strip the leading backslashes.
                    SessionInfo session = new SessionInfo();
                    session.UserName = userName;
                    session.ClientName = clientName.TrimStart('\\');
                    session.ClientIP = string.Empty;
                    sessions.Add(session);
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] NetSessionEnum - " + exception.Message);
            }
            finally
            {
                if (sessionBuffer != IntPtr.Zero)
                {
                    try { NativeMethods.NetApiBufferFree(sessionBuffer); } catch { }
                }
            }

            // ---- Phase 2: deduplication ----
            // Windows sometimes reports the same connection twice with differing
            // username casing (negotiation session vs. authenticated session).
            // Keep only the first occurrence of each username+hostname pair.
            List<SessionInfo> dedupedSessions = new List<SessionInfo>();
            foreach (SessionInfo candidate in sessions)
            {
                bool alreadySeen = false;
                foreach (SessionInfo existing in dedupedSessions)
                {
                    if (string.Equals(candidate.UserName, existing.UserName, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(candidate.ClientName, existing.ClientName, StringComparison.OrdinalIgnoreCase))
                    {
                        alreadySeen = true;
                        break;
                    }
                }

                if (!alreadySeen)
                {
                    dedupedSessions.Add(candidate);
                }
            }

            sessions = dedupedSessions;

            // ---- Phase 3: DNS resolution (isolated - failures never discard sessions) ----
            if (PhantomFSSettings.ResolveRemoteIPs)
            {
                foreach (SessionInfo session in sessions)
                {
                    try
                    {
                        session.ClientIP = ResolveToIPAddress(session.ClientName);
                    }
                    catch (Exception exception)
                    {
                        Console.Error.WriteLine("[WARN] DNS resolution failed - " + exception.Message);
                    }
                }
            }

            return sessions;
        }

        // Attempts to resolve a hostname to an IP address string.
        // Returns the input unchanged if it is already an IP, or an empty string
        // if DNS resolution fails.
        private static string ResolveToIPAddress(string hostName)
        {
            if (string.IsNullOrEmpty(hostName))
            {
                return string.Empty;
            }

            IPAddress parsedAddress;
            if (IPAddress.TryParse(hostName, out parsedAddress))
            {
                return hostName;
            }

            try
            {
                IPAddress[] resolvedAddresses = Dns.GetHostAddresses(hostName);
                if (resolvedAddresses.Length > 0)
                {
                    return resolvedAddresses[0].ToString();
                }
            }
            catch
            {
            }

            return string.Empty;
        }

        // Formats a session list for inclusion in Event Log messages.
        // Returns an empty string when the list is null or empty.
        public static string FormatSessions(List<SessionInfo> sessions)
        {
            if (sessions == null || sessions.Count == 0)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder();
            foreach (SessionInfo session in sessions)
            {
                builder.Append("\r\nRemote  : ").Append(session.UserName);
                if (!string.IsNullOrEmpty(session.ClientName))
                {
                    builder.Append(" @ ").Append(session.ClientName);
                }

                if (!string.IsNullOrEmpty(session.ClientIP)
                    && !string.Equals(session.ClientIP, session.ClientName, StringComparison.OrdinalIgnoreCase))
                {
                    builder.Append("  [").Append(session.ClientIP).Append("]");
                }
            }

            return builder.ToString();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticEntry - one parsed row from <syntheticFileList>.
    // RelativePath uses backslash separators with no leading backslash.
    // -------------------------------------------------------------------------
    internal sealed class SyntheticEntry
    {
        public string RelativePath;   // "AWS\credentials"
        public string Name;           // "credentials"
        public string ParentPath;     // "AWS"  (empty = root)
        public bool IsDirectory;
        public long FileSize;
        public long UnixTimestamp;

        public long GetFiletime()
        {
            DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return unixEpoch.AddSeconds((double)UnixTimestamp).ToFileTime();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticData - loads and indexes the virtual file tree from the config.
    //
    // Line format:  \Path\To\Entry,isDirectory,fileSize,unixTimestamp
    // -------------------------------------------------------------------------
    internal sealed class SyntheticData
    {
        private readonly Dictionary<string, SyntheticEntry> _entriesByPath;
        private readonly Dictionary<string, List<SyntheticEntry>> _entriesByParent;

        private SyntheticData()
        {
            _entriesByPath = new Dictionary<string, SyntheticEntry>(StringComparer.OrdinalIgnoreCase);
            _entriesByParent = new Dictionary<string, List<SyntheticEntry>>(StringComparer.OrdinalIgnoreCase);
        }

        public int EntryCount
        {
            get { return _entriesByPath.Count; }
        }

        public static SyntheticData LoadFromConfig(string configPath)
        {
            if (!File.Exists(configPath))
            {
                Console.Error.WriteLine("[WARN] Config not found: " + configPath);
                return null;
            }

            try
            {
                XmlDocument configDocument = new XmlDocument();
                configDocument.Load(configPath);

                XmlNode fileListNode = configDocument.SelectSingleNode("/configuration/syntheticFileList");
                if (fileListNode == null)
                {
                    Console.Error.WriteLine("[WARN] No <syntheticFileList> in config.");
                    return null;
                }

                string rawFileList = fileListNode.InnerText;
                if (string.IsNullOrEmpty(rawFileList.Trim()))
                {
                    Console.Error.WriteLine("[WARN] <syntheticFileList> is empty.");
                    return null;
                }

                return ParseLines(rawFileList.Split(new char[] { '\r', '\n' }, StringSplitOptions.None));
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Could not load file list - " + exception.Message);
                return null;
            }
        }

        private static SyntheticData ParseLines(string[] lines)
        {
            SyntheticData data = new SyntheticData();
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                {
                    continue;
                }

                string[] fields = trimmedLine.Split(',');
                if (fields.Length < 4)
                {
                    continue;
                }

                bool isDirectory;
                long fileSize;
                long unixTimestamp;
                if (!bool.TryParse(fields[1].Trim(), out isDirectory))
                {
                    continue;
                }

                if (!long.TryParse(fields[2].Trim(), out fileSize))
                {
                    continue;
                }

                if (!long.TryParse(fields[3].Trim(), out unixTimestamp))
                {
                    continue;
                }

                string normalizedPath = fields[0].Trim().TrimStart('\\');
                AddEntry(data, normalizedPath, isDirectory, fileSize, unixTimestamp);
            }

            return data;
        }

        // Shared by both the XML line-format loader (ParseLines) and the YAML
        // loader (LoadFromYaml) - builds one SyntheticEntry and indexes it by
        // path and by parent, so both formats produce an identical in-memory
        // structure regardless of which one was on disk.
        private static void AddEntry(SyntheticData data, string normalizedPath, bool isDirectory, long fileSize, long unixTimestamp)
        {
            SyntheticEntry entry = new SyntheticEntry();
            entry.RelativePath = normalizedPath;
            entry.IsDirectory = isDirectory;
            entry.FileSize = fileSize;
            entry.UnixTimestamp = unixTimestamp;

            int lastSeparatorIndex = normalizedPath.LastIndexOf('\\');
            if (lastSeparatorIndex >= 0)
            {
                entry.Name = normalizedPath.Substring(lastSeparatorIndex + 1);
                entry.ParentPath = normalizedPath.Substring(0, lastSeparatorIndex);
            }
            else
            {
                entry.Name = normalizedPath;
                entry.ParentPath = string.Empty;
            }

            data._entriesByPath[normalizedPath] = entry;

            List<SyntheticEntry> siblings;
            if (!data._entriesByParent.TryGetValue(entry.ParentPath, out siblings))
            {
                siblings = new List<SyntheticEntry>();
                data._entriesByParent[entry.ParentPath] = siblings;
            }

            siblings.Add(entry);
        }

        // Loads the virtual file tree from a YAML file instead of the
        // <syntheticFileList> block in PhantomFS.exe.config.  Expected shape:
        //
        //   files:
        //     - path: AWS
        //       directory: true
        //       size: 0
        //       timestamp: 1743942586
        //     - path: AWS/credentials
        //       directory: false
        //       size: 116
        //       timestamp: 1741508986
        //
        // "path" accepts either / or \ as the separator; it is normalized to \
        // internally so the rest of the provider (which indexes on \) needs no
        // changes.  "directory" defaults to false and "size"/"timestamp" default
        // to 0 when omitted, matching the leniency of the CSV-line parser above.
        public static SyntheticData LoadFromYaml(string yamlPath)
        {
            if (!File.Exists(yamlPath))
            {
                Console.Error.WriteLine("[WARN] YAML synthetic data file not found: " + yamlPath);
                return null;
            }

            List<Dictionary<string, string>> rows;
            try
            {
                rows = SimpleYamlListParser.ParseSection(yamlPath, "files");
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Could not parse YAML file list - " + exception.Message);
                return null;
            }

            if (rows.Count == 0)
            {
                Console.Error.WriteLine("[WARN] No entries found under 'files:' in " + yamlPath);
                return null;
            }

            SyntheticData data = new SyntheticData();
            foreach (Dictionary<string, string> row in rows)
            {
                string rawPath;
                if (!row.TryGetValue("path", out rawPath) || string.IsNullOrEmpty(rawPath.Trim()))
                {
                    Console.Error.WriteLine("[WARN] Skipping YAML entry with no 'path'.");
                    continue;
                }

                string normalizedPath = rawPath.Trim().Replace('/', '\\').TrimStart('\\');

                bool isDirectory = false;
                string directoryText;
                if (row.TryGetValue("directory", out directoryText))
                {
                    bool.TryParse(directoryText.Trim(), out isDirectory);
                }

                long fileSize = 0;
                string sizeText;
                if (row.TryGetValue("size", out sizeText))
                {
                    long.TryParse(sizeText.Trim(), out fileSize);
                }

                long unixTimestamp = 0;
                string timestampText;
                if (row.TryGetValue("timestamp", out timestampText))
                {
                    long.TryParse(timestampText.Trim(), out unixTimestamp);
                }

                AddEntry(data, normalizedPath, isDirectory, fileSize, unixTimestamp);
            }

            return data;
        }

        public SyntheticEntry Find(string relativePath)
        {
            if (relativePath == null)
            {
                relativePath = string.Empty;
            }

            SyntheticEntry entry;
            return _entriesByPath.TryGetValue(relativePath, out entry) ? entry : null;
        }

        public List<SyntheticEntry> GetChildren(string parentPath)
        {
            if (parentPath == null)
            {
                parentPath = string.Empty;
            }

            List<SyntheticEntry> children;
            return _entriesByParent.TryGetValue(parentPath, out children) ? children : new List<SyntheticEntry>();
        }
    }

    // -------------------------------------------------------------------------
    // SyntheticContent - generates plausible file content for synthetic entries.
    //
    // Template types (set via type= attribute on <template> elements):
    //   type="pem"   - deterministic LCG-generated PEM block sized to fileSize
    //   (CDATA text) - static text, padded/trimmed to match fileSize
    //
    // Match order:  exact filename match, then file extension, then built-in fallback
    // -------------------------------------------------------------------------
    internal static class SyntheticContent
    {
        private sealed class TemplateEntry
        {
            public bool IsPem;
            public string PemLabel;
            public string Text;

            // Binary content, embedded as base64 (optionally gzip-compressed) in
            // either the YAML "content: |" block or the XML <template> CDATA body.
            // The base64 text itself is stored as-is at load time; decoding (and
            // gunzipping) happens lazily on first access via GetDecodedBytes, not
            // at startup, so a config with many large embedded binaries does not
            // pay the decode cost for files that are never opened.
            public bool IsBinary;
            public bool IsGzipCompressed;
            public string Base64Payload;

            private byte[] _decodedBytes;
            private readonly object _decodeLock = new object();
            private bool _warnedSizeMismatch;

            // Decodes (and caches) the binary payload. Convert.FromBase64String
            // tolerates embedded whitespace/newlines, so the multi-line base64
            // text produced by a YAML "|" block or an XML CDATA body needs no
            // pre-processing. Safe to call concurrently - ProjFS can invoke
            // GetFileData for the same path from more than one thread.
            public byte[] GetDecodedBytes()
            {
                if (_decodedBytes != null)
                {
                    return _decodedBytes;
                }

                lock (_decodeLock)
                {
                    if (_decodedBytes == null)
                    {
                        byte[] base64Decoded = Convert.FromBase64String(Base64Payload ?? string.Empty);
                        _decodedBytes = IsGzipCompressed ? GunzipBytes(base64Decoded) : base64Decoded;
                    }
                }

                return _decodedBytes;
            }

            // Warns once (not on every read) when the decoded byte count does not
            // match the declared synthetic file size - FitToSize will otherwise
            // silently truncate or newline-pad the content, which corrupts most
            // binary formats (zip-based .xlsx/.docx, .pdf, images, and so on).
            public void WarnIfSizeMismatch(long declaredSize, long actualLength)
            {
                if (_warnedSizeMismatch || actualLength == declaredSize)
                {
                    return;
                }

                _warnedSizeMismatch = true;
                Console.Error.WriteLine("[WARN] Binary template decoded to " + actualLength
                    + " bytes but its synthetic entry declares size=" + declaredSize
                    + " - set 'size:' (YAML) or the CSV fileSize field (XML) to the exact"
                    + " decoded length, or the file will be truncated/padded and likely corrupted.");
            }
        }

        private static Dictionary<string, TemplateEntry> _templatesByFileName;
        private static Dictionary<string, TemplateEntry> _templatesByExtension;

        public static void LoadFromConfig(string configPath)
        {
            _templatesByFileName = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);
            _templatesByExtension = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(configPath))
            {
                Console.WriteLine("[INFO] Config not found - synthetic files will return generic text.");
                return;
            }

            int templateCount = 0;
            try
            {
                XmlDocument configDocument = new XmlDocument();
                configDocument.Load(configPath);

                XmlNodeList templateNodes = configDocument.SelectNodes("/configuration/syntheticTemplates/template");
                if (templateNodes == null)
                {
                    Console.WriteLine("[INFO] No <syntheticTemplates> found.");
                    return;
                }

                foreach (XmlNode templateNode in templateNodes)
                {
                    string nameAttribute = ReadAttribute(templateNode, "name");
                    string extensionAttribute = ReadAttribute(templateNode, "extension");
                    string typeAttribute = ReadAttribute(templateNode, "type");
                    string pemLabelAttribute = ReadAttribute(templateNode, "pemLabel");
                    bool isPem = string.Equals(typeAttribute, "pem", StringComparison.OrdinalIgnoreCase);
                    bool isBase64 = string.Equals(typeAttribute, "base64", StringComparison.OrdinalIgnoreCase);
                    bool isBase64Gzip = string.Equals(typeAttribute, "base64gzip", StringComparison.OrdinalIgnoreCase);

                    TemplateEntry template = new TemplateEntry();
                    template.IsPem = isPem;
                    template.PemLabel = isPem && pemLabelAttribute != null ? pemLabelAttribute : "PRIVATE KEY";

                    if (isBase64 || isBase64Gzip)
                    {
                        template.IsBinary = true;
                        template.IsGzipCompressed = isBase64Gzip;
                        template.Base64Payload = templateNode.InnerText;
                    }
                    else
                    {
                        template.Text = isPem ? null : (templateNode.InnerText.Trim() + "\n");
                    }

                    if (nameAttribute != null)
                    {
                        _templatesByFileName[nameAttribute.ToLowerInvariant()] = template;
                        templateCount++;
                    }
                    else if (extensionAttribute != null)
                    {
                        _templatesByExtension[extensionAttribute.ToLowerInvariant()] = template;
                        templateCount++;
                    }
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Could not load templates - " + exception.Message);
                return;
            }

            Console.WriteLine("  Loaded " + templateCount + " content templates from config.");
        }

        // Loads content templates from a YAML file instead of the
        // <syntheticTemplates> block in PhantomFS.exe.config.  Expected shape:
        //
        //   templates:
        //     - name: credentials
        //       content: |
        //         [default]
        //         aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        //     - extension: .pdf
        //       content: |
        //         %PDF-1.4
        //         ...
        //     - name: id_rsa
        //       type: pem
        //       pemLabel: RSA PRIVATE KEY
        //     - name: company_logo.png
        //       type: base64
        //       content: |
        //         iVBORw0KGgoAAAANSUhEUgAA...        (plain base64, no compression)
        //     - name: Board_Deck_Q3.pptx
        //       type: base64gzip
        //       content: |
        //         H4sIAAAAAAAAA+2c...                (base64 of a gzip stream)
        //
        // Exactly one of "name" or "extension" should be set per entry, matching
        // the name=/extension= attribute pair used by the XML <template> element.
        // "type: pem" and "pemLabel" behave the same as their XML counterparts.
        //
        // "type: base64" / "type: base64gzip" embed real binary content (an
        // actual small PDF, image, xlsx/docx, etc.) instead of synthesized text.
        // Decoding happens lazily on first read and is cached afterward, so
        // startup cost stays flat regardless of how many binaries are embedded.
        // base64gzip additionally gzip-decompresses after the base64 decode,
        // which keeps large real files reasonably compact inside the YAML.
        // IMPORTANT: the matching "files:" entry's "size:" must equal the exact
        // decoded (post-gzip) byte length, or FitToSize will truncate/pad the
        // content and most binary formats will not open correctly. A mismatch
        // logs a one-time [WARN] the first time the file is read.
        public static void LoadFromYaml(string yamlPath)
        {
            _templatesByFileName = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);
            _templatesByExtension = new Dictionary<string, TemplateEntry>(StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(yamlPath))
            {
                Console.Error.WriteLine("[WARN] YAML templates file not found: " + yamlPath);
                return;
            }

            List<Dictionary<string, string>> rows;
            try
            {
                rows = SimpleYamlListParser.ParseSection(yamlPath, "templates");
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[WARN] Could not parse YAML templates - " + exception.Message);
                return;
            }

            int templateCount = 0;
            foreach (Dictionary<string, string> row in rows)
            {
                string nameValue;
                row.TryGetValue("name", out nameValue);
                string extensionValue;
                row.TryGetValue("extension", out extensionValue);
                string typeValue;
                row.TryGetValue("type", out typeValue);
                string pemLabelValue;
                row.TryGetValue("pemLabel", out pemLabelValue);
                string contentValue;
                row.TryGetValue("content", out contentValue);

                bool isPem = string.Equals(typeValue, "pem", StringComparison.OrdinalIgnoreCase);
                bool isBase64 = string.Equals(typeValue, "base64", StringComparison.OrdinalIgnoreCase);
                bool isBase64Gzip = string.Equals(typeValue, "base64gzip", StringComparison.OrdinalIgnoreCase);

                TemplateEntry template = new TemplateEntry();
                template.IsPem = isPem;
                template.PemLabel = isPem && !string.IsNullOrEmpty(pemLabelValue) ? pemLabelValue.Trim() : "PRIVATE KEY";

                if (isBase64 || isBase64Gzip)
                {
                    template.IsBinary = true;
                    template.IsGzipCompressed = isBase64Gzip;
                    template.Base64Payload = contentValue ?? string.Empty;
                }
                else
                {
                    template.Text = isPem ? null : ((contentValue ?? string.Empty).Trim() + "\n");
                }

                if (!string.IsNullOrEmpty(nameValue))
                {
                    _templatesByFileName[nameValue.Trim().ToLowerInvariant()] = template;
                    templateCount++;
                }
                else if (!string.IsNullOrEmpty(extensionValue))
                {
                    _templatesByExtension[extensionValue.Trim().ToLowerInvariant()] = template;
                    templateCount++;
                }
                else
                {
                    Console.Error.WriteLine("[WARN] Skipping YAML template with neither 'name' nor 'extension'.");
                }
            }

            Console.WriteLine("  Loaded " + templateCount + " content templates from YAML.");
        }

        public static byte[] Generate(string fileName, long declaredSize)
        {
            string lowerFileName = fileName.ToLowerInvariant();
            byte[] rawContent = ResolveBytes(lowerFileName, declaredSize);
            return FitToSize(rawContent, declaredSize);
        }

        // Generates only the requested window of bytes for a synthetic file.
        // This avoids allocating multi-GB buffers when placeholders advertise
        // very large sizes and the caller requests a small read range.
        public static byte[] GenerateSlice(string fileName, long declaredSize, ulong byteOffset, uint length)
        {
            if (declaredSize <= 0 || length == 0 || byteOffset >= (ulong)declaredSize)
            {
                return new byte[0];
            }

            long remaining = declaredSize - (long)byteOffset;
            int requestedLength = (int)Math.Min((long)length, remaining);
            string lowerFileName = fileName.ToLowerInvariant();
            byte[] rawContent = ResolveBytes(lowerFileName, declaredSize);
            return FitToSizeSlice(rawContent, declaredSize, (long)byteOffset, requestedLength);
        }

        private static byte[] ResolveBytes(string lowerFileName, long declaredSize)
        {
            TemplateEntry template;
            if (_templatesByFileName != null && _templatesByFileName.TryGetValue(lowerFileName, out template))
            {
                return ProduceBytes(template, declaredSize);
            }

            string extension = Path.GetExtension(lowerFileName);
            if (!string.IsNullOrEmpty(extension)
                && _templatesByExtension != null
                && _templatesByExtension.TryGetValue(extension, out template))
            {
                return ProduceBytes(template, declaredSize);
            }

            return Encoding.UTF8.GetBytes(
                "# " + lowerFileName + "\n# Synthetic honeypot file - add a <template> to PhantomFS.exe.config\n");
        }

        private static byte[] ProduceBytes(TemplateEntry template, long declaredSize)
        {
            if (template.IsPem)
            {
                return Encoding.UTF8.GetBytes(BuildPemBlock(template.PemLabel, declaredSize));
            }

            if (template.IsBinary)
            {
                byte[] decodedBytes = template.GetDecodedBytes();
                template.WarnIfSizeMismatch(declaredSize, decodedBytes.Length);
                return decodedBytes;
            }

            return Encoding.UTF8.GetBytes(template.Text ?? string.Empty);
        }

        // Reverses gzip compression on an already base64-decoded byte array.
        // Used for "type: base64gzip" templates - keeps large real binaries
        // reasonably compact inside the YAML/XML config.
        private static byte[] GunzipBytes(byte[] compressedBytes)
        {
            using (MemoryStream compressedStream = new MemoryStream(compressedBytes))
            using (GZipStream gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (MemoryStream resultStream = new MemoryStream())
            {
                gzipStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }
        }

        private static string BuildPemBlock(string label, long targetSize)
        {
            string header = "-----BEGIN " + label + "-----\n";
            string footer = "\n-----END " + label + "-----\n";
            int bodyLength = (int)targetSize - header.Length - footer.Length;
            if (bodyLength < 64)
            {
                bodyLength = 64;
            }

            return header + GenerateFakeBase64(bodyLength) + footer;
        }

        private static string GenerateFakeBase64(int approximateLength)
        {
            const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int generatorState = unchecked(0x12345678);
            StringBuilder builder = new StringBuilder(approximateLength + 80);
            int columnIndex = 0;
            while (builder.Length < approximateLength)
            {
                generatorState = unchecked(generatorState * 1664525 + 1013904223);
                builder.Append(Base64Alphabet[((generatorState >> 8) & 0x7FFFFFFF) % 64]);
                if (++columnIndex == 64)
                {
                    builder.Append('\n');
                    columnIndex = 0;
                }
            }

            if (columnIndex > 0)
            {
                builder.Append('\n');
            }

            return builder.ToString();
        }

        private static byte[] FitToSize(byte[] rawContent, long targetSize)
        {
            if (targetSize <= 0)
            {
                return new byte[0];
            }

            if (targetSize > int.MaxValue)
            {
                Console.Error.WriteLine("[WARN] Requested synthetic payload exceeds in-memory limit: size="
                    + targetSize + " - serving data in read-window mode.");
                return FitToSizeSlice(rawContent, targetSize, 0, rawContent != null ? rawContent.Length : 0);
            }

            byte[] result = new byte[(int)targetSize];
            if (rawContent.Length >= (int)targetSize)
            {
                Array.Copy(rawContent, result, (int)targetSize);
            }
            else
            {
                Array.Copy(rawContent, result, rawContent.Length);
                for (int paddingIndex = rawContent.Length; paddingIndex < (int)targetSize; paddingIndex++)
                {
                    result[paddingIndex] = (byte)'\n';
                }
            }

            return result;
        }

        private static byte[] FitToSizeSlice(byte[] rawContent, long targetSize, long startOffset, int requestedLength)
        {
            if (requestedLength <= 0 || targetSize <= 0 || startOffset >= targetSize)
            {
                return new byte[0];
            }

            byte[] result = new byte[requestedLength];
            byte[] source = rawContent ?? new byte[0];

            long sourceLength = source.LongLength;
            if (startOffset < sourceLength)
            {
                int copyStart = (int)startOffset;
                int copyLength = (int)Math.Min((long)requestedLength, sourceLength - startOffset);
                Array.Copy(source, copyStart, result, 0, copyLength);

                for (int paddingIndex = copyLength; paddingIndex < requestedLength; paddingIndex++)
                {
                    result[paddingIndex] = (byte)'\n';
                }
            }
            else
            {
                for (int paddingIndex = 0; paddingIndex < requestedLength; paddingIndex++)
                {
                    result[paddingIndex] = (byte)'\n';
                }
            }

            return result;
        }

        private static string ReadAttribute(XmlNode node, string attributeName)
        {
            if (node.Attributes == null)
            {
                return null;
            }

            XmlAttribute attribute = node.Attributes[attributeName];
            return attribute != null ? attribute.Value : null;
        }
    }

    // -------------------------------------------------------------------------
    // SimpleYamlListParser - a deliberately narrow YAML reader.
    //
    // This is not a general-purpose YAML parser. It understands exactly one
    // shape, which is all PhantomFS needs: a top-level "key:" line followed by
    // a block sequence of flat mappings, where a mapping value can either be a
    // plain scalar or a literal block scalar introduced with "|" (used for
    // multi-line template content). That shape covers both the "files:" and
    // "templates:" sections of a PhantomFS synthetic-data YAML file:
    //
    //   files:
    //     - path: AWS\credentials
    //       directory: false
    //       size: 116
    //       timestamp: 1741508986
    //
    //   templates:
    //     - name: credentials
    //       content: |
    //         [default]
    //         aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    //
    // Indentation must use spaces (tabs are rejected). Comments (#) and blank
    // lines are ignored outside of literal block scalars, where every line is
    // taken verbatim once the block has started.
    // -------------------------------------------------------------------------
    internal static class SimpleYamlListParser
    {
        public static List<Dictionary<string, string>> ParseSection(string yamlPath, string sectionKey)
        {
            string[] lines = File.ReadAllLines(yamlPath);
            foreach (string line in lines)
            {
                if (line.IndexOf('\t') >= 0)
                {
                    throw new FormatException("Tabs are not supported in PhantomFS YAML files - use spaces for indentation.");
                }
            }

            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();

            int lineIndex = FindTopLevelKey(lines, sectionKey);
            if (lineIndex < 0)
            {
                return results;   // section absent - caller decides whether that's fatal
            }

            int? itemIndent = null;
            Dictionary<string, string> currentItem = null;

            while (lineIndex < lines.Length)
            {
                string rawLine = lines[lineIndex];
                if (IsBlankOrComment(rawLine))
                {
                    lineIndex++;
                    continue;
                }

                int indent = IndentOf(rawLine);
                if (indent == 0)
                {
                    break;   // next top-level key, or end of section
                }

                string content = rawLine.Substring(indent);
                if (content.StartsWith("- "))
                {
                    if (itemIndent == null)
                    {
                        itemIndent = indent;
                    }

                    if (indent != itemIndent.Value)
                    {
                        break;   // inconsistent nesting - stop rather than guess
                    }

                    if (currentItem != null)
                    {
                        results.Add(currentItem);
                    }

                    currentItem = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    string firstFieldText = content.Substring(2);
                    lineIndex++;
                    lineIndex = ConsumeKeyValue(lines, lineIndex, firstFieldText, indent + 2, currentItem);
                }
                else
                {
                    if (currentItem == null || itemIndent == null || indent < itemIndent.Value + 2)
                    {
                        break;   // dedent out of the current list item
                    }

                    lineIndex++;
                    lineIndex = ConsumeKeyValue(lines, lineIndex, content, itemIndent.Value + 2, currentItem);
                }
            }

            if (currentItem != null)
            {
                results.Add(currentItem);
            }

            return results;
        }

        private static int FindTopLevelKey(string[] lines, string sectionKey)
        {
            string wantedKey = sectionKey + ":";
            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];
                if (IsBlankOrComment(line) || IndentOf(line) != 0)
                {
                    continue;
                }

                if (string.Equals(line.Trim(), wantedKey, StringComparison.OrdinalIgnoreCase))
                {
                    return lineIndex + 1;
                }
            }

            return -1;
        }

        // Parses one "key: value" pair starting at fieldText (the part of the
        // line after any leading "- "). If the value introduces a literal block
        // scalar ("|", "|-", or "|+"), consumes the following more-indented
        // lines as the block body. Returns the line index to resume parsing at.
        private static int ConsumeKeyValue(string[] lines, int lineIndex, string fieldText, int fieldIndent, Dictionary<string, string> targetMap)
        {
            int colonIndex = fieldText.IndexOf(':');
            if (colonIndex < 0)
            {
                return lineIndex;   // malformed line - ignore and move on
            }

            string key = fieldText.Substring(0, colonIndex).Trim();
            string value = fieldText.Substring(colonIndex + 1).Trim();

            if (value == "|" || value == "|-" || value == "|+")
            {
                StringBuilder blockBuilder = new StringBuilder();
                int? contentIndent = null;

                while (lineIndex < lines.Length)
                {
                    string blockLine = lines[lineIndex];

                    if (blockLine.Trim().Length == 0)
                    {
                        if (contentIndent == null)
                        {
                            lineIndex++;   // skip leading blank lines before the block starts
                            continue;
                        }

                        blockBuilder.Append("\n");
                        lineIndex++;
                        continue;
                    }

                    int blockLineIndent = IndentOf(blockLine);
                    if (contentIndent == null)
                    {
                        if (blockLineIndent <= fieldIndent)
                        {
                            break;   // block introduced but empty
                        }

                        contentIndent = blockLineIndent;
                    }

                    if (blockLineIndent < contentIndent.Value)
                    {
                        break;   // dedent - block has ended
                    }

                    blockBuilder.Append(blockLine.Substring(contentIndent.Value)).Append("\n");
                    lineIndex++;
                }

                targetMap[key] = blockBuilder.ToString();
                return lineIndex;
            }

            targetMap[key] = StripQuotes(value);
            return lineIndex;
        }

        private static string StripQuotes(string value)
        {
            if (value.Length >= 2)
            {
                char first = value[0];
                char last = value[value.Length - 1];
                if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
                {
                    return value.Substring(1, value.Length - 2);
                }
            }

            return value;
        }

        private static bool IsBlankOrComment(string line)
        {
            string trimmed = line.TrimStart();
            return trimmed.Length == 0 || trimmed[0] == '#';
        }

        private static int IndentOf(string line)
        {
            int count = 0;
            while (count < line.Length && line[count] == ' ')
            {
                count++;
            }

            return count;
        }
    }
}

// =============================================================================
// Unified directory-listing entry - shared between PhantomFSProvider
// and EnumerationSession (both at the global namespace level).
// =============================================================================

internal struct DirEntry
{
    public string Name;
    public bool IsSynthetic;
    public bool IsDirectory;
    public long FileSize;
    public long CreationTimeFiletime;
    public long LastAccessTimeFiletime;
    public long LastWriteTimeFiletime;
    public uint FileAttributes;
}

// =============================================================================
// EnumerationSession - tracks the cursor for a single directory enumeration.
// =============================================================================

internal sealed class EnumerationSession
{
    private readonly DirEntry[] _entries;
    private int _currentIndex;

    public EnumerationSession(DirEntry[] entries)
    {
        _entries = entries;
        _currentIndex = 0;
    }

    public void Reset()
    {
        _currentIndex = 0;
    }

    public void StepBack()
    {
        if (_currentIndex > 0)
        {
            _currentIndex--;
        }
    }

    public bool TryGetNext(out DirEntry entry)
    {
        if (_currentIndex < _entries.Length)
        {
            entry = _entries[_currentIndex++];
            return true;
        }

        entry = default(DirEntry);
        return false;
    }
}

// =============================================================================
// P/Invoke layer - ProjectedFSLib.dll
//
// All native structures are declared with explicit layouts that match the
// x64 headers, and callback data is marshaled through a typed
// PRJ_CALLBACK_DATA struct rather than raw pointer-offset arithmetic.
// =============================================================================

internal static class ProjectedFileSystemNative
{
    // ---- HRESULT values ----

    public const int HResultOk = 0;
    public const int HResultFail = unchecked((int)0x80004005);
    public const int HResultInsufficientBuffer = unchecked((int)0x8007007A);
    public const int HResultFileNotFound = unchecked((int)0x80070002);
    public const int HResultPathNotFound = unchecked((int)0x80070003);
    public const int HResultNotAReparsePoint = unchecked((int)0x80071126);

    // ---- PRJ_CALLBACK_DATA_FLAGS ----

    public const int CallbackDataFlagEnumRestartScan = 0x00000001;

    // ---- PRJ_UPDATE_TYPES flags ----
    // Passed to PrjDeleteFile / PrjUpdateFileIfNeeded to authorize acting on a
    // placeholder that has diverged from its virtual state.
    // DirtyMetadata = timestamps/attributes touched since the placeholder was created.
    // DirtyData     = the file's data stream was hydrated (read/cached) or modified.
    // Tombstone     = the path currently carries a deletion tombstone.
    // ReadOnly      = the file carries the read-only attribute.

    public const uint UpdateAllowDirtyMetadata = 0x00000001;
    public const uint UpdateAllowDirtyData = 0x00000002;
    public const uint UpdateAllowTombstone = 0x00000004;
    public const uint UpdateAllowReadOnly = 0x00000008;

    // ---- Callback delegates ----

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int StartDirectoryEnumerationCallback(
        ref CallbackData callbackData, ref Guid enumerationId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int EndDirectoryEnumerationCallback(
        ref CallbackData callbackData, ref Guid enumerationId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetDirectoryEnumerationCallback(
        ref CallbackData callbackData, ref Guid enumerationId,
        [MarshalAs(UnmanagedType.LPWStr)] string searchExpression,
        IntPtr dirEntryBufferHandle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetPlaceholderInfoCallback(ref CallbackData callbackData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int GetFileDataCallback(
        ref CallbackData callbackData, ulong byteOffset, uint length);

    // ---- Native structures ----

    // PRJ_CALLBACKS - pointer table registered with PrjStartVirtualizing.
    [StructLayout(LayoutKind.Sequential)]
    public struct CallbackTable
    {
        public IntPtr StartDirectoryEnumeration;
        public IntPtr EndDirectoryEnumeration;
        public IntPtr GetDirectoryEnumeration;
        public IntPtr GetPlaceholderInfo;
        public IntPtr GetFileData;
        public IntPtr QueryFileName;
        public IntPtr Notification;
        public IntPtr CancelCommand;
    }

    // PRJ_CALLBACK_DATA - x64 layout (explicit offsets; the two GUIDs are not
    // naturally 8-byte aligned, so Sequential layout would mis-place the
    // pointer fields that follow them).
    [StructLayout(LayoutKind.Explicit)]
    public struct CallbackData
    {
        [FieldOffset(0)]  public uint Size;
        [FieldOffset(4)]  public uint Flags;
        [FieldOffset(8)]  public IntPtr NamespaceVirtualizationContext;
        [FieldOffset(16)] public int CommandId;
        [FieldOffset(20)] public Guid FileId;
        [FieldOffset(36)] public Guid DataStreamId;
        [FieldOffset(56)] public IntPtr FilePathNamePtr;
        [FieldOffset(64)] public IntPtr VersionInfo;
        [FieldOffset(72)] public uint TriggeringProcessId;
        [FieldOffset(80)] public IntPtr TriggeringProcessImageFileNamePtr;
        [FieldOffset(88)] public IntPtr InstanceContext;

        public string FilePathName
        {
            get { return ReadWideString(FilePathNamePtr); }
        }

        public string TriggeringProcessImageFileName
        {
            get { return ReadWideString(TriggeringProcessImageFileNamePtr); }
        }
    }

    // PRJ_FILE_BASIC_INFO - MSVC x64 layout (56 bytes; the bool at offset 0 is
    // padded to 8 bytes before the LARGE_INTEGER fields).
    [StructLayout(LayoutKind.Explicit, Size = 56)]
    public struct FileBasicInfo
    {
        [FieldOffset(0)]  public byte IsDirectory;
        [FieldOffset(8)]  public long FileSize;
        [FieldOffset(16)] public long CreationTime;
        [FieldOffset(24)] public long LastAccessTime;
        [FieldOffset(32)] public long LastWriteTime;
        [FieldOffset(40)] public long ChangeTime;
        [FieldOffset(48)] public uint FileAttributes;
    }

    // PRJ_PLACEHOLDER_INFO - 344 bytes.  Only the leading FileBasicInfo block
    // is populated; the EA, security, streams, and version regions remain
    // zeroed, which ProjFS treats as "not supplied".
    [StructLayout(LayoutKind.Explicit, Size = 344)]
    public struct PlaceholderInfo
    {
        [FieldOffset(0)] public FileBasicInfo FileBasicInfo;
    }

    // ---- P/Invoke declarations ----

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjStartVirtualizing(
        string virtualizationRootPath,
        ref CallbackTable callbacks,
        IntPtr instanceContext,
        IntPtr options,
        out IntPtr namespaceVirtualizationContext);

    [DllImport("ProjectedFSLib.dll", ExactSpelling = true)]
    public static extern void PrjStopVirtualizing(IntPtr namespaceVirtualizationContext);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjMarkDirectoryAsPlaceholder(
        string rootPathName,
        string targetPathName,
        IntPtr versionInfo,
        ref Guid virtualizationInstanceId);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjWritePlaceholderInfo(
        IntPtr namespaceVirtualizationContext,
        string destinationFileName,
        ref PlaceholderInfo placeholderInfo,
        uint placeholderInfoSize);

    [DllImport("ProjectedFSLib.dll", ExactSpelling = true)]
    public static extern int PrjWriteFileData(
        IntPtr namespaceVirtualizationContext,
        ref Guid dataStreamId,
        IntPtr buffer,
        ulong byteOffset,
        uint length);

    [DllImport("ProjectedFSLib.dll", ExactSpelling = true)]
    public static extern IntPtr PrjAllocateAlignedBuffer(
        IntPtr namespaceVirtualizationContext, UIntPtr size);

    [DllImport("ProjectedFSLib.dll", ExactSpelling = true)]
    public static extern void PrjFreeAlignedBuffer(IntPtr buffer);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjFillDirEntryBuffer(
        string fileName, ref FileBasicInfo fileBasicInfo, IntPtr dirEntryBufferHandle);

    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PrjFileNameMatch(string fileNameToCheck, string pattern);

    // Discards the on-disk representation of a placeholder and returns the path
    // to a pure virtual entry. Despite the name, when the destination is a
    // placeholder (not a full file) this de-hydrates it: the cached data stream
    // is dropped WITHOUT creating a tombstone, so the entry stays visible in the
    // virtual directory and the next open re-triggers GetPlaceholderInfo and the
    // next read re-triggers GetFileData (and therefore a fresh alert).
    //
    // This is the correct primitive for reverting a read honeypot file.
    // PrjUpdateFileIfNeeded only rewrites placeholder metadata and can leave an
    // already-hydrated data stream in place, so a subsequent read is served from
    // the ProjFS cache without a callback.
    //
    // updateFlags authorizes acting on a placeholder that has diverged from its
    // virtual state (dirty data/metadata, tombstone, read-only). failureReason
    // receives a PRJ_UPDATE_FAILURE_CAUSES bitmask when the call returns a
    // failure HRESULT because the divergence was not authorized.
    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjDeleteFile(
        IntPtr namespaceVirtualizationContext,
        string destinationFileName,
        uint updateFlags,
        out uint failureReason);

    // Rewrites the metadata of an existing placeholder. Retained for reference;
    // NOT used for de-hydration because it does not reliably drop a hydrated
    // data stream (see PrjDeleteFile above).
    [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int PrjUpdateFileIfNeeded(
        IntPtr namespaceVirtualizationContext,
        string destinationFileName,
        ref PlaceholderInfo placeholderInfo,
        uint placeholderInfoSize,
        uint updateFlags,
        out uint failureReason);

    // ---- Helpers ----

    public static PlaceholderInfo BuildPlaceholderInfo(
        bool isDirectory, long fileSize,
        long creationTime, long lastAccessTime, long lastWriteTime, long changeTime,
        uint fileAttributes)
    {
        PlaceholderInfo info = new PlaceholderInfo();
        info.FileBasicInfo.IsDirectory = isDirectory ? (byte)1 : (byte)0;
        info.FileBasicInfo.FileSize = isDirectory ? 0L : fileSize;
        info.FileBasicInfo.CreationTime = creationTime;
        info.FileBasicInfo.LastAccessTime = lastAccessTime;
        info.FileBasicInfo.LastWriteTime = lastWriteTime;
        info.FileBasicInfo.ChangeTime = changeTime;
        info.FileBasicInfo.FileAttributes = fileAttributes;
        return info;
    }

    public static uint PlaceholderInfoSize
    {
        get { return (uint)Marshal.SizeOf(typeof(PlaceholderInfo)); }
    }

    public static string ReadWideString(IntPtr pointer)
    {
        return pointer == IntPtr.Zero ? null : Marshal.PtrToStringUni(pointer);
    }

    public static string DescribeHResult(int hresult)
    {
        switch (hresult)
        {
            case HResultOk:                 return "S_OK";
            case HResultFileNotFound:       return "FileNotFound";
            case HResultPathNotFound:       return "PathNotFound";
            case HResultInsufficientBuffer: return "InsufficientBuffer";
            case HResultNotAReparsePoint:   return "NotAReparsePoint";
            case HResultFail:               return "E_FAIL";
            default:                        return "0x" + ((uint)hresult).ToString("X8");
        }
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
        Console.WriteLine("  PhantomFS  -  Virtual Honeypot File System");
        Console.WriteLine("  " + new string('-', 50));
        Console.WriteLine();

        // Locate config
        System.Reflection.Assembly entryAssembly = System.Reflection.Assembly.GetEntryAssembly();
        string configPath = entryAssembly != null
            ? entryAssembly.Location + ".config"
            : Path.Combine(Directory.GetCurrentDirectory(), "PhantomFS.exe.config");

        Console.WriteLine("  Config   : " + configPath);

        // Load settings (always from the XML .config - this section is left alone)
        PhantomFSSettings.Load(configPath);

        // Parse CLI args - override config-embedded paths if supplied
        string sourceRoot = PhantomFSSettings.ConfigSourceRoot;
        string virtualRoot = PhantomFSSettings.ConfigVirtRoot;
        bool syntheticOnly = PhantomFSSettings.ConfigSyntheticOnly;
        bool forceService = false;
        string syntheticYamlPath = null;

        for (int argIndex = 0; argIndex < args.Length; argIndex++)
        {
            string flag = args[argIndex];
            if (flag.Equals("--syntheticonly", StringComparison.OrdinalIgnoreCase))
            {
                syntheticOnly = true;
                continue;
            }

            if (flag.Equals("--service", StringComparison.OrdinalIgnoreCase))
            {
                // Force non-interactive mode regardless of Environment.UserInteractive.
                // Use this when launched by Task Scheduler or a service host so the
                // process blocks until stopped instead of reading stdin.
                forceService = true;
                continue;
            }

            if (argIndex + 1 >= args.Length)
            {
                continue;
            }

            string value = args[argIndex + 1];
            if (flag.Equals("--sourceroot", StringComparison.OrdinalIgnoreCase))
            {
                sourceRoot = value;
                argIndex++;
            }
            else if (flag.Equals("--virtroot", StringComparison.OrdinalIgnoreCase))
            {
                virtualRoot = value;
                argIndex++;
            }
            else if (flag.Equals("--syntheticyaml", StringComparison.OrdinalIgnoreCase))
            {
                // Opt-in override: load the synthetic file list and content
                // templates from this YAML file instead of the <syntheticFileList>
                // and <syntheticTemplates> blocks in PhantomFS.exe.config. The
                // <settings> section of the XML config is still used as-is.
                syntheticYamlPath = value;
                argIndex++;
            }
        }

        // Optional config-embedded fallback, for parity with virtRoot/sourceRoot -
        // lets a scheduled task or service pin the YAML path without CLI args.
        if (syntheticYamlPath == null)
        {
            syntheticYamlPath = ReadOptionalSetting(configPath, "syntheticYamlPath");
        }

        // Load synthetic data + content templates, either from the YAML file
        // (when supplied) or from the untouched XML <syntheticFileList> /
        // <syntheticTemplates> blocks. This is the only branch point introduced
        // by YAML support - everything else behaves exactly as before.
        SyntheticData syntheticData;
        if (syntheticYamlPath != null)
        {
            Console.WriteLine("  YAML     : " + syntheticYamlPath);
            SyntheticContent.LoadFromYaml(syntheticYamlPath);
            syntheticData = SyntheticData.LoadFromYaml(syntheticYamlPath);
        }
        else
        {
            SyntheticContent.LoadFromConfig(configPath);
            syntheticData = SyntheticData.LoadFromConfig(configPath);
        }

        if (syntheticData != null)
        {
            Console.WriteLine("  Entries  : " + syntheticData.EntryCount + " synthetic files/dirs");
        }

        if (virtualRoot == null)
        {
            PrintUsage();
            return 1;
        }

        if (!syntheticOnly && sourceRoot == null)
        {
            Console.Error.WriteLine("[ERROR] --sourceroot required unless --syntheticonly");
            PrintUsage();
            return 1;
        }

        if (syntheticOnly && syntheticData == null)
        {
            Console.Error.WriteLine("[ERROR] --syntheticonly requires synthetic file entries "
                + "(either <syntheticFileList> in config, or --syntheticyaml)");
            return 1;
        }

        // Initialise alert channels
        AlertManager.Initialize();

        // Create and start the provider
        PhantomFSProvider provider;
        try
        {
            provider = new PhantomFSProvider(sourceRoot, virtualRoot, syntheticData, syntheticOnly);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("[ERROR] " + exception.Message);
            return 1;
        }

        int startResult = provider.StartVirtualizing();
        if (startResult != ProjectedFileSystemNative.HResultOk)
        {
            Console.Error.WriteLine("[ERROR] PrjStartVirtualizing failed: "
                + ProjectedFileSystemNative.DescribeHResult(startResult));
            if (startResult == ProjectedFileSystemNative.HResultNotAReparsePoint)
            {
                Console.Error.WriteLine("        Run: rmdir /s /q \"" + Path.GetFullPath(virtualRoot) + "\"");
            }
            else
            {
                Console.Error.WriteLine("        Ensure Client-ProjFS is enabled and this process is elevated.");
            }

            return 1;
        }

        // Whether a real interactive console is attached. When launched by Task
        // Scheduler as SYSTEM there is no console: stdin is closed and
        // Console.ReadLine() returns null immediately, which would make the
        // process fall through and exit right after starting. In that case block
        // on a signal instead and keep running until the task/service is stopped.
        // --service forces this path even when UserInteractive misreports.
        bool interactive = Environment.UserInteractive && !forceService;

        Console.WriteLine();
        Console.WriteLine("  [OK] Provider running.");
        Console.WriteLine("  VirtRoot : " + Path.GetFullPath(virtualRoot));
        if (!syntheticOnly)
        {
            Console.WriteLine("  Source   : " + Path.GetFullPath(sourceRoot));
        }

        Console.WriteLine("  Mode     : " + (syntheticOnly ? "synthetic-only" : "mixed"));
        Console.WriteLine("  EventLog : " + PhantomFSSettings.EnableEventLog
                        + "   Toast : " + PhantomFSSettings.EnableToast);
        Console.WriteLine("  Cleanup  : "
            + (PhantomFSSettings.AutoCleanupEnabled
                ? "enabled - " + PhantomFSSettings.AutoCleanupDelaySeconds + "s delay"
                : "disabled"));
        Console.WriteLine();
        Console.WriteLine(interactive
            ? "  Press ENTER to stop..."
            : "  Running non-interactively. Stop the task/service to shut down.");

        AlertManager.OnProviderStarted(Path.GetFullPath(virtualRoot));

        // Signal released to unblock the main thread during shutdown.
        ManualResetEvent shutdownSignal = new ManualResetEvent(false);

        // Guarantee shutdown cleanup on Ctrl+C and on normal process exit, not
        // just on ENTER. StopVirtualizing is idempotent, so overlapping paths
        // are safe. ProcessExit is what fires when Task Scheduler ends the task
        // or the service host stops the process.
        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;   // run our cleanup instead of a hard kill
            Console.WriteLine();
            Console.WriteLine("  Ctrl+C received - stopping...");
            shutdownSignal.Set();
        };
        AppDomain.CurrentDomain.ProcessExit += delegate(object sender, EventArgs eventArgs)
        {
            AlertManager.OnProviderStopped(Path.GetFullPath(virtualRoot));
            provider.StopVirtualizing();
            shutdownSignal.Set();
        };

        if (interactive)
        {
            // Block on ENTER, but fall back to the signal if stdin returns null
            // (redirected or closed input) so the process never spins or exits early.
            if (Console.ReadLine() == null)
            {
                shutdownSignal.WaitOne();
            }
        }
        else
        {
            // No console: wait until ProcessExit or a stop signal releases us.
            shutdownSignal.WaitOne();
        }

        AlertManager.OnProviderStopped(Path.GetFullPath(virtualRoot));
        provider.StopVirtualizing();
        Console.WriteLine("  PhantomFS stopped.");
        return 0;
    }

    // Reads a single optional top-level <settings> element that PhantomFSSettings
    // itself does not know about yet. Kept separate (rather than growing
    // PhantomFSSettings) so the well-known settings block stays exactly as it
    // was; this is purely additive and silently returns null on any failure.
    private static string ReadOptionalSetting(string configPath, string elementName)
    {
        if (!File.Exists(configPath))
        {
            return null;
        }

        try
        {
            XmlDocument configDocument = new XmlDocument();
            configDocument.Load(configPath);
            XmlNode node = configDocument.SelectSingleNode("/configuration/settings/" + elementName);
            if (node == null)
            {
                return null;
            }

            string value = node.InnerText.Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        catch
        {
            return null;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine("  Usage:");
        Console.WriteLine("    PhantomFS.exe --virtroot <path> [--sourceroot <path>] [--syntheticonly] [--service] [--syntheticyaml <path>]");
        Console.WriteLine();
        Console.WriteLine("  Options:");
        Console.WriteLine("    --virtroot     <path>   Directory where virtual files appear.");
        Console.WriteLine("    --sourceroot   <path>   Real files to mirror alongside synthetic ones.");
        Console.WriteLine("    --syntheticonly         Serve only config-defined synthetic files.");
        Console.WriteLine("    --service               Run non-interactively (Task Scheduler / service).");
        Console.WriteLine("    --syntheticyaml <path>  Load the synthetic file list and content");
        Console.WriteLine("                            templates from a YAML file instead of the");
        Console.WriteLine("                            <syntheticFileList> / <syntheticTemplates>");
        Console.WriteLine("                            blocks in PhantomFS.exe.config.");
        Console.WriteLine();
        Console.WriteLine("  Notes:");
        Console.WriteLine("    * Requires Administrator.");
        Console.WriteLine("    * Paths can also be set in PhantomFS.exe.config <settings>.");
        Console.WriteLine("    * <settings><syntheticYamlPath> is the config-file equivalent of");
        Console.WriteLine("      --syntheticyaml, for scheduled tasks that run without CLI args.");
        Console.WriteLine("    * Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart");
    }
}

// =============================================================================
// PhantomFSProvider - ProjFS provider implementation
// =============================================================================

internal sealed class PhantomFSProvider
{
    private readonly string _sourceRoot;
    private readonly string _virtualRoot;
    private readonly SyntheticData _syntheticData;
    private readonly bool _syntheticOnly;
    private IntPtr _virtualizationContext;

    private readonly ConcurrentDictionary<Guid, EnumerationSession> _enumerationSessions =
        new ConcurrentDictionary<Guid, EnumerationSession>();

    // Tracks synthetic files that have been materialized to disk, keyed by
    // their relative path.  The value is the UTC time of first hydration.
    // The cleanup timer reads and removes entries from this dictionary on its
    // own thread - ConcurrentDictionary ensures thread safety.
    private readonly ConcurrentDictionary<string, DateTime> _materializedFiles =
        new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

    private Timer _cleanupTimer;
    private readonly object _shutdownLock = new object();
    private bool _markedAsPlaceholderRoot;

    private static PhantomFSProvider _current;

    // Delegate fields prevent GC while ProjFS callbacks are active.
    private readonly ProjectedFileSystemNative.StartDirectoryEnumerationCallback _startEnumerationCallback;
    private readonly ProjectedFileSystemNative.EndDirectoryEnumerationCallback _endEnumerationCallback;
    private readonly ProjectedFileSystemNative.GetDirectoryEnumerationCallback _getEnumerationCallback;
    private readonly ProjectedFileSystemNative.GetPlaceholderInfoCallback _getPlaceholderInfoCallback;
    private readonly ProjectedFileSystemNative.GetFileDataCallback _getFileDataCallback;

    public PhantomFSProvider(
        string sourceRoot, string virtualRoot,
        SyntheticData syntheticData, bool syntheticOnly)
    {
        _syntheticOnly = syntheticOnly;
        _syntheticData = syntheticData;
        _virtualRoot = Path.GetFullPath(virtualRoot);

        if (syntheticOnly)
        {
            _sourceRoot = string.Empty;
        }
        else
        {
            if (!Directory.Exists(sourceRoot))
            {
                throw new ArgumentException("Source root does not exist: " + sourceRoot);
            }

            _sourceRoot = Path.GetFullPath(sourceRoot);
        }

        Directory.CreateDirectory(_virtualRoot);

        _startEnumerationCallback = StartEnumerationThunk;
        _endEnumerationCallback = EndEnumerationThunk;
        _getEnumerationCallback = GetEnumerationThunk;
        _getPlaceholderInfoCallback = GetPlaceholderInfoThunk;
        _getFileDataCallback = GetFileDataThunk;
    }

    public int StartVirtualizing()
    {
        _current = this;

        // REAL-FILE GUARD 1: the virtroot and sourceroot must never overlap.
        // A nested or identical pair would let the projection and cleanup
        // machinery operate over real files.
        if (!_syntheticOnly && PathsOverlap(_virtualRoot, _sourceRoot))
        {
            Console.Error.WriteLine("[ABORT] --virtroot and --sourceroot overlap:");
            Console.Error.WriteLine("        virtroot   = " + _virtualRoot);
            Console.Error.WriteLine("        sourceroot = " + _sourceRoot);
            Console.Error.WriteLine("        Choose two unrelated directories.");
            return ProjectedFileSystemNative.HResultFail;
        }

        // REAL-FILE GUARD 2: only ever delete a pre-existing virtroot when it
        // is provably stale ProjFS state from a previous run, identified by
        // the reparse-point attribute that PrjMarkDirectoryAsPlaceholder sets
        // on the root.  A normal directory containing content is real data:
        // it is never deleted here, with or without confirmation.
        if (Directory.Exists(_virtualRoot))
        {
            bool isProjectionRoot =
                (File.GetAttributes(_virtualRoot) & FileAttributes.ReparsePoint) != 0;
            bool isEmpty = Directory.GetFileSystemEntries(_virtualRoot).Length == 0;

            if (isProjectionRoot)
            {
                // Stale state from a previous PhantomFS run.  Clearing it
                // prevents HResultNotAReparsePoint on restart.
                Console.WriteLine("  Clearing stale ProjFS virtroot: " + _virtualRoot);
                try
                {
                    Directory.Delete(_virtualRoot, true);
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine("[WARN] " + exception.Message);
                }
            }
            else if (!isEmpty)
            {
                Console.Error.WriteLine("[ABORT] VirtRoot exists, is not a ProjFS root, and is not empty:");
                Console.Error.WriteLine("        " + _virtualRoot);
                Console.Error.WriteLine("        Refusing to touch it - it may contain real data.");
                Console.Error.WriteLine("        Point --virtroot at a new or empty directory.");
                return ProjectedFileSystemNative.HResultFail;
            }
        }

        Directory.CreateDirectory(_virtualRoot);

        Guid virtualizationInstanceId = Guid.NewGuid();
        int markResult = ProjectedFileSystemNative.PrjMarkDirectoryAsPlaceholder(
            _virtualRoot, null, IntPtr.Zero, ref virtualizationInstanceId);
        if (markResult != ProjectedFileSystemNative.HResultOk)
        {
            Console.Error.WriteLine("[ERROR] PrjMark: " + ProjectedFileSystemNative.DescribeHResult(markResult));
            return markResult;
        }

        // From this point the directory is a ProjFS placeholder root created by
        // this instance, so shutdown is allowed to remove it.
        _markedAsPlaceholderRoot = true;

        ProjectedFileSystemNative.CallbackTable callbacks = new ProjectedFileSystemNative.CallbackTable();
        callbacks.StartDirectoryEnumeration = Marshal.GetFunctionPointerForDelegate(_startEnumerationCallback);
        callbacks.EndDirectoryEnumeration = Marshal.GetFunctionPointerForDelegate(_endEnumerationCallback);
        callbacks.GetDirectoryEnumeration = Marshal.GetFunctionPointerForDelegate(_getEnumerationCallback);
        callbacks.GetPlaceholderInfo = Marshal.GetFunctionPointerForDelegate(_getPlaceholderInfoCallback);
        callbacks.GetFileData = Marshal.GetFunctionPointerForDelegate(_getFileDataCallback);

        int startResult = ProjectedFileSystemNative.PrjStartVirtualizing(
            _virtualRoot, ref callbacks, IntPtr.Zero, IntPtr.Zero, out _virtualizationContext);

        if (startResult == ProjectedFileSystemNative.HResultOk && PhantomFSSettings.AutoCleanupEnabled)
        {
            // Check every 30 seconds; revert files older than AutoCleanupDelaySeconds.
            _cleanupTimer = new Timer(
                CleanupCallback, null,
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));
            Log("[CLEANUP] Timer started - delay=" + PhantomFSSettings.AutoCleanupDelaySeconds + "s");
        }

        return startResult;
    }

    // Stops the provider and guarantees that no synthetic content remains on
    // disk afterwards:
    //   1. While the virtualization context is still live, every materialized
    //      synthetic file is reverted to an unhydrated placeholder (reverts
    //      require an active context, so this must happen before stopping).
    //   2. The provider is stopped.
    //   3. The virtroot is deleted.  The virtroot is purely a projection: in
    //      synthetic-only mode it contains nothing real, and in mixed mode it
    //      contains only placeholders whose real content lives untouched in
    //      the source root.  The directory is only deleted when this instance
    //      marked it as a placeholder root, never an arbitrary path.
    // Safe to call multiple times; subsequent calls are no-ops.
    public void StopVirtualizing()
    {
        lock (_shutdownLock)
        {
            if (_cleanupTimer != null)
            {
                _cleanupTimer.Dispose();
                _cleanupTimer = null;
            }

            if (_virtualizationContext == IntPtr.Zero)
            {
                return;
            }

            // Final revert pass: ignore the configured delay and retry briefly
            // so files held open by a reader still get reverted once released.
            const int MaxFinalPassAttempts = 5;
            for (int attempt = 0; attempt < MaxFinalPassAttempts && !_materializedFiles.IsEmpty; attempt++)
            {
                if (attempt > 0)
                {
                    Thread.Sleep(500);
                }

                foreach (KeyValuePair<string, DateTime> materializedFile in _materializedFiles)
                {
                    RevertToPlaceholder(materializedFile.Key);
                }
            }

            if (!_materializedFiles.IsEmpty)
            {
                Console.Error.WriteLine("[WARN] " + _materializedFiles.Count
                    + " synthetic file(s) could not be reverted before stop (still open?).");
            }

            ProjectedFileSystemNative.PrjStopVirtualizing(_virtualizationContext);
            _virtualizationContext = IntPtr.Zero;

            RemoveProjectionRoot();
        }
    }

    // Deletes the virtroot directory tree after the provider has stopped.
    // Only runs when this instance itself marked the directory as a ProjFS
    // placeholder root, so an arbitrary directory can never be deleted here.
    private void RemoveProjectionRoot()
    {
        if (!_markedAsPlaceholderRoot)
        {
            return;
        }

        try
        {
            if (Directory.Exists(_virtualRoot))
            {
                Directory.Delete(_virtualRoot, true);
                Console.WriteLine("  Projection root removed: " + _virtualRoot);
            }

            _markedAsPlaceholderRoot = false;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("[WARN] Could not remove projection root "
                + _virtualRoot + " - " + exception.Message);
            Console.Error.WriteLine("       Remove it manually: rmdir /s /q \"" + _virtualRoot + "\"");
        }
    }

    // ---- Auto-cleanup callback ----

    // Runs on a thread-pool thread every 30 seconds.
    // For each synthetic file whose first-hydration time exceeds
    // AutoCleanupDelaySeconds, de-hydrates it back to a pure virtual entry via
    // RevertToPlaceholder (PrjDeleteFile).
    //
    // Why PrjDeleteFile instead of File.Delete:
    //   File.Delete on a ProjFS placeholder creates a tombstone: a reparse
    //   marker that blocks re-projection of that path until it is cleared.
    //   Deleted files therefore disappear from the virtual directory and never
    //   trigger alerts again. PrjDeleteFile with the dirty-data flag drops the
    //   hydrated data stream WITHOUT a tombstone, so the file stays visible in
    //   directory listings and the next read fires a fresh GetFileData callback
    //   (and therefore a fresh alert).
    private void CleanupCallback(object state)
    {
        if (!PhantomFSSettings.AutoCleanupEnabled)
        {
            return;
        }

        if (_syntheticData == null || _virtualizationContext == IntPtr.Zero)
        {
            return;
        }

        TimeSpan cleanupThreshold = TimeSpan.FromSeconds(PhantomFSSettings.AutoCleanupDelaySeconds);
        DateTime now = DateTime.UtcNow;

        foreach (KeyValuePair<string, DateTime> materializedFile in _materializedFiles)
        {
            if ((now - materializedFile.Value) < cleanupThreshold)
            {
                continue;
            }

            RevertToPlaceholder(materializedFile.Key);
        }
    }

    // De-hydrates one materialized synthetic file back to a pure virtual entry.
    // Returns true when the file was reverted (or safely skipped) and its entry
    // removed from the tracking dictionary; false when it should be retried.
    //
    // Uses PrjDeleteFile, which drops the hydrated data stream without leaving a
    // tombstone. The entry stays visible and the next read re-triggers
    // GetFileData and a fresh alert. PrjUpdateFileIfNeeded was tried first but
    // only rewrote placeholder metadata: it left the cached data stream in place,
    // so re-reads were served from cache with no callback and no alert.
    //
    // REAL-FILE GUARD: a path is never reverted when a real source file exists
    // behind it in mixed mode.  Real files are served by the real branch of
    // OnGetFileData and are never added to _materializedFiles, but this guard
    // ensures that even a tracking bug or a real file appearing at a formerly
    // synthetic path after startup can never lead to PrjDeleteFile touching
    // real-backed content.
    private bool RevertToPlaceholder(string relativePath)
    {
        DateTime removedValue;

        if (!_syntheticOnly && File.Exists(GetSourcePath(relativePath)))
        {
            Log("[CLEANUP] Skipped (real source file exists): " + relativePath);
            _materializedFiles.TryRemove(relativePath, out removedValue);
            return true;
        }

        SyntheticEntry entry = _syntheticData != null ? _syntheticData.Find(relativePath) : null;
        if (entry == null || entry.IsDirectory)
        {
            _materializedFiles.TryRemove(relativePath, out removedValue);
            return true;
        }

        // DirtyData     - the data stream was hydrated by the earlier read
        // DirtyMetadata - timestamps may have been touched
        // Tombstone     - authorize the edge case where a tombstone already exists
        uint failureReason;
        int revertResult = ProjectedFileSystemNative.PrjDeleteFile(
            _virtualizationContext,
            relativePath,
              ProjectedFileSystemNative.UpdateAllowDirtyData
            | ProjectedFileSystemNative.UpdateAllowDirtyMetadata
            | ProjectedFileSystemNative.UpdateAllowTombstone,
            out failureReason);

        if (revertResult == ProjectedFileSystemNative.HResultOk)
        {
            Log("[CLEANUP] Reverted to placeholder: " + relativePath);
            _materializedFiles.TryRemove(relativePath, out removedValue);
            return true;
        }

        // File is likely still open. Leave in the dictionary so it is retried.
        Log("[CLEANUP] Revert failed: " + relativePath
            + " - " + ProjectedFileSystemNative.DescribeHResult(revertResult)
            + " (failureReason=0x" + failureReason.ToString("X") + ")");
        return false;
    }

    // ---- Static thunks ----
    // ProjFS callbacks must never let a managed exception cross the native
    // boundary; each thunk converts failures to E_FAIL.

    private static int StartEnumerationThunk(
        ref ProjectedFileSystemNative.CallbackData callbackData, ref Guid enumerationId)
    {
        try { return _current.OnStartEnumeration(ref callbackData, enumerationId); }
        catch { return ProjectedFileSystemNative.HResultFail; }
    }

    private static int EndEnumerationThunk(
        ref ProjectedFileSystemNative.CallbackData callbackData, ref Guid enumerationId)
    {
        try { return _current.OnEndEnumeration(enumerationId); }
        catch { return ProjectedFileSystemNative.HResultFail; }
    }

    private static int GetEnumerationThunk(
        ref ProjectedFileSystemNative.CallbackData callbackData, ref Guid enumerationId,
        string searchExpression, IntPtr dirEntryBufferHandle)
    {
        try { return _current.OnGetEnumeration(ref callbackData, enumerationId, searchExpression, dirEntryBufferHandle); }
        catch { return ProjectedFileSystemNative.HResultFail; }
    }

    private static int GetPlaceholderInfoThunk(ref ProjectedFileSystemNative.CallbackData callbackData)
    {
        try { return _current.OnGetPlaceholderInfo(ref callbackData); }
        catch { return ProjectedFileSystemNative.HResultFail; }
    }

    private static int GetFileDataThunk(
        ref ProjectedFileSystemNative.CallbackData callbackData, ulong byteOffset, uint length)
    {
        try { return _current.OnGetFileData(ref callbackData, byteOffset, length); }
        catch { return ProjectedFileSystemNative.HResultFail; }
    }

    // ---- Callback implementations ----

    private int OnStartEnumeration(
        ref ProjectedFileSystemNative.CallbackData callbackData, Guid enumerationId)
    {
        string relativePath = callbackData.FilePathName ?? string.Empty;
        Log("StartEnum [" + relativePath + "]");

        List<DirEntry> allEntries = new List<DirEntry>();

        if (!_syntheticOnly)
        {
            string fullSourcePath = GetSourcePath(relativePath);
            if (Directory.Exists(fullSourcePath))
            {
                try
                {
                    foreach (FileSystemInfo fileSystemInfo in new DirectoryInfo(fullSourcePath).GetFileSystemInfos())
                    {
                        allEntries.Add(CreateRealEntry(fileSystemInfo));
                    }
                }
                catch (Exception exception)
                {
                    Log("[WARN] " + exception.Message);
                }
            }
        }

        if (_syntheticData != null)
        {
            foreach (SyntheticEntry syntheticEntry in _syntheticData.GetChildren(relativePath))
            {
                if (!NameExists(allEntries, syntheticEntry.Name))
                {
                    allEntries.Add(CreateSyntheticEntry(syntheticEntry));
                }
            }
        }

        allEntries.Sort(delegate(DirEntry left, DirEntry right)
        {
            return string.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
        });

        _enumerationSessions[enumerationId] = new EnumerationSession(allEntries.ToArray());
        return ProjectedFileSystemNative.HResultOk;
    }

    private int OnEndEnumeration(Guid enumerationId)
    {
        EnumerationSession removedSession;
        _enumerationSessions.TryRemove(enumerationId, out removedSession);
        return ProjectedFileSystemNative.HResultOk;
    }

    private int OnGetEnumeration(
        ref ProjectedFileSystemNative.CallbackData callbackData, Guid enumerationId,
        string searchExpression, IntPtr dirEntryBufferHandle)
    {
        string filter = searchExpression ?? string.Empty;

        EnumerationSession session;
        if (!_enumerationSessions.TryGetValue(enumerationId, out session))
        {
            return ProjectedFileSystemNative.HResultFail;
        }

        if ((callbackData.Flags & ProjectedFileSystemNative.CallbackDataFlagEnumRestartScan) != 0)
        {
            session.Reset();
        }

        DirEntry entry;
        while (session.TryGetNext(out entry))
        {
            if (!string.IsNullOrEmpty(filter)
                && !ProjectedFileSystemNative.PrjFileNameMatch(entry.Name, filter))
            {
                continue;
            }

            ProjectedFileSystemNative.FileBasicInfo basicInfo = new ProjectedFileSystemNative.FileBasicInfo();
            basicInfo.IsDirectory = entry.IsDirectory ? (byte)1 : (byte)0;
            basicInfo.FileSize = entry.FileSize;
            basicInfo.CreationTime = entry.CreationTimeFiletime;
            basicInfo.LastAccessTime = entry.LastAccessTimeFiletime;
            basicInfo.LastWriteTime = entry.LastWriteTimeFiletime;
            basicInfo.ChangeTime = entry.LastWriteTimeFiletime;
            basicInfo.FileAttributes = entry.FileAttributes;

            int fillResult = ProjectedFileSystemNative.PrjFillDirEntryBuffer(
                entry.Name, ref basicInfo, dirEntryBufferHandle);
            if (fillResult == ProjectedFileSystemNative.HResultInsufficientBuffer)
            {
                session.StepBack();
                break;
            }

            if (fillResult != ProjectedFileSystemNative.HResultOk)
            {
                return fillResult;
            }
        }

        return ProjectedFileSystemNative.HResultOk;
    }

    private int OnGetPlaceholderInfo(ref ProjectedFileSystemNative.CallbackData callbackData)
    {
        string relativePath = callbackData.FilePathName ?? string.Empty;
        string processName = callbackData.TriggeringProcessImageFileName;
        uint processId = callbackData.TriggeringProcessId;
        IntPtr virtualizationContext = callbackData.NamespaceVirtualizationContext;

        Log("GetPlaceholderInfo [" + relativePath + "] proc=" + processName + " pid=" + processId);

        // Detect SMB/network access - PID 4 is the Windows System process, which
        // is the triggering PID when the kernel SMB driver (srv2.sys) opens a file.
        List<RemoteSessionHelper.SessionInfo> sessions = null;
        if (RemoteSessionHelper.IsLikelyRemote(processId, processName))
        {
            sessions = RemoteSessionHelper.GetActiveSessions();
        }

        // -- Real source --------------------------------------------------------------
        if (!_syntheticOnly)
        {
            FileSystemInfo fileSystemInfo = GetSourceFileSystemInfo(GetSourcePath(relativePath));
            if (fileSystemInfo != null)
            {
                bool isDirectory = (fileSystemInfo.Attributes & FileAttributes.Directory) != 0;
                long fileSize = isDirectory ? 0L : ((FileInfo)fileSystemInfo).Length;
                ProjectedFileSystemNative.PlaceholderInfo placeholder =
                    ProjectedFileSystemNative.BuildPlaceholderInfo(
                        isDirectory, fileSize,
                        fileSystemInfo.CreationTime.ToFileTime(),
                        fileSystemInfo.LastAccessTime.ToFileTime(),
                        fileSystemInfo.LastWriteTime.ToFileTime(),
                        fileSystemInfo.LastWriteTime.ToFileTime(),
                        (uint)fileSystemInfo.Attributes & 0xFFFF);

                int writeResult = ProjectedFileSystemNative.PrjWritePlaceholderInfo(
                    virtualizationContext, relativePath,
                    ref placeholder, ProjectedFileSystemNative.PlaceholderInfoSize);
                Log("Phi(real) " + ProjectedFileSystemNative.DescribeHResult(writeResult));
                return writeResult;
            }
        }

        // -- Synthetic ----------------------------------------------------------------
        if (_syntheticData != null)
        {
            SyntheticEntry syntheticEntry = _syntheticData.Find(relativePath);
            if (syntheticEntry != null)
            {
                long filetime = syntheticEntry.GetFiletime();
                ProjectedFileSystemNative.PlaceholderInfo placeholder =
                    ProjectedFileSystemNative.BuildPlaceholderInfo(
                        syntheticEntry.IsDirectory,
                        syntheticEntry.IsDirectory ? 0L : syntheticEntry.FileSize,
                        filetime, filetime, filetime, filetime,
                        syntheticEntry.IsDirectory ? 0x10u : 0x20u);

                int writeResult = ProjectedFileSystemNative.PrjWritePlaceholderInfo(
                    virtualizationContext, relativePath,
                    ref placeholder, ProjectedFileSystemNative.PlaceholderInfoSize);
                if (writeResult == ProjectedFileSystemNative.HResultOk && !syntheticEntry.IsDirectory)
                {
                    AlertManager.OnPlaceholderCreated(relativePath, processName, processId, sessions);
                }

                Log("Phi(synthetic) " + ProjectedFileSystemNative.DescribeHResult(writeResult));
                return writeResult;
            }
        }

        return ProjectedFileSystemNative.HResultFileNotFound;
    }

    private int OnGetFileData(
        ref ProjectedFileSystemNative.CallbackData callbackData, ulong byteOffset, uint length)
    {
        string relativePath = callbackData.FilePathName ?? string.Empty;
        string processName = callbackData.TriggeringProcessImageFileName;
        uint processId = callbackData.TriggeringProcessId;
        IntPtr virtualizationContext = callbackData.NamespaceVirtualizationContext;
        Guid dataStreamId = callbackData.DataStreamId;

        Log("GetFileData [" + relativePath + "] offset=" + byteOffset + " len=" + length);

        // Detect SMB/network access - PID 4 indicates the kernel SMB driver.
        List<RemoteSessionHelper.SessionInfo> sessions = null;
        if (RemoteSessionHelper.IsLikelyRemote(processId, processName))
        {
            sessions = RemoteSessionHelper.GetActiveSessions();
        }

        // PRIMARY ALERT - a process is reading honeypot file content
        AlertManager.OnFileAccessed(relativePath, processId, processName, sessions);

        // -- Real source --------------------------------------------------------------
        if (!_syntheticOnly)
        {
            string fullSourcePath = GetSourcePath(relativePath);
            if (File.Exists(fullSourcePath))
            {
                byte[] fileData;
                try
                {
                    fileData = File.ReadAllBytes(fullSourcePath);
                }
                catch (Exception exception)
                {
                    Log("[WARN] Read error - " + exception.Message);
                    return ProjectedFileSystemNative.HResultFail;
                }

                return WriteFileData(virtualizationContext, ref dataStreamId, fileData, byteOffset, length);
            }
        }

        // -- Synthetic content --------------------------------------------------------
        if (_syntheticData != null)
        {
            SyntheticEntry syntheticEntry = _syntheticData.Find(relativePath);
            if (syntheticEntry != null && !syntheticEntry.IsDirectory)
            {
                byte[] slice = SyntheticContent.GenerateSlice(
                    syntheticEntry.Name,
                    syntheticEntry.FileSize,
                    byteOffset,
                    length);
                int writeResult = WriteFileDataChunk(
                    virtualizationContext,
                    ref dataStreamId,
                    slice,
                    byteOffset);

                // Record the materialization time so the cleanup timer can revert
                // this file back to a virtual placeholder after the configured delay.
                // TryAdd is a no-op if the key already exists - we only want the
                // time of first hydration, not the most recent partial read.
                if (writeResult == ProjectedFileSystemNative.HResultOk && PhantomFSSettings.AutoCleanupEnabled)
                {
                    _materializedFiles.TryAdd(relativePath, DateTime.UtcNow);
                }

                return writeResult;
            }
        }

        return ProjectedFileSystemNative.HResultFileNotFound;
    }

    private int WriteFileDataChunk(
        IntPtr virtualizationContext, ref Guid dataStreamId,
        byte[] dataChunk, ulong destinationOffset)
    {
        uint chunkLength = dataChunk != null ? (uint)dataChunk.Length : 0u;
        if (chunkLength == 0)
        {
            return ProjectedFileSystemNative.HResultOk;
        }

        IntPtr alignedBuffer = ProjectedFileSystemNative.PrjAllocateAlignedBuffer(
            virtualizationContext, new UIntPtr(chunkLength));
        if (alignedBuffer == IntPtr.Zero)
        {
            return ProjectedFileSystemNative.HResultFail;
        }

        try
        {
            Marshal.Copy(dataChunk, 0, alignedBuffer, (int)chunkLength);
            return ProjectedFileSystemNative.PrjWriteFileData(
                virtualizationContext, ref dataStreamId, alignedBuffer, destinationOffset, chunkLength);
        }
        finally
        {
            ProjectedFileSystemNative.PrjFreeAlignedBuffer(alignedBuffer);
        }
    }

    private int WriteFileData(
        IntPtr virtualizationContext, ref Guid dataStreamId,
        byte[] data, ulong byteOffset, uint length)
    {
        uint startOffset = (uint)byteOffset;
        uint endOffset = startOffset + length;
        if (endOffset > (uint)data.Length)
        {
            endOffset = (uint)data.Length;
        }

        uint bytesToWrite = endOffset > startOffset ? endOffset - startOffset : 0u;
        if (bytesToWrite == 0)
        {
            return ProjectedFileSystemNative.HResultOk;
        }

        IntPtr alignedBuffer = ProjectedFileSystemNative.PrjAllocateAlignedBuffer(
            virtualizationContext, new UIntPtr(bytesToWrite));
        if (alignedBuffer == IntPtr.Zero)
        {
            return ProjectedFileSystemNative.HResultFail;
        }

        try
        {
            Marshal.Copy(data, (int)startOffset, alignedBuffer, (int)bytesToWrite);
            return ProjectedFileSystemNative.PrjWriteFileData(
                virtualizationContext, ref dataStreamId, alignedBuffer, byteOffset, bytesToWrite);
        }
        finally
        {
            ProjectedFileSystemNative.PrjFreeAlignedBuffer(alignedBuffer);
        }
    }

    // ---- Helpers ----

    private string GetSourcePath(string relativePath)
    {
        return string.IsNullOrEmpty(relativePath)
            ? _sourceRoot
            : Path.Combine(_sourceRoot, relativePath);
    }

    // Returns true when either path equals or is nested inside the other.
    // Comparison is ordinal case-insensitive on normalized full paths with a
    // trailing separator, so "C:\Data" does not falsely match "C:\Database".
    private static bool PathsOverlap(string firstPath, string secondPath)
    {
        if (string.IsNullOrEmpty(firstPath) || string.IsNullOrEmpty(secondPath))
        {
            return false;
        }

        string first = NormalizeForComparison(firstPath);
        string second = NormalizeForComparison(secondPath);
        return first.StartsWith(second, StringComparison.OrdinalIgnoreCase)
            || second.StartsWith(first, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeForComparison(string path)
    {
        string fullPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return fullPath + Path.DirectorySeparatorChar;
    }

    private static FileSystemInfo GetSourceFileSystemInfo(string fullPath)
    {
        if (File.Exists(fullPath))
        {
            return new FileInfo(fullPath);
        }

        if (Directory.Exists(fullPath))
        {
            return new DirectoryInfo(fullPath);
        }

        return null;
    }

    private static DirEntry CreateRealEntry(FileSystemInfo fileSystemInfo)
    {
        DirEntry entry = new DirEntry();
        entry.Name = fileSystemInfo.Name;
        bool isDirectory = (fileSystemInfo.Attributes & FileAttributes.Directory) != 0;
        entry.IsDirectory = isDirectory;
        entry.FileSize = isDirectory ? 0L : ((FileInfo)fileSystemInfo).Length;
        entry.CreationTimeFiletime = fileSystemInfo.CreationTime.ToFileTime();
        entry.LastAccessTimeFiletime = fileSystemInfo.LastAccessTime.ToFileTime();
        entry.LastWriteTimeFiletime = fileSystemInfo.LastWriteTime.ToFileTime();
        entry.FileAttributes = (uint)fileSystemInfo.Attributes & 0xFFFF;
        return entry;
    }

    private static DirEntry CreateSyntheticEntry(SyntheticEntry syntheticEntry)
    {
        DirEntry entry = new DirEntry();
        entry.Name = syntheticEntry.Name;
        entry.IsSynthetic = true;
        entry.IsDirectory = syntheticEntry.IsDirectory;
        entry.FileSize = syntheticEntry.IsDirectory ? 0L : syntheticEntry.FileSize;
        long filetime = syntheticEntry.GetFiletime();
        entry.CreationTimeFiletime = filetime;
        entry.LastAccessTimeFiletime = filetime;
        entry.LastWriteTimeFiletime = filetime;
        entry.FileAttributes = syntheticEntry.IsDirectory ? 0x10u : 0x20u;
        return entry;
    }

    private static bool NameExists(List<DirEntry> entries, string name)
    {
        foreach (DirEntry entry in entries)
        {
            if (string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void Log(string message)
    {
        if (PhantomFSSettings.Verbose)
        {
            Console.WriteLine("  [" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + message);
        }
    }
}
