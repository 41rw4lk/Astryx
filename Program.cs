using System;
using System.IO;
using System.Windows.Forms;

namespace CMDownloaderUI
{
    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // Updater-mode: run as a separate process so files are not locked
            // args: --apply-update "<fromDir>" "<toDir>" <parentPid>
            if (args != null && args.Length >= 4 &&
                string.Equals(args[0], "--apply-update", StringComparison.OrdinalIgnoreCase))
            {
                try { System.IO.File.WriteAllText(System.IO.Path.Combine(args[2], "_UPDATE_MODE_ENTERED.txt"), string.Join("\r\n", args)); } catch { }
                string fromDir = args[1];
                string toDir = args[2];
                int parentPid = 0; int.TryParse(args[3], out parentPid);

                try { ApplyUpdate(fromDir, toDir, parentPid); } catch { }
                return;
            }

            try
            {
                string baseDir = AppContext.BaseDirectory;
                string exe = Path.Combine(baseDir, "Astryx.exe");
                string neo = Path.Combine(baseDir, "Astryx.new.exe");
                string bak = Path.Combine(baseDir, "Astryx.old.exe");

                if (File.Exists(neo))
                {
                    try { if (File.Exists(bak)) File.Delete(bak); } catch { }
                    try { if (File.Exists(exe)) File.Move(exe, bak, overwrite: true); } catch { }
                    try { File.Move(neo, exe, overwrite: true); } catch { }
                }
            }
            catch { }


            ApplicationConfiguration.Initialize();

            var appDir = AppContext.BaseDirectory;
            var pwDir = Path.Combine(appDir, "pw-browsers");
            Directory.CreateDirectory(pwDir);

            Environment.SetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH", pwDir);

            var form = new MainForm
            {
                WindowState = FormWindowState.Minimized,
                ShowInTaskbar = false,
                Opacity = 0   // invisible
            };

            Application.Run(form);
        }

        static void ApplyUpdate(string fromDir, string toDir, int parentPid)
        {
            try
            {
                // Wait for parent to exit (unlock exe/dll)
                if (parentPid > 0)
                {
                    for (int i = 0; i < 200; i++)
                    {
                        try
                        {
                            var p = System.Diagnostics.Process.GetProcessById(parentPid);
                            if (p.HasExited) break;
                        }
                        catch { break; }
                        System.Threading.Thread.Sleep(100);
                    }
                }

                System.Threading.Thread.Sleep(300);

                // AUTO-ROOT: choose the folder that actually contains "wwwroot"
                string root = fromDir;

                if (!Directory.Exists(Path.Combine(root, "wwwroot")))
                {
                    foreach (var d in Directory.GetDirectories(root))
                    {
                        if (Directory.Exists(Path.Combine(d, "wwwroot")))
                        {
                            root = d;
                            break;
                        }
                    }
                }


                // Proof file so we can see what happened without guessing
                try
                {
                    File.WriteAllText(Path.Combine(toDir, "_update_applied.txt"),
                        DateTime.Now.ToString("s") + "\r\nFROM=" + root + "\r\nTO=" + toDir + "\r\n");
                }
                catch { }

                bool IsExcluded(string rel)
                {
                    rel = rel.Replace('/', '\\');

                    // preserve UI.ini
                    if (string.Equals(rel, "ui.ini", StringComparison.OrdinalIgnoreCase)) return true;

                    // preserve root index* (BUT still allow wwwroot\index.html)
                    if (!rel.StartsWith("wwwroot\\", StringComparison.OrdinalIgnoreCase))
                    {
                        if (rel.IndexOf('\\') < 0 && rel.StartsWith("index", StringComparison.OrdinalIgnoreCase))
                            return true;
                    }

                    // preserve obvious local indexes if you keep them under these folders
                    if (rel.IndexOf("\\media-index", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                    if (rel.IndexOf("\\indexes", StringComparison.OrdinalIgnoreCase) >= 0) return true;

                    return false;
                }

                foreach (var src in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    var rel = Path.GetRelativePath(root, src);
                    if (IsExcluded(rel)) continue;
                    // stage exe swap (can't overwrite running Astryx.exe)
                    if (string.Equals(rel, "Astryx.exe", StringComparison.OrdinalIgnoreCase))
                        rel = "Astryx.new.exe";


                    var dst = Path.Combine(toDir, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(dst)!);

                    Exception? last = null;
                    for (int t = 0; t < 12; t++)
                    {
                        try
                        {
                            File.Copy(src, dst, overwrite: true);
                            last = null;
                            break;
                        }
                        catch (Exception ex)
                        {
                            last = ex;
                            System.Threading.Thread.Sleep(150);
                        }
                    }
                    if (last != null) throw last;
                }

                // Relaunch main app
                try
                {
                    string selfName = Path.GetFileName(System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "Astryx.exe");
                    string exe = Path.Combine(toDir, selfName);

                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = exe,
                        WorkingDirectory = toDir,
                        UseShellExecute = true
                    });
                }
                catch { }
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(Path.Combine(toDir, "_update_error.txt"), ex.ToString()); } catch { }
            }
        }

    }
}
