using System;
using System.Windows.Forms;

namespace CMDownloaderUI
{
    internal sealed partial class MainForm
    {
        private enum MediaMode { All, Images, VideoAudio }

        private MediaMode _mediaMode = MediaMode.All;
        private int _nvAll, _vidAll, _nvImg, _vidImg, _nvVid, _vidVid; // [MODE.MEM.1]


        private bool ShouldKeepKind(string kind)
        {
            if (_mediaMode == MediaMode.All) return true;

            var k = kind?.ToUpperInvariant() ?? "";
            bool isImg = k == "IMG";
            bool isVid = k == "VID" || k == "VIDEO" || k == "AUDIO";
            bool isZip = k == "ZIP";

            return _mediaMode switch
            {
                MediaMode.Images => isImg, // ZIP excluded
                MediaMode.VideoAudio => isVid, // ZIP excluded
                _ => true
            };
        }

        private void ApplyMediaModeLanes()
        {
            if (nudNV == null || nudVID == null) return;
            switch (_mediaMode)
            {
                case MediaMode.Images:
                    nudNV.Value = Math.Min(nudNV.Maximum, Math.Max(nudNV.Minimum, _nvImg));
                    nudVID.Value = Math.Min(nudVID.Maximum, Math.Max(nudVID.Minimum, _vidImg));
                    break;

                case MediaMode.VideoAudio:
                    nudNV.Value = Math.Min(nudNV.Maximum, Math.Max(nudNV.Minimum, _nvVid));
                    nudVID.Value = Math.Min(nudVID.Maximum, Math.Max(nudVID.Minimum, _vidVid));
                    break;

                default: // All
                    nudNV.Value = Math.Min(nudNV.Maximum, Math.Max(nudNV.Minimum, _nvAll));
                    nudVID.Value = Math.Min(nudVID.Maximum, Math.Max(nudVID.Minimum, _vidAll));
                    break;
            }

        }
        private void RememberModeLanes() // [MODE.MEM.2]
        {
            int nv = (int)nudNV.Value, vv = (int)nudVID.Value;
            switch (_mediaMode)
            {
                case MediaMode.Images: _nvImg = nv; _vidImg = vv; break;
                case MediaMode.VideoAudio: _nvVid = nv; _vidVid = vv; break;
                default: _nvAll = nv; _vidAll = vv; break; // All
            }
        }

    }
}
