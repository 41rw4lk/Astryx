using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace CMDownloaderUI
{
    // This file only adds the menu to the existing MainForm via partial class.
    internal sealed partial class MainForm
    {
        private MenuStrip _menu;
        private ToolStripMenuItem _miFile, _miSettings, _miAbout;
        private ToolStripMenuItem _miLock, _miOpenOnDone, _miAdblock, _miParallel;
        private ToolStripMenuItem _miNv, _miVid;
        private TableLayoutPanel _headerBar;
        private Label _brand; // used only if we don't find your existing brand label
                              // host we align the menu to (your top toolbar)
        private Control? _toolbar;



        // Build and attach the app menu (call this once from the MainForm ctor, after pnlTop/pnlMain exist)
        private void BuildMenu(Control hostToolbar)
        {
            // Avoid duplicate menus
            if (_menu != null && !_menu.IsDisposed && Controls.Contains(_menu))
                return;

            _toolbar = hostToolbar;

            _menu = new MenuStrip
            {
                // IMPORTANT: do NOT dock; we will position it manually beside the brand
                Dock = DockStyle.None,
                GripStyle = ToolStripGripStyle.Hidden,
                Renderer = new ToolStripProfessionalRenderer(),
                Padding = new Padding(2, 0, 2, 0),
                Margin = new Padding(0),
                BackColor = Color.Transparent
            };

            // top-level items
            _miFile = new ToolStripMenuItem("&File");
            _miSettings = new ToolStripMenuItem("&Settings");
            _miAbout = new ToolStripMenuItem("&About");
            _menu.Items.AddRange(new ToolStripItem[] { _miFile, _miSettings, _miAbout });

            // Put the menu on the same parent as the brand overlay (the Form itself)
            if (_menu.Parent != this)
                this.Controls.Add(_menu);

            // Anchor to the right so it stays flush-right when resizing
            _menu.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            // initial placement + keep it in place on resize/relayout
            PositionMenu();
            this.Resize += (_, __) => PositionMenu();
            _toolbar.Resize += (_, __) => PositionMenu();
            _toolbar.LocationChanged += (_, __) => PositionMenu();

            // If you already build your Settings submenu here, keep that code below this point.
        }
        private void PositionMenu()
        {
            if (_menu == null || _menu.IsDisposed || _toolbar == null) return;

            // align with the toolbar’s top edge; tweak the +4 as needed to match your brand’s baseline
            int y = _toolbar.Top + 4;

            // flush-right with an 8px inset
            int x = this.ClientSize.Width - _menu.PreferredSize.Width - 8;

            _menu.Location = new Point(Math.Max(8, x), y);
            _menu.BringToFront();
        }


    }
}
