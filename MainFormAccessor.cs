namespace CMDownloaderUI
{
    internal static class MainFormAccessor
    {
        public static MainForm? MainFormInstance { get; private set; }

        // alias so existing calls to .Instance compile
        public static MainForm? Instance => MainFormInstance;

        public static void Set(MainForm form) => MainFormInstance = form;
    }
}
