/*
  KeePass ColoredQualityColumn Plugin
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.Drawing;

using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util.Spr;

using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Utility;
using KeePassLib.Security;

namespace ColoredQualityColumn
{
    public sealed class ColoredQualityColumnExt : Plugin
    {
        private static IPluginHost m_host = null;
        private ColoredQualityColumnProvider m_prov = null;
        //Quality classification cutoffs, populated per KeePass website.
        //In the future, might make these configurable.
        private SortedList<uint, Color> QualityDelimiter = new SortedList<uint, Color> {
            {             0, Color.FromArgb(unchecked((int)0xFFFFFFFF)) }, // White
            {            64, Color.FromArgb(unchecked((int)0xFFD81B00)) }, // Red
            {            80, Color.FromArgb(unchecked((int)0xFFFF7D02)) }, // Orange
            {           112, Color.FromArgb(unchecked((int)0xFFFFFA00)) }, // Yellow
            {           128, Color.FromArgb(unchecked((int)0xFF84CE00)) }, // Light Green
            { uint.MaxValue, Color.FromArgb(unchecked((int)0xFF02B801)) }, // Green
        };
        private const string QcpName = "Quality";

        internal static IPluginHost Host
        {
            get { return m_host; }
        }

        public override bool Initialize(IPluginHost host)
        {
            Terminate();

            m_host = host;
            if (m_host == null) { Debug.Assert(false); return false; }

            m_prov = new ColoredQualityColumnProvider();
            m_host.ColumnProviderPool.Add(m_prov);

            ListView lv = (m_host.MainWindow.Controls.Find(
                "m_lvEntries", true)[0] as ListView);
            if (lv == null) { Debug.Assert(false); return false; }

            //Custom draw the entry list so we can set background color.
            lv.OwnerDraw = true;
            lv.DrawColumnHeader += Lv_DrawColumnHeader;
            lv.DrawItem += Lv_DrawItem;
            lv.DrawSubItem += Lv_DrawSubItem;

            m_host.MainWindow.FileClosed += this.OnFileClosed;

            return true;
        }

        public override void Terminate()
        {
            if (m_host == null) return;

            m_host.MainWindow.FileClosed -= this.OnFileClosed;

            ListView lv = (m_host.MainWindow.Controls.Find(
                "m_lvEntries", true)[0] as ListView);
            if (lv == null) { Debug.Assert(false); return; }

            lv.DrawSubItem -= Lv_DrawSubItem;
            lv.DrawItem -= Lv_DrawItem;
            lv.DrawColumnHeader -= Lv_DrawColumnHeader;
            lv.OwnerDraw = false;

            m_host.ColumnProviderPool.Remove(m_prov);
            m_prov = null;

            m_host = null;
        }

        public override string UpdateUrl
        {
            get
            {
                return "https://raw.githubusercontent.com/CutthroatBaron/ColoredQualityColumn/master/VERSION.txt";
            }
        }

        private void Lv_DrawItem(object sender, DrawListViewItemEventArgs e)
        {
            e.Item.UseItemStyleForSubItems = false;
            e.DrawDefault = true;
        }

        private void Lv_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawDefault = true;
        }

        private void Lv_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            ListViewItem lvi = e.Item;
            if (e.Header.Text == QcpName)
            {
                PwListItem li = (lvi.Tag as PwListItem);
                if (li == null) { Debug.Assert(false); return; }

                PwEntry pe = li.Entry;
                if (pe == null) { Debug.Assert(false); return; }

                ProtectedString pStr = pe.Strings.Get(PwDefs.PasswordField);
                if (pStr == null) { Debug.Assert(false); return; }

                string strPw = pStr.ReadString();

                uint uCacheEst = ColoredQualityColumnProvider.loadQualityFromCache(strPw);
                foreach (KeyValuePair<uint, Color> kvp in QualityDelimiter)
                {
                    if (uCacheEst <= kvp.Key)
                    {
                        e.SubItem.BackColor = kvp.Value;
                        break;
                    }
                }
            }
            else
            {
                e.SubItem.BackColor = lvi.BackColor;
            }
            e.DrawDefault = true;
        }

        private void OnFileClosed(object sender, FileClosedEventArgs e)
        {
            ColoredQualityColumnProvider.ClearCache();
        }
    }

    public sealed class ColoredQualityColumnProvider : ColumnProvider
    {
        private const string QcpName = "Quality";
        private const string QcpBitsSuffix = " bits";

        private static object m_oCacheSync = new object();
        private static Dictionary<string, uint> m_dCache =
            new Dictionary<string, uint>();

        private string[] m_vColNames = new string[] { QcpName };
        public override string[] ColumnNames
        {
            get { return m_vColNames; }
        }

        public override HorizontalAlignment TextAlign
        {
            get { return HorizontalAlignment.Right; }
        }

        internal static void ClearCache()
        {
            lock (m_oCacheSync)
            {
                m_dCache.Clear();
            }
        }

        internal static uint loadQualityFromCache(String pw)
        {
            uint pwStrength = 0;
            if (m_dCache.ContainsKey(pw))
            {
                pwStrength = m_dCache[pw];
            }
            return pwStrength;
        }

        public override string GetCellData(string strColumnName, PwEntry pe)
        {
            if (strColumnName == null) { Debug.Assert(false); return string.Empty; }
            if (strColumnName != QcpName) return string.Empty;
            if (pe == null) { Debug.Assert(false); return string.Empty; }

            string strPw = pe.Strings.ReadSafe(PwDefs.PasswordField);

            if (strPw.IndexOf('{') >= 0)
            {
                IPluginHost host = ColoredQualityColumnExt.Host;
                if (host == null) { Debug.Assert(false); return string.Empty; }

                PwDatabase pd = null;
                try
                {
                    pd = host.MainWindow.DocumentManager.SafeFindContainerOf(pe);
                }
                catch (Exception) { Debug.Assert(false); }

                SprContext ctx = new SprContext(pe, pd, (SprCompileFlags.Deref |
                    SprCompileFlags.TextTransforms), false, false);
                strPw = SprEngine.Compile(strPw, ctx);
            }

            uint uEst;
            lock (m_oCacheSync)
            {
                if (!m_dCache.TryGetValue(strPw, out uEst)) uEst = uint.MaxValue;
            }

            if (uEst == uint.MaxValue)
            {
                uEst = QualityEstimation.EstimatePasswordBits(strPw.ToCharArray());

                lock (m_oCacheSync)
                {
                    m_dCache[strPw] = uEst;
                }
            }

            return (uEst.ToString() + QcpBitsSuffix);
        }
    }
}
