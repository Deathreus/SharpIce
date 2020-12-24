using System;
using System.Linq;
using System.Windows.Forms;
using System.IO;
using System.Threading;

// This is the code for your desktop app.
// Press Ctrl+F5 (or go to Debug > Start Without Debugging) to run your app.

namespace SharpIce
{
    public partial class ICEForm : Form
    {
        private static string ICEKey;
        private static ErrorForm error;

        public ICEForm() => InitializeComponent();

        private void Form1_Load(object sender, EventArgs e) => error = new ErrorForm();

        private void textBox1_TextChanged(object sender, EventArgs e) => ICEKey = textBox1.Text;

        private void Form1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
        }

        private void Form1_DragDrop(object sender, DragEventArgs e)
        {
            Invoke(new Action(() => progressBar1.Value = 0));
            Invoke(new Action(() => progressBar1.Maximum = 100));

            if (String.IsNullOrWhiteSpace(ICEKey))
            {
                error.ShowDialog();
                return;
            }

            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string file in files)
            {
                using (FileStream fs = File.Open(file, FileMode.Open, FileAccess.Read))
                {
                    if (fs.CanRead)
                    {
                        fs.Seek(0, SeekOrigin.Begin);
                        Invoke(new Action(() => progressBar1.Maximum += (int)fs.Length));
                    }
                }
            }

            foreach (string file in files)
            {
                ThreadPool.QueueUserWorkItem((o) =>
                {
                    using (FileStream fsr = File.Open(file, FileMode.Open, FileAccess.Read))
                    {
                        if (fsr.CanRead)
                        {
                            fsr.Seek(0, SeekOrigin.Begin);
                            int iFileSize = (int)fsr.Length;

                            string ext = file.Substring(file.LastIndexOf('.'));
                            bool bShouldEncrypt = ext.Equals(".txt");
                            string newExt = bShouldEncrypt ? ".ctx" : ".txt";

                            using (FileStream fsw = File.Create(file.Replace(ext, newExt)))
                            {
                                IceKey ice = new IceKey(0).Set(ICEKey);

                                int iBlockSize = ice.BlockSize;
                                byte[] inBuf = new byte[iBlockSize];
                                byte[] outBuf = new byte[iBlockSize];

                                int iBytesLeft = iFileSize;
                                for (int i = 0; iBytesLeft >= iBlockSize; i += iBlockSize)
                                {
                                    fsr.Read(inBuf, 0, iBlockSize);

                                    if (bShouldEncrypt)
                                        ice.Encrypt(inBuf, out outBuf);
                                    else
                                        ice.Decrypt(inBuf, out outBuf);

                                    Invoke(new Action(() => progressBar1.Value += iBlockSize));

                                    fsw.Write(outBuf, 0, iBlockSize);

                                    iBytesLeft -= iBlockSize;
                                }

                                Invoke(new Action(() => progressBar1.Value += iBytesLeft));

                                if (iBytesLeft > 0)
                                {
                                    fsr.Read(outBuf, 0, iBytesLeft);
                                    fsw.Write(outBuf, 0, iBytesLeft);
                                }
                            }
                        }
                    }
                });
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox1.Text = String.Empty;

            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{};/.,~`:<>?";
            int len = checkBox1.Checked ? chars.Length : chars.Length - 29;
            var rand = new Random();
            for (int i = 0; i < 8; i++)
            {
                char c = chars.ElementAt((int)Math.Floor(rand.NextDouble() * len));
                textBox1.Text += c;
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            switch (comboBox1.SelectedIndex)
            {
                case 0:
                    textBox1.Text = String.Empty;
                    break;
                case 1:
                    textBox1.Text = "x9Ke0BY7";
                    break;
                case 2:
                    textBox1.Text = "d7NSuLq2";
                    break;
                case 3:
                    textBox1.Text = "Wl0u5B3F";
                    break;
                case 4:
                    textBox1.Text = "E2NcUkG2";
                    break;
                case 5:
                    textBox1.Text = "SDhfi878";
                    break;
            }
        }
    }
}
