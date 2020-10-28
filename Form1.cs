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
            if (String.IsNullOrWhiteSpace(ICEKey))
            {
                error.ShowDialog();
                return;
            }

            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string file in files)
            {
                ThreadPool.QueueUserWorkItem(async (o) =>
                {
                    using (FileStream fsr = File.Open(file, FileMode.Open, FileAccess.Read))
                    {
                        if (fsr.CanRead)
                        {
                            progressBar1.Value = 0;

                            fsr.Seek(0, SeekOrigin.Begin);
                            int iFileSize = (int)fsr.Length;

                            string ext = file.Substring(file.LastIndexOf('.'));
                            bool bShouldEncrypt = ext.Equals(".txt");

                            string newExt = bShouldEncrypt ? ".ctx" : ".txt";

                            using (FileStream fsw = File.Create(file.Replace(ext, newExt)))
                            {
                                byte[] inBuf = new byte[iFileSize];
                                int nRead = await fsr.ReadAsync(inBuf, 0, iFileSize);
                                byte[] outBuf = new byte[iFileSize];

                                IceKey ice = new IceKey(0).Set(ICEKey);

                                int iBlockSize = ice.BlockSize;
                                int iBytesLeft = iFileSize;
                                for (int i = 0; i < iFileSize && iBytesLeft >= iBlockSize; i += iBlockSize)
                                {
                                    if (bShouldEncrypt)
                                    {
                                        byte[] buffer = inBuf.Skip(i).Take(iBlockSize).ToArray();
                                        ice.Encrypt(buffer, out var temp);

                                        Array.Copy(temp, 0, outBuf, i, iBlockSize);
                                    }
                                    else
                                    {
                                        byte[] buffer = inBuf.Skip(i).Take(iBlockSize).ToArray();
                                        ice.Decrypt(buffer, out var temp);

                                        Array.Copy(temp, 0, outBuf, i, iBlockSize);
                                    }

                                    if (InvokeRequired)
                                    {
                                        Invoke(new MethodInvoker(
                                            delegate{ progressBar1.Value = i / iFileSize * 100; }));
                                    }
                                    else
                                    {
                                        progressBar1.Value = i / iFileSize * 100;
                                    }
                                    iBytesLeft -= iBlockSize;
                                }

                                Array.Copy(inBuf,
                                    iFileSize - iBytesLeft,
                                    outBuf,
                                    iFileSize - iBytesLeft,
                                    iBytesLeft);

                                await fsw.WriteAsync(outBuf, 0, iFileSize);
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
