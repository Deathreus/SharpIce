using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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

		public ICEForm()
		{
			InitializeComponent();
		}

		private void Form1_Load(object sender, EventArgs e)
		{
			error = new ErrorForm();
		}

		private void textBox1_TextChanged(object sender, EventArgs e)
		{
			ICEKey = textBox1.Text;
		}

		private void Form1_DragEnter(object sender, DragEventArgs e)
		{
			if (e.Data.GetDataPresent(DataFormats.FileDrop))
				e.Effect = DragDropEffects.Copy;
		}

		private void Form1_DragDrop(object sender, DragEventArgs e)
		{
			if (string.IsNullOrWhiteSpace(ICEKey))
			{
				error.ShowDialog();
				return;
			}

			progressBar1.Value = 0;

			string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
			foreach (string file in files)
			{
				FileStream fs = File.Open(file, FileMode.Open, FileAccess.Read);
				if(fs.CanRead)
				{
					new Thread((f) =>
					{
						FileStream fsr = (FileStream)f;
						fsr.Seek(0, SeekOrigin.Begin);

						string ext = file.Substring(file.LastIndexOf('.'));
						bool bShouldEncrypt = ext.Equals(".txt");

						FileStream fsw;
						if (bShouldEncrypt)
							fsw = File.Create(file.Replace(ext, ".ctx"));
						else
							fsw = File.Create(file.Replace(ext, ".txt"));

						long lFileSize = fsr.Length;

						IceKey ice = new IceKey(0);
						ice.Set(ICEKey);

						int iBlockSize = ice.BlockSize;

						for(int i = 0; i < lFileSize; i += iBlockSize)
						{
							byte[] pBuf = new byte[iBlockSize];
							fsr.Read(pBuf, 0, iBlockSize);

							byte[] pOutBuf = new byte[iBlockSize];
							if (bShouldEncrypt)
								ice.Encrypt(pBuf, ref pOutBuf);
							else
								ice.Decrypt(pBuf, ref pOutBuf);

							fsw.Write(pOutBuf, 0, pOutBuf.Length);

							progressBar1.Value += (i / (int)lFileSize) * 100;
						}

						fsw.Flush();
						fsw.Close();

						fsr.Close();
					}).Start(fs);
				}
			}
		}

		private void button1_Click(object sender, EventArgs e)
		{
			textBox1.Text = String.Empty;

			const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{};/.,~`:<>?";
			int len = checkBox1.Checked ? chars.Length : chars.Length - 29;
			Random rand = new Random(DateTime.UtcNow.Second);
			for(int i=0; i<8; i++)
			{
				char c = chars.ElementAt((int)Math.Floor(rand.NextDouble() * len));
				textBox1.Text += c;
			}
		}

		private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
		{
			switch(comboBox1.SelectedIndex)
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
