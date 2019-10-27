using System;
using System.Windows.Forms;

namespace SharpIce
{
    public partial class ErrorForm : Form
    {
        public ErrorForm()
        {
            InitializeComponent();
            Visible = false;
        }

        private void button1_Click(object sender, EventArgs e) => Hide();
    }
}
