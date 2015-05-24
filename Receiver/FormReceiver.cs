using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;

namespace Receiver
{
    public partial class FormReceiver : Form
    {

        string N_1;
        string N_2;
        string IDa;
        string KS;
        string publicKey;
        string privateKey;
        string decryptedIDa;
        string decryptedN_1;
        string encryptedN_1;
        string encryptedN_2;
        Thread threadClient = null;
        Socket client = null;

        public FormReceiver()
        {
            InitializeComponent();
            TextBox.CheckForIllegalCrossThreadCalls = false;
        }

        private void FormReceiver_Load(object sender, EventArgs e)
        {
            skinEngine1.SkinFile = Application.StartupPath + @"\MacOS.ssk";
            Button_Send.Enabled = false;
            Button_OpenPrivateKey.Enabled = false;
            Button_OpenPublicKey.Enabled = false;
        }

        private void btnPath_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "请选择文件路径";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                string foldPath = dialog.SelectedPath;
                MessageBox.Show("已选择文件夹:" + foldPath, "选择文件夹提示", MessageBoxButtons.OK,MessageBoxIcon.Information);
            }
        }

        private void btnOpen_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start("Explorer.exe", "c:\\windows");
        }

        private void Button_OpenPrivateKey_Click(object sender, EventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.Multiselect = true;
            fileDialog.Title = "请选择文件";
            fileDialog.Filter = "文件格式(*.xml)|*.xml";
            if (fileDialog.ShowDialog() == DialogResult.OK)
            {
                string file = fileDialog.FileName;
                MessageBox.Show("已选择文件:" + file, "选择文件提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                TextBox_PrivateKeyPath.Text = fileDialog.FileName;
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(fileDialog.FileName);
                XmlNode root = xmlDoc.SelectSingleNode("RSAKeyValue");
                if (root != null)
                {
                    if (root.SelectSingleNode("Exponent") != null)
                    {
                        StreamReader sr = new StreamReader(fileDialog.FileName,false);
                        privateKey = sr.ReadToEnd();
                        sr.Close();

                        try
                        {
                            decryptedN_1 = RSA.DecryptPrivateKey(privateKey, N_1);
                            decryptedIDa = RSA.DecryptPrivateKey(privateKey, IDa);
                        }
                        catch (Exception)
                        {
                            MessageBox.Show("密钥文件不匹配，请重新导入！", "错误");
                        }
                        TextBox_Process.AppendText("接收方私钥已加载完成，即将对随机数N1进行解密。\n");

                        TextBox_Process.AppendText("随机数N1为："+decryptedN_1+"\n");
                        TextBox_Process.AppendText("身份标识为:" + decryptedIDa+"\n");
                        TextBox_Process.AppendText("下面生成随机数N2。\n");

                        N_2 = RSA.CreateRandom();

                        TextBox_Process.AppendText("随机数N2已生成，请导入发送方公钥以对N1、N2加密。\n");

                        Button_OpenPublicKey.Enabled = true;
                    }
                    else
                    {
                        MessageBox.Show("未找到私钥请检查文件是否正确", "错误");
                    }
                }
                else
                {
                    MessageBox.Show("请检查文件格式是否正确", "错误");
                }
            }
        }

        private void Button_OpenPublicKey_Click(object sender, EventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.Multiselect = true;
            fileDialog.Title = "请选择文件";
            fileDialog.Filter = "文件格式(*.xml)|*.xml";
            if (fileDialog.ShowDialog() == DialogResult.OK)
            {
                string file = fileDialog.FileName;
                MessageBox.Show("已选择文件:" + file, "选择文件提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                TextBox_PublicKeyPath.Text = fileDialog.FileName;
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(fileDialog.FileName);
                XmlNode root = xmlDoc.SelectSingleNode("RSAKeyValue");
                if (root != null)
                {
                    if (root.SelectSingleNode("Exponent") != null)
                    {
                        StreamReader sr = new StreamReader(fileDialog.FileName, false);
                        publicKey = sr.ReadLine().ToString();
                        sr.Close();

                        TextBox_Process.AppendText("接收方公钥已加载完成，即将对随机数N1、N2进行加密。\n");

                        encryptedN_1 = RSA.EncryptPublicKey(publicKey, decryptedN_1);
                        encryptedN_2 = RSA.EncryptPublicKey(publicKey, N_2);

                        TextBox_Process.AppendText("随机数已完成加密，下面将数据发送给发送方。\n");

                        Button_Send.Enabled = true;
                    }
                    else
                    {
                        MessageBox.Show("未找到公钥请检查文件是否正确", "错误");
                    }
                }
                else
                {
                    MessageBox.Show("请检查文件格式是否正确", "错误");
                }
            }
        }

        private void Button_Startup_Click(object sender, EventArgs e)
        {
            Button_OpenPrivateKey.Enabled = true;
            TextBox_Process.AppendText("开始接收数据...\n");
            client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint IPeP = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 9050);
            client.Connect(IPeP);
            threadClient = new Thread(RecMsg);
            threadClient.IsBackground = true;
            threadClient.Start();
        }

        private void RecMsg()
        {
            int index = 0;
            try
            {
                while (true)
                {
                    byte[] arrRecMsg = new byte[1024 * 1024];
                    int length = client.Receive(arrRecMsg);
                    string strRecMsg = Encoding.UTF8.GetString(arrRecMsg, 0, length);
                    switch (index)
                    {
                        case 0:
                            TextBox_Process.AppendText("随机数N1和身份标识已收到，请导入接收方私钥进行解密。\n");
                            N_1 = strRecMsg;
                            break;
                        case 1:
                            IDa = strRecMsg;
                            break;
                        case 2:
                            N_2 = strRecMsg;
                            N_2 = BitConverter.ToString(Encoding.UTF8.GetBytes(RSA.DecryptPrivateKey(privateKey, N_2)));
                            TextBox_Process.AppendText("随机数N2已收到，为：" + N_2 + "\n");
                            TextBox_Process.AppendText("可确定发送方是A。\n");
                            break;
                        case 3:
                            KS = strRecMsg;
                            KS = RSA.DecryptPrivateKey(privateKey, KS);
                            TextBox_Process.AppendText("会话秘钥已收到，为：" + KS + "\n");
                            TextBox_Process.AppendText("以上操作即为密钥协商。\n");
                            break;
                    }
                    index++;
                }
            }
            catch (System.Net.Sockets.SocketException)
            {
                MessageBox.Show("断开连接！");
            }
        }

        private void ClientSendMsg(string sendMsg)
        {
            byte[] arrClientSendMsg = Encoding.UTF8.GetBytes(sendMsg);
            client.Send(arrClientSendMsg);
        }

        private void Button_Send_Click(object sender, EventArgs e)
        {
            ClientSendMsg(encryptedN_1);
            ClientSendMsg(encryptedN_2);
        }
    }
}
