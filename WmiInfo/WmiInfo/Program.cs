using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace WmiInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            string host = args[0];
            byte[] WMI_Client_Receive = new byte[2048];
            //Socket WMI_Client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                var WMI_Client = new TcpClient();
                IAsyncResult result = WMI_Client.BeginConnect(host, 135, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(5000, true);
                if (!WMI_Client.Connected)
                {
                    Console.WriteLine($@"target {host} WmiInfo can't connect!");
                    return;
                }
                NetworkStream WMI_Client_Stream = WMI_Client.GetStream();
                WMI_Client_Receive = SendStream(WMI_Client_Stream, new byte[] { 5, 0, 11, 3, 16, 0, 0, 0, 120, 0, 40, 0, 3, 0, 0, 0, 184, 16, 184, 16, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 160, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 0, 0, 0, 0, 4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96, 2, 0, 0, 0, 10, 2, 0, 0, 0, 0, 0, 0, 78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 7, 130, 8, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 1, 177, 29, 0, 0, 0, 15 });
                NTLMInfo ntlminfo = new NTLMInfo();
                ntlminfo = GetNTLMInfo(WMI_Client_Receive, ntlminfo);
                Console.Write($@"target {host} WMIInfo: Windows Version {ntlminfo.OsVersion} Build {ntlminfo.OsBuildNumber}, Domain Name {ntlminfo.NbtDoaminName}, Computer Name {ntlminfo.NbtComputer}, Dns Suffix {ntlminfo.DnsDomainName}, Dns Computer Name {ntlminfo.DnsDomainName}, TimeStamp {ntlminfo.TimeStamp}");
                WMI_Client.Close();
                WMI_Client_Stream.Close();
            }       
            catch (Exception ex)
            {
                Console.WriteLine($@"target {host} WMIinfo Error:{ex.Message}");
            }
        }

        public static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }

        public class NTLMInfo
        {
            public string NativeOs { get; set; }
            public string NativeLanManager { get; set; }
            public string NbtDoaminName { get; set; }
            public string NbtComputer { get; set; }
            public string DomainName { get; set; }
            public short OsBuildNumber { get; set; }

            public string OsVersion { get; set; }
            public string DnsComputerName { get; set; }
            public string DnsDomainName { get; set; }
            public string DNSTreeName { get; set; }
            public DateTime TimeStamp { get; set; }
            public bool SMBsigning { get; set; }
        }

        public static NTLMInfo GetNTLMInfo(byte[] buf, NTLMInfo ntlminfo)
        {
            string NTLMSSP_Negotiate = BitConverter.ToString(buf).Replace("-", "");
            int off;
            off = NTLMSSP_Negotiate.IndexOf("4E544C4D53535000") / 2;
            int NTLMSSP_Negotiate_Len = (NTLMSSP_Negotiate.Length - NTLMSSP_Negotiate.IndexOf("4E544C4D53535000")) / 2;
            byte[] ntlm = new byte[NTLMSSP_Negotiate_Len];
            Array.Copy(buf, off, ntlm, 0, NTLMSSP_Negotiate_Len);

            NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, 0xc);
            off = BitConverter.ToInt16(ntlm, 0x10);
            ntlminfo.OsBuildNumber = BitConverter.ToInt16(ntlm, off - 6);
            ntlminfo.OsVersion = $@"{ntlm[off - 8]}.{ntlm[off - 7]}";

            off += NTLMSSP_Negotiate_Len;
            int type = BitConverter.ToInt16(ntlm, off);

            while (type != 0)
            {
                off += 2;
                NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, off);
                off += 2;
                switch (type)
                {
                    case 1:
                        {
                            ntlminfo.NbtComputer = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("NetBIOS computer name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 2:
                        {
                            ntlminfo.NbtDoaminName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("NetBIOS domain name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 3:
                        {
                            ntlminfo.DnsComputerName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS computer name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 4:
                        {
                            ntlminfo.DnsDomainName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS domain name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 5:
                        {
                            ntlminfo.DNSTreeName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                            //Console.WriteLine("DNS tree name: " + Encoding.Unicode.GetString(ntlm, off, len));
                            break;
                        }
                    case 7:
                        {
                            ntlminfo.TimeStamp = DateTime.FromFileTime(BitConverter.ToInt64(ntlm, off));
                            //Console.WriteLine("time stamp: {0:o}", DateTime.FromFileTime(BitConverter.ToInt64(ntlm, off)));
                            break;
                        }
                    default:
                        {
                            //Console.Write("Unknown type {0}, data: ", type);
                            for (int i = 0; i < NTLMSSP_Negotiate_Len; i++)
                            {
                                Console.Write(ntlm[i + off].ToString("X2"));
                            }
                            Console.WriteLine();
                            break;
                        }
                }
                off += NTLMSSP_Negotiate_Len;
                type = BitConverter.ToInt16(ntlm, off);
            }

            return ntlminfo;
        }
    }

}
