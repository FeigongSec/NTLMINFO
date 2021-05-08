using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SmbInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            string host = args[0];
            int port = int.Parse(args[1]);

            byte[] SMBClientReceive = new byte[2048];

            TcpClient SMB_Client = new TcpClient();
            IAsyncResult result = SMB_Client.BeginConnect(host, 445, null, null);
            bool success = result.AsyncWaitHandle.WaitOne(5000, true);
            if (!SMB_Client.Connected)
            {
                Console.WriteLine($@"target {host} SMBInfo can't connect!");
                return;
            }

            NetworkStream SMB_Client_Stream = SMB_Client.GetStream();
            NTLMInfo ntlminfo = new NTLMInfo();
            SMBPacket SMBPackets = new SMBPacket();
            if (port == 139)
            {
                SendStream(SMB_Client_Stream, GetNtbiosTCPData());
            }

            try
            {
                SMBClientReceive = SendStream(SMB_Client_Stream, GetNegotiateSMBv1Data());
                if (BitConverter.ToString(SMBClientReceive).Replace("-", "").Substring(78, 2) == "0F")
                {
                    ntlminfo.SMBsigning = true;
                }
                else
                {
                    ntlminfo.SMBsigning = false;
                }
                SMBClientReceive = SendStream(SMB_Client_Stream, GetNTLMSSPNegotiatev1Data());

                int len = BitConverter.ToInt16(SMBClientReceive, 43);

                string[] ss = null;

                if (Encoding.Unicode.GetString(SMBClientReceive, len + 47, SMBClientReceive.Length - len - 47).Split('\0')[0].ToLower().IndexOf("windows") > -1)
                {
                    ss = Encoding.Unicode.GetString(SMBClientReceive, len + 47, SMBClientReceive.Length - len - 47).Split('\0');
                }
                else
                {
                    ss = Encoding.Unicode.GetString(SMBClientReceive, len + 48, SMBClientReceive.Length - len - 48).Split('\0');
                }

                //Console.WriteLine(ss);
                ntlminfo.NativeOs = ss[0];
                ntlminfo.NativeLanManager = ss[1];
                ntlminfo = GetNTLMInfo(SMBClientReceive, ntlminfo);
                Console.WriteLine($@"target {host} SMBInfo: {ntlminfo.NativeOs} ({ntlminfo.NativeLanManager}), Version {ntlminfo.OsVersion} Build {ntlminfo.OsBuildNumber}, Domain Name {ntlminfo.NbtDoaminName}, Computer Name {ntlminfo.NbtComputer}, Dns Suffix {ntlminfo.DnsDomainName}, Tree Dns ComputerName {ntlminfo.DnsComputerName}, SMB Signing {ntlminfo.SMBsigning}");
            }
            catch
            {
                if (!SMB_Client.Connected)
                {
                    SMB_Client = new TcpClient();
                    SMB_Client.Connect(host, port);
                    SMB_Client_Stream = SMB_Client.GetStream();
                }
                SMBClientReceive = SendStream(SMB_Client_Stream, GetNegotiateSMBv2Data1());
                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                {
                    Console.WriteLine($@"target {host} Could not connect with SMBv2");
                }
                else
                {
                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                    {
                        ntlminfo.SMBsigning = true;
                        SMBPackets.SMB_Signing = true;
                        SMBPackets.SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                        SMBPackets.SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                    }
                    else
                    {
                        SMBPackets.SMB_Signing = false;
                        ntlminfo.SMBsigning = false;
                        SMBPackets.SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                        SMBPackets.SMB_Negotiate_Flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };
                    }
                    SendStream(SMB_Client_Stream, GetNegotiateSMBv2Data2());
                    SMBClientReceive = SendStream(SMB_Client_Stream, GetNTLMSSPNegotiatev2Data(SMBPackets));
                    ntlminfo = GetNTLMInfo(SMBClientReceive, ntlminfo);
                    Console.WriteLine($@"target {host} SMBInfo: Windows Version {ntlminfo.OsVersion} Build {ntlminfo.OsBuildNumber}, Domain Name {ntlminfo.NbtDoaminName}, Computer Name {ntlminfo.NbtComputer}, Dns Suffix {ntlminfo.DnsDomainName}, Tree Dns ComputerName {ntlminfo.DnsComputerName}, SMB Signing {ntlminfo.SMBsigning}, TimeStamp {ntlminfo.TimeStamp}");
                }

            }
        }

        public static byte[] GetNtbiosTCPData()
        {
            byte[] NtbiosTCPData ={
                0x81,0x00,0x00,0x44,0x20,0x43,0x4b,0x46,0x44,0x45,0x4e,0x45,0x43,0x46,0x44,0x45
                ,0x46,0x46,0x43,0x46,0x47,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x00,0x20,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
            };
            return NtbiosTCPData;
        }

        public static byte[] GetNegotiateSMBv1Data()
        {
            byte[] NegotiateSMBv1Data ={
                0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
                0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
                0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
                0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
                0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
                0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
                0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
            };
            return NegotiateSMBv1Data;
        }

        public static byte[] GetNTLMSSPNegotiatev1Data()
        {

            byte[] NTLMSSPNegotiatev1Data ={
                0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
                0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
                0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
                0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
                0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
                0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
                0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
                0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
                0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
                0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
                0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
                0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            return NTLMSSPNegotiatev1Data;
        }
        public static byte[] GetNegotiateSMBv2Data1()
        {
            byte[] NegotiateSMBData ={
                        0x00, 0x00, 0x00, 0x45, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
                        0x00, 0x00, 0x00, 0x18, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                        0xAC, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02,
                        0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32,
                        0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30,
                        0x32, 0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F,
                        0x3F, 0x3F, 0x00
                };
            return NegotiateSMBData;
        }

        public static byte[] GetNegotiateSMBv2Data2()
        {
            byte[] NegotiateSMB2Data = {
                    0x00, 0x00, 0x00, 0x68, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
                    0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02
            };
            return NegotiateSMB2Data;
        }


        public static byte[] GetNTLMSSPNegotiatev2Data(SMBPacket SMBPackets)
        {
            byte[] NTLMSSPNegotiateData = {
                    0x00, 0x00, 0x00, 0x9A, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x58, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x60, 0x40, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
                    0x05, 0x02, 0xA0, 0x36, 0x30, 0x34, 0xA0, 0x0E, 0x30, 0x0C,
                    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
                    0x02, 0x0A, 0xA2, 0x22, 0x04, 0x20, 0x4E, 0x54, 0x4C, 0x4D,
                    0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
                    SMBPackets.SMB_Negotiate_Flags[0], SMBPackets.SMB_Negotiate_Flags[1],
                    SMBPackets.SMB_Negotiate_Flags[2], SMBPackets.SMB_Negotiate_Flags[3],
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            return NTLMSSPNegotiateData;

        }

        public static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }


        public class SMBPacket
        {
            public OrderedDictionary Packet_SMB_Header { get; set; }
            public OrderedDictionary Packet_SMB2_Header { get; set; }
            public OrderedDictionary Packet_SMB_Data { get; set; }
            public OrderedDictionary Packet_SMB2_Data { get; set; }
            public OrderedDictionary Packet_NTLMSSP_Negotiate { get; set; }
            public OrderedDictionary Packet_NTLMSSP_Auth { get; set; }
            public OrderedDictionary Packet_RPC_Data { get; set; }
            public OrderedDictionary Packet_SCM_Data { get; set; }
            public bool SMB_Signing { get; set; }
            public byte[] SMB_Session_ID { get; set; }
            public byte[] SMB_Session_Key_Length { get; set; }
            public byte[] SMB_Negotiate_Flags { get; set; }
            public byte[] Session_Key { get; set; }
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
