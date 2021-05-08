using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Net;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            string target = args[0];
            try
            {
                Uri ourUri = new Uri($@"http://{target}:5985/wsman");
                // Creates an HttpWebRequest for the specified URL.
                HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(ourUri);
                myHttpWebRequest.Method = "POST";
                myHttpWebRequest.ContentLength = 0;
                myHttpWebRequest.KeepAlive = true;
                myHttpWebRequest.ContentType = "application/soap+xml;charset=UTF-8";
                myHttpWebRequest.UserAgent = "Microsoft WinRM Client";
                myHttpWebRequest.Headers.Add("Authorization", "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==");
                HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();
                Console.WriteLine("\nThe server did not issue any challenge.  Please try again with a protected resource URL.");
                // Releases the resources of the response.
                myHttpWebResponse.Close();
            }
            catch (WebException e)
            {
                HttpWebResponse response = (HttpWebResponse)e.Response;
                if (response != null)
                {
                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        string challenge = null;
                        challenge = response.GetResponseHeader("WWW-Authenticate");
                        //if (challenge != null)

                        NTLMInfo ntlminfo = GetNTLMInfo(Convert.FromBase64String(challenge.Split()[1]), new NTLMInfo());
                        Console.WriteLine($@"target {target} WinRmInfo: Windows Version {ntlminfo.OsVersion} Build {ntlminfo.OsBuildNumber}, Domain Name {ntlminfo.NbtDoaminName}, Computer Name {ntlminfo.NbtComputer}, Dns Suffix {ntlminfo.DnsDomainName}, Dns Computer Name {ntlminfo.DnsDomainName}, TimeStamp {ntlminfo.TimeStamp}");
                    }
                    else
                    {
                        Console.WriteLine($@"target {target} WinRmInfo Error: The following WebException was raised : {0}", e.Message);
                    }
                }
                else
                {
                    Console.WriteLine($@"target {target} WinRmInfo Error: Response Received from server was null");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($@"target {target} WinRmInfo Error: The following Exception was raised : {0}", e.Message);
            }
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

