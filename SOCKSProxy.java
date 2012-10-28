import java.net.*;
import java.io.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;

import edu.mscd.cs.javaln.*;

class SOCKSThread extends Thread
{
    private static JavaLN logger = new JavaLN();
    private static ConsoleHandler CH = new ConsoleHandler();

    static
    {
        CH.setFormatter (new LineNumberFormatter());
        CH.setLevel (Level.FINER);
        logger.addHandler (CH);
        logger.setUseParentHandlers (false);
        logger.setLevel (Level.FINER);
    }

    private InputStream IS;
    private OutputStream OS;
    private OutputStream copyOS;

    public SOCKSThread (InputStream IS, OutputStream OS,
        OutputStream copyOS)
    {
        this.IS = IS;
        this.OS = OS;
        this.copyOS = copyOS;
    }

    public static void readNwrite (InputStream IS, OutputStream OS,
        OutputStream copyOS)
    {
        logger.entering();

        int read = -1;
        byte buffer[] = new byte[8192];

        for (;;)
        {
            try
            {
                read = IS.read (buffer, 0, 8192);
            }
            catch (IOException IOE)
            {
                logger.throwing (IOE);
                break;
            }

            logger.finer ("read " + read);

            if (read == -1)
                return;

            try
            {
                OS.write (buffer, 0, read);
            }
            catch (IOException IOE)
            {
                logger.throwing (IOE);
                return;
            }

            if (copyOS != null)
            {
                try
                {
                    copyOS.write (buffer, 0, read);
                }
                catch (IOException IOE)
                {
                    logger.throwing (IOE);
                }
            }
        }
    }

    public void run()
    {
        readNwrite (IS, OS, copyOS);
    }
}

class Connection extends Thread
{
    private static JavaLN logger = new JavaLN();
    private static ConsoleHandler CH = new ConsoleHandler();

    static
    {
        CH.setFormatter (new LineNumberFormatter());
        CH.setLevel (Level.FINER);
        logger.addHandler (CH);
        logger.setUseParentHandlers (false);
        logger.setLevel (Level.FINER);
    }

    private Socket socket;

    public Connection (Socket socket)
    {
        this.socket = socket;
    }

    public void run()
    {
        Thread t = null;

        try
        {
            t = new SOCKSProxy (socket.getInputStream(),
                socket.getOutputStream(), null, null);
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
        }

        t.start();

        try
        {
            t.join();
        }
        catch (InterruptedException IE)
        {
            logger.warning (IE);
            return;
        }

        try
        {
            socket.getInputStream().close();
            socket.getOutputStream().close();
            socket.close();
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
        }
    }
}

public class SOCKSProxy extends Thread
{
    private static JavaLN logger = new JavaLN();
    private static ConsoleHandler CH = new ConsoleHandler();

    static
    {
        CH.setFormatter (new LineNumberFormatter());
        CH.setLevel (Level.FINER);
        logger.addHandler (CH);
        logger.setUseParentHandlers (false);
        logger.setLevel (Level.FINER);
    }

    private OutputStream localOS;
    private InputStream localIS;
    private OutputStream requestOS;

    private InputStream remoteIS;
    private OutputStream remoteOS;
    private OutputStream responseOS;

    private InetAddress remoteAddress;
    private int remotePort;

    public SOCKSProxy (InputStream localIS, OutputStream localOS,
        OutputStream requestOS, OutputStream responseOS)
    {
        this.localIS = localIS;
        this.localOS = localOS;
        this.requestOS = requestOS;
        this.responseOS = responseOS;
    }

    /*
    ** open the remote port, sending a SOCKS error back if unsuccessful.
    */
    private boolean openRemote()
    {
        /*
        ** SOCKS Server to SOCKS client:
        **
        ** field 1: null byte
        ** field 2: status, 1 byte:
        **  0x5a = request granted
        **  0x5b = request rejected or failed
        **  0x5c = request failed because client is not running identd (or
        **      not reachable from the server)
        **  0x5d = request failed because client's identd could not confirm
        **      the user ID string in the request
        ** field 3: 2 arbitrary bytes, that should be ignored
        ** field 4: 4 arbitrary bytes, that should be ignored
        */

        try
        {
            Socket socket = new Socket (remoteAddress, remotePort);
            remoteIS = socket.getInputStream();
            remoteOS = socket.getOutputStream();
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);

            /*
            ** failed, so write back SOCKS failure.
            */
            try
            {
                byte bad[] = {0, 0x5b, 0, 0, 0, 0, 0, 0};
                localOS.write (bad);
            }
            catch (IOException IOE2)
            {
                logger.throwing (IOE2);
            }

            return (false);
        }

        byte good[] = {0, 0x5a, 0, 0, 0, 0, 0, 0};

        try
        {
            localOS.write (good);
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
        }

        return (true);
    }

    /*
    ** get SOCKS request information
    */
    private boolean readSOCKSHeader()
    {
        /*
        ** http://en.wikipedia.org/wiki/SOCKS#SOCKS4
        **
        ** SOCKS Client to SOCKS Server:
        **
        ** field 1: SOCKS version number, 1 byte, must be 0x04 for this version
        ** field 2: command code, 1 byte:
        **  0x01 = establish a TCP/IP stream connection
        **  0x02 = establish a TCP/IP port binding
        ** field 3: network byte order port number, 2 bytes
        ** field 4: network byte order IP address, 4 bytes
        ** field 5: the user ID string, variable length, terminated with a null
        **     0x00
        */

        try
        {
            /*
            ** read and ignore the version and command.
            */
            int version = localIS.read();

            if (version != 4)
            {
                logger.warning ("SOCKS version " + version + " != 4");
                return (false);
            }

            int command = localIS.read();

            if (command != 1)
            {
                logger.warning ("SOCKS command " + command + " != 1");
                return (false);
            }

            /*
            ** read the port number.
            */
            byte p[] = new byte[2];
            localIS.read (p);

            /*
            ** make the two numbers unsigned and do the arithmetic.
            */
            remotePort = (p[0] & 0x000000ff) * 256 + (p[1] & 0x000000ff);

            logger.finer ("remotePort " + remotePort);

            /*
            ** read the address and convert to an InetAddress.
            */
            byte a[] = new byte[4];
            localIS.read (a);
            remoteAddress = InetAddress.getByAddress (a);

            logger.finer ("remoteAddress " + remoteAddress);

            /*
            ** skip past user info
            */
            int user;
            while ((user = localIS.read()) != 0)
                ;
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
            return (false);
        }

        return (true);
    }

    public void run()
    {
        if (! readSOCKSHeader())
        {
            return;
        }

        if (! openRemote())
        {
            return;
        }

        Thread t1 = new SOCKSThread (localIS, remoteOS, requestOS);
        Thread t2 = new SOCKSThread (remoteIS, localOS, responseOS);

        t1.start();
        t2.start();

        /*
        ** wait for both threads to finish so that no one closes any of the
        ** related sockets or streams prematurely
        */
        try
        {
            t1.join();
            t2.join();
        }
        catch (InterruptedException IE)
        {
            logger.warning (IE);
            return;
        }
    }


    public static void main (String[] args) throws IOException
    {
        try
        {
            ServerSocket serverSocket = new ServerSocket
                (Integer.decode (args[0]));

            for (;;)
            {
                Socket socket = serverSocket.accept();

                new Connection (socket).start();
            }
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
        }
    }
}
