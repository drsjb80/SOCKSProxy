import java.net.*;
import java.io.*;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.ArrayList;

import edu.mscd.cs.javaln.*;

class Communicate extends Thread
{
    private JavaLN logger;
    private Socket socket;  // the client socket
    private String host;    // the host to connect to
    private String path;    // the host to connect to
    private int reply;    // the host to connect to
    private int port = -1;  // the port on that host
    private boolean onedotone = false;
    private boolean keepAlive = false;
    private boolean head = false;

    public Communicate (Socket socket, JavaLN logger)
    {
        this.socket = socket;
        this.logger = logger;
    }

    private int readChar (BufferedInputStream BIS)
    {
        try
        {
            return (BIS.read());
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            return (-1);
        } 
    }

    /*
    ** read a single (header) line that terminates with a \r\n
    */
    private String readLine (BufferedInputStream BIS)
    {
        logger.entering();

        String ret = "";
        
        for (;;)
        {
            int c = readChar (BIS);
            logger.finest ((char) c);

            if (c == -1)
            {
                logger.exiting (null);
                return (null);    // we expect at least a CRLF
            }

            if (c == '\r')
            {
                c = readChar (BIS);

                if (c == '\n')
                {
                    logger.exiting (ret);
                    return (ret);
                }
                else
                {
                    System.err.println ("ERROR CR without LF");
                    return (null);
                }
            }
            else
            {
                ret += (char) c;
            }
        }
    }

    /*
    ** write a (header) line with a \r\n
    */
    private void writeLine (String s, BufferedOutputStream BOS)
    {
        logger.entering (s);

        byte b[] = s.getBytes();

        try
        {
            BOS.write (b, 0, b.length);
            BOS.write ('\r');
            BOS.write ('\n');
            BOS.flush();
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
        } 
    }


    private String firstLine (String s)
    {
        logger.entering (s);

        head = s.toUpperCase().startsWith ("HEAD");

        if (s.toUpperCase().startsWith ("GET") ||
            s.toUpperCase().startsWith ("POST"))
        {
            String a[] = s.split (" ");

            URL url = null;

            try
            {
                url = new URL (a[1]);
            }
            catch (MalformedURLException MUE)
            {
                logger.warning (MUE);
                return (s);
            }

            host = url.getHost();
            port = url.getPort();

            path = host + url.getPath() +
                (url.getQuery() == null ? "" : "?" + url.getQuery()) +
                (url.getRef() == null ? "" : url.getRef());

            if (port == -1)
                port = 80;

            logger.finer (host);
            logger.finer (port);

            onedotone = a[2].endsWith ("1.1");
            logger.finer (onedotone);

            s = s.replaceFirst ("http://[^/]*", "");
        }
        else if (s.toUpperCase().startsWith ("HTTP"))
        {
            logger.entering (s);
            
            String a[] = s.split (" ");

            reply = Integer.parseInt (a[1]);
        }
        else
        {
            logger.severe ("Error: no GET, POST, or HTTP found");
        }

        logger.exiting (s);
        return (s);
    }

    /*
    ** read through the header lines and save an array of them
    */
    private String[] getHeaderFields (BufferedInputStream BIS)
        throws IOException
    {
        logger.entering();

        ArrayList ret = new ArrayList();

        String s = readLine (BIS);

        // didn't find any headers
        if (s == null)
        {
            logger.exiting (null);
            return (null);
        }

        s = firstLine (s);

        while (! s.equals (""))
        {
            logger.finer (s);
            ret.add (s);
            s = readLine (BIS);
        }

        return ((String []) ret.toArray (new String[0]));
    }

    /*
    ** look through the array of headers looking for a specific one
    */
    private String getMatch (String array[], String match)
    {
        for (int i = 0; i < array.length; i++)
        {
            if (array[i].toUpperCase().startsWith (match.toUpperCase()))
                return (array[i]);
        }

        return (null);
    }

    /*
    ** does the header specify the length?
    */
    private int getContentLength (String headerFields[])
    {
        int contentLength = -1;
        String t = getMatch (headerFields, "Content-Length:");

        if (t != null)
        {
            String a[] = t.split (" ");
            contentLength = Integer.parseInt (a[1]);
        }

        logger.exiting (contentLength);
        return (contentLength);
    }

    /*
    ** read from a stream and write to both the other end, and a file.
    ** read only up a a specific length, if specified
    */
    private void readAndWrite (BufferedInputStream BIS,
        BufferedOutputStream BOS, FileOutputStream FOS, int len)
    {
        logger.entering (len);

        byte buffer[] = null;

        if (len == -1)
        {
            buffer = new byte[8192];
        }
        else 
        {
            buffer = new byte[len];
        }

        int read = -1;

        for (;;)
        {
            try
            {
                logger.finer ("len = " + len);
                read = BIS.read (buffer, 0, len);
                logger.finer ("read = " + read);
            }
            catch (IOException IOE)
            {
                logger.warning (IOE);
            }

            if (read == -1)
            {
                logger.exiting();
                return;
            }

            /*
            ** write whatever we got to the file and output stream
            */
            if (FOS != null)
            {
                try
                {
                    FOS.write (buffer, 0, read);
                    FOS.flush();
                }
                catch (IOException IOE)
                {
                    logger.warning (IOE);
                }
            }

            try
            {
                BOS.write (buffer, 0, read);
                BOS.flush();
            }
            catch (IOException IOE)
            {
                logger.warning (IOE);
            }

            /*
            ** if we didn't know how many to read, continue
            ** reading.
            */
            if (len == -1)
                continue;

            len -= read;

            if (len == 0)
                break;
        }
    }

    /*
    ** Each chunk starts with the number of octets of the data it embeds
    ** expressed in hexadecimal followed by optional parameters (chunk
    ** extension) and a terminating CRLF sequence, followed by the chunk data.
    ** The chunk is terminated by CRLF.
    **
    ** The last-chunk is a regular chunk, with the exception that its length
    ** is zero.
    **
    ** The last-chunk is followed by the trailer, which consist of a (possibly
    ** empty) sequence of entity header fields.
    */
    private void copyChunked (BufferedInputStream BIS, BufferedOutputStream BOS,
        FileOutputStream FOS)
        throws IOException
    {
        logger.entering();

        for (;;)
        {
            String hex = readLine (BIS);

            if (hex == "")
                break;

            int count = Integer.parseInt (hex, 16);

            logger.finer (hex);
            logger.finer (count);
            
            if (count == 0)
                break;

            readAndWrite (BIS, BOS, FOS, count);
        }
        logger.exiting();
    }

    private void copyRaw (BufferedInputStream BIS, BufferedOutputStream BOS,
        FileOutputStream FOS, int contentLength)
        throws IOException
    {
        logger.entering();

        readAndWrite (BIS, BOS, FOS, contentLength);

        logger.exiting();
    }

    /*
    ** copy the contents of BIS to BOS and a file stream created here.
    */
    private void copy (BufferedInputStream BIS, BufferedOutputStream BOS,
        int contentLength, boolean chunked) throws IOException
    {
        logger.entering();

        logger.info (Thread.currentThread() + " saving " + path);

        File f = new File (path);
        File g = new File (f.getParent());
        g.mkdirs();

        FileOutputStream FOS = null;
        try
        {
            FOS = new FileOutputStream (path, false);
        }
        catch (FileNotFoundException FNFE)
        {
            FOS = null;
            logger.warning (FNFE);
        }

        if (chunked)
            copyChunked (BIS, BOS, FOS);
        else
            copyRaw (BIS, BOS, FOS, contentLength);

        if (FOS != null)
            FOS.close();

        logger.exiting();
    }

    /*
    ** get the host and port number from the headers; the host portion may
    ** be different and overwrite that one previously found in the GET or
    ** POST
    */
    private void getHostAndPort (String headerFields[])
    {
        String t = getMatch (headerFields, "Host:");
        if (t != null)
        {
            String a[] = t.split (" ");
            String b[] = a[1].split (":");

            host = b[0];

            if (b.length > 1)
                port = Integer.parseInt (b[1]);
        }
    }

    public void run()
    {
        logger.info ("Starting " + Thread.currentThread());

        String headerFields[] = null;

        BufferedInputStream localBIS = null;
        BufferedOutputStream localBOS = null;

        Socket remoteSocket = null;
        BufferedInputStream remoteBIS = null;
        BufferedOutputStream remoteBOS = null;

        try
        {
            localBIS = new BufferedInputStream (socket.getInputStream());
            localBOS = new BufferedOutputStream (socket.getOutputStream());

            for (;;)
            {
                headerFields = getHeaderFields (localBIS);

                if (headerFields == null)
                {
                    logger.finer ("done");
                    break;
                }

                getHostAndPort (headerFields);

                logger.info ("requesting " + path);

                boolean close = getMatch
                    (headerFields, "Connection: close") != null;
                logger.finer (close);

                boolean keepAlive = getMatch
                    (headerFields, "Connection: Keep-Alive") != null;
                logger.finer (keepAlive);

                /*
                ** open remote, if not already done by persistent connection
                */
                if (remoteSocket == null)
                {
                    logger.fine ("opening new socket");

                    remoteSocket = new Socket (host, port);
                    remoteBIS = new BufferedInputStream
                        (remoteSocket.getInputStream());
                    remoteBOS = new BufferedOutputStream
                        (remoteSocket.getOutputStream());
                }

                /*
                ** write the local header to the remote server
                */
                for (int i = 0; i < headerFields.length; i++)
                    writeLine (headerFields[i], remoteBOS);

                writeLine ("", remoteBOS);

                /*
                ** write the remote server's headers to the local client
                */
                headerFields = getHeaderFields (remoteBIS);

                if (headerFields == null)
                {
                    logger.finer ("done");
                    break;
                }

                for (int i = 0; i < headerFields.length; i++)
                    writeLine (headerFields[i], localBOS);

                writeLine ("", localBOS);

                boolean chunked = getMatch
                    (headerFields, "Transfer-Encoding: chunked") != null;
                logger.finer (chunked);

                int contentLength = getContentLength (headerFields);

                if (reply == 404)
                    logger.severe ("404 for " + path);

                logger.info ("reply " + reply);
                logger.info ("contentLength " + contentLength);

                if ((keepAlive || onedotone) && contentLength < 0)
                {
                    logger.severe ("contentLength not specified");
                    copy (remoteBIS, localBOS, contentLength, chunked);
                }
                else if (contentLength > 0 || chunked)
                {
                    copy (remoteBIS, localBOS, contentLength, chunked);
                }
                else if (head)
                {
                    // nothing to copy
                }
                else if (reply >= 100 && reply <= 199)
                {
                    // nothing to copy
                }
                else if (reply == 204 || reply == 304)
                {
                    // nothing to copy
                }
                else if (close)
                {
                    copy (remoteBIS, localBOS, contentLength, chunked);
                }

                if (close)
                {
                    logger.finer ("closing");
                    break;
                }

                if (onedotone || keepAlive)
                {
                    logger.finer ("persistent");
                    continue;
                }

                logger.severe ("continuing anyway");
            }
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            logger.warning ("path = " + path);
        }

        try
        {
            localBIS.close();
            localBOS.close();
            socket.close();
            remoteBIS.close();
            remoteBOS.close();
            remoteSocket.close();
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            logger.warning ("path = " + path);
        }

        logger.info ("Ending " + Thread.currentThread());
    }
}

public class HTTProxyGrab
{
    private static JavaLN logger = new JavaLN();

    public static void main (String[] args) throws IOException
    {
        ServerSocket serverSocket = new ServerSocket (Integer.decode (args[0]));

        /*
        ConsoleHandler CH0 = new ConsoleHandler();
        CH0.setFormatter (new NullFormatter());
        CH0.setLevel (Level.INFO);
        CH0.setFilter (new LevelFilter (Level.INFO));
        logger.addHandler (CH0);
        */

        ConsoleHandler CH1 = new ConsoleHandler();
        CH1.setFormatter (new LineNumberFormatter());
        CH1.setLevel (Level.FINER);
        // CH1.setLevel (Level.WARNING);
        // CH1.setFilter (new LevelFilter (Level.WARNING));
        logger.addHandler (CH1);

        logger.setUseParentHandlers (false);
        logger.setLevel (Level.FINEST);

        for (;;)
        {
            Socket socket = serverSocket.accept();

            new Communicate (socket, logger).start();
        }
    }
}
