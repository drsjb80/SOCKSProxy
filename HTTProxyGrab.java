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
    private int port = -1;  // the port on that host
    private String path;
    private URL url;
    private final int BUFFERSIZE = 10000;
    private byte buffer[] = new byte[BUFFERSIZE];

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

    private void getGETorPOST (String s)
    {
        logger.entering (s);

        if (s.startsWith ("GET") || s.startsWith ("POST"))
        {
            String a[] = s.split (" ");

            try
            {
                url = new URL (a[1]);
            }
            catch (MalformedURLException MUE)
            {
                logger.warning (MUE);
                return;
            }

            host = url.getHost();
            port = url.getPort();
            path = url.getPath();

            if (port == -1)
                port = 80;
        }
        else
        {
            logger.severe ("Error: no GET or POST found");
        }

        logger.exiting (host);
        logger.exiting (port);
        logger.exiting (path);
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

        while (! s.equals (""))
        {
            logger.finest (s);

            if (! s.startsWith ("Proxy-") ||
                ! s.startsWith ("Connection: keep-alive"))
            {
                ret.add (s);
            }

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
            if (array[i].startsWith (match))
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
    private int readAndWrite (BufferedInputStream BIS,
        BufferedOutputStream BOS, FileOutputStream FOS, int len)
        throws IOException
    {
        logger.entering (len);

        int read = BIS.read (buffer, 0, len);

        if (read == -1)
        {
            logger.exiting (read);
            return (read);
        }

        BOS.write (buffer, 0, read);
        BOS.flush();

        if (FOS != null)
        {
            FOS.write (buffer, 0, read);
            FOS.flush();
        }

        logger.exiting (read);
        return (read);
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
        logger.severe ("CHUNKED");

        for (;;)
        {
            String hex = readLine (BIS);
            int count = Integer.parseInt (hex, 16);

            logger.finer (hex);
            logger.finer (count);
            
            if (count == 0)
                break;

            int read = readAndWrite (BIS, BOS, FOS, count);
            
            if (read != count)
            {
                logger.severe (read + " != " + count);
                break;
            }

            if (read == -1)
            {
                logger.severe ("read == -1");
                break;
            }
        }
    }

    private void copyRaw (BufferedInputStream BIS, BufferedOutputStream BOS,
        FileOutputStream FOS, String[] headerFields)
        throws IOException
    {
        logger.entering();

        int contentLength = getContentLength (headerFields);
        int remaining = contentLength;
        int len = BUFFERSIZE;

        for (;;)
        {
            logger.finest (remaining);

            // if there was a contentlength and it's smaller than the
            // buffer size, just set the length to that.
            if (contentLength != -1 && remaining < BUFFERSIZE)
                len = remaining;

            logger.finest (len);

            int read = readAndWrite (BIS, BOS, FOS, len);

            if (contentLength != -1)
            {
                if (read == -1)
                {
                    logger.severe ("read == -1");
                    break;
                }

                remaining -= read;
                logger.finest (remaining);

                if (remaining <= 0)
                    break;
            }
            else
            {
                if (read == -1)
                    break;
            }
        }
    }

    /*
    ** copy the contents of BIS to BOS and a file stream created here.
    */
    private void copy (BufferedInputStream BIS, BufferedOutputStream BOS,
        String headerFields[], boolean chunked) throws IOException
    {
        logger.entering();

        String path = url.getPath();
        String sep = path.startsWith ("/") ? "" : "/";
        String def = path.endsWith ("/") ? "index.html" : "";

        // String total = host + "/" + port + sep + path + def;

        String total = host + sep + path + def;

        logger.info ("Saving " + total);

        File f = new File (total);
        File g = new File (f.getParent());
        g.mkdirs();

        FileOutputStream FOS = null;
        try
        {
            FOS = new FileOutputStream (total, false);
        }
        catch (FileNotFoundException FNFE)
        {
            FOS = null;
            logger.warning (FNFE);
        }

        if (chunked)
            copyChunked (BIS, BOS, FOS);
        else
            copyRaw (BIS, BOS, FOS, headerFields);

        if (FOS != null)
            FOS.close();
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
        String headerFields[] = null;
        try
        {
            BufferedInputStream localBIS = new BufferedInputStream
                (socket.getInputStream());
            BufferedOutputStream localBOS = new BufferedOutputStream
                (socket.getOutputStream());

            headerFields = getHeaderFields (localBIS);

            if (headerFields == null)
            {
                logger.warning ("null headerfields");
                return;
            }

            getGETorPOST (headerFields[0]);
            getHostAndPort (headerFields);

            boolean chunked =
                getMatch (headerFields, "Transfer-Encoding: chunked") != null;

            if (host != null)
            {
                Socket remoteSocket = new Socket (host, port);
                BufferedInputStream remoteBIS = new BufferedInputStream
                    (remoteSocket.getInputStream());
                BufferedOutputStream remoteBOS = new BufferedOutputStream
                    (remoteSocket.getOutputStream());

                // send the local headers to the remote server
                for (int i = 0; i < headerFields.length; i++)
                    writeLine (headerFields[i], remoteBOS);

                writeLine ("", remoteBOS);

                // write the remote server's headers to the local client
                headerFields = getHeaderFields (remoteBIS);

                for (int i = 0; i < headerFields.length; i++)
                    writeLine (headerFields[i], localBOS);

                writeLine ("", localBOS);

                copy (remoteBIS, localBOS, headerFields, chunked);

                localBIS.close();
                localBOS.close();
                socket.close();
                remoteBIS.close();
                remoteBOS.close();
                remoteSocket.close();
            }
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            logger.warning ("url = " + url);
        }
    }
}

public class HTTProxyGrab
{
    private static JavaLN logger = new JavaLN();

    public static void main (String[] args) throws IOException
    {
        ServerSocket serverSocket = new ServerSocket (Integer.decode (args[0]));

        ConsoleHandler CH = new ConsoleHandler();
        CH.setFormatter (new LineNumberFormatter());
        // CH.setLevel (Level.FINER);

        logger.addHandler (CH);
        logger.setUseParentHandlers (false);
        // logger.setLevel (Level.FINEST);
        logger.finer ("Starting " + Thread.currentThread());

        for (;;)
        {
            Socket socket = serverSocket.accept();

            new Communicate (socket, logger).start();
        }
    }
}
